package it.amhs.network;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.PushbackInputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.SocketException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicLong;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import it.amhs.service.protocol.p3.P3Asn1GatewayProtocol;
import it.amhs.service.protocol.p3.P3GatewaySessionService;
import it.amhs.service.protocol.rfc1006.CotpConnectionTpdu;

@Component
@ConditionalOnProperty(prefix = "amhs.p3.gateway", name = "enabled", havingValue = "true")
public class P3GatewayServer {

    private static final Logger logger = LoggerFactory.getLogger(P3GatewayServer.class);
    private static final byte TPKT_VERSION = 0x03;
    private static final byte TPKT_RESERVED = 0x00;
    private static final int MAX_TPKT_LENGTH = 65_535;
    private static final byte COTP_PDU_CR = (byte) 0xE0;
    private static final byte COTP_PDU_CC = (byte) 0xD0;
    private static final byte COTP_PDU_DT = (byte) 0xF0;
    private static final byte COTP_PDU_DR = (byte) 0x80;
    private static final byte COTP_PDU_DC = (byte) 0xC0;
    private static final byte[] COTP_DT_HEADER = new byte[] { 0x02, (byte) 0xF0 };

    private final String host;
    private final int port;
    private final boolean tlsEnabled;
    private final boolean needClientAuth;
    private final boolean textWelcomeEnabled;
    private final SSLContext tls;
    private final P3GatewaySessionService sessionService;
    private final P3Asn1GatewayProtocol asn1GatewayProtocol;
    private final ExecutorService clientExecutor;
    private final AtomicLong connectionSequence = new AtomicLong(0);

    public P3GatewayServer(
        @Value("${amhs.p3.gateway.host:0.0.0.0}") String host,
        @Value("${amhs.p3.gateway.port:1988}") int port,
        @Value("${amhs.p3.gateway.max-sessions:64}") int maxSessions,
        @Value("${amhs.p3.gateway.tls.enabled:false}") boolean tlsEnabled,
        @Value("${amhs.p3.gateway.tls.need-client-auth:false}") boolean needClientAuth,
        @Value("${amhs.p3.gateway.text.welcome-enabled:false}") boolean textWelcomeEnabled,
        SSLContext tls,
        P3GatewaySessionService sessionService,
        P3Asn1GatewayProtocol asn1GatewayProtocol
    ) {
        if (port < 1 || port > 65_535) {
            throw new IllegalArgumentException("amhs.p3.gateway.port out of range: " + port);
        }
        if (maxSessions < 1) {
            throw new IllegalArgumentException("amhs.p3.gateway.max-sessions must be >= 1");
        }
        this.host = host;
        this.port = port;
        this.tlsEnabled = tlsEnabled;
        this.needClientAuth = needClientAuth;
        this.textWelcomeEnabled = textWelcomeEnabled;
        this.tls = tls;
        this.sessionService = sessionService;
        this.asn1GatewayProtocol = asn1GatewayProtocol;
        this.clientExecutor = Executors.newFixedThreadPool(maxSessions, new NamedDaemonThreadFactory());
    }

    public void start() throws Exception {
        if (tlsEnabled) {
            SSLServerSocket server = (SSLServerSocket) tls.getServerSocketFactory().createServerSocket(port, 50, InetAddress.getByName(host));
            server.setEnabledProtocols(new String[] { "TLSv1.3", "TLSv1.2" });
            server.setNeedClientAuth(needClientAuth);
            logger.info("AMHS P3 gateway TLS server listening on {}:{}", host, port);
            acceptLoop(server);
            return;
        }

        ServerSocket server = new ServerSocket(port, 50, InetAddress.getByName(host));
        logger.info("AMHS P3 gateway clear transport server listening on {}:{}", host, port);
        acceptLoop(server);
    }

    private void acceptLoop(ServerSocket server) throws Exception {
        while (true) {
            Socket socket = server.accept();
            long connectionId = connectionSequence.incrementAndGet();
            logger.info("P3 gateway connection #{} from {}:{} to local-port={}", connectionId, socket.getInetAddress(), socket.getPort(), socket.getLocalPort());
            clientExecutor.execute(() -> handleClient(connectionId, socket));
        }
    }

    private void handleClient(long connectionId, Socket socket) {
        try (socket;
             PushbackInputStream input = new PushbackInputStream(socket.getInputStream(), 16);
             OutputStream output = socket.getOutputStream()) {
            P3GatewaySessionService.SessionState session = sessionService.newSession();
            byte[] preview = input.readNBytes(8);
            if (preview.length == 0) {
                return;
            }
            input.unread(preview);

            int first = preview[0] & 0xFF;
            ProtocolKind protocolKind = detectProtocol(preview);
            logger.info(
                "P3 gateway connection #{} protocol-detect kind={} first-octets={}",
                connectionId,
                protocolKind,
                toHex(preview)
            );

            if (protocolKind == ProtocolKind.TEXT_COMMAND) {
                logger.info("P3 gateway protocol=text-command remote={}", socket.getInetAddress());
                handleTextSession(connectionId, session, input, output);
                return;
            }

            if (protocolKind == ProtocolKind.BER_APDU) {
                logger.info("P3 gateway protocol=ber-apdu remote={}", socket.getInetAddress());
                handleAsn1Session(connectionId, session, input, output);
                return;
            }

            if (protocolKind == ProtocolKind.RFC1006_TPKT) {
                logger.info("P3 gateway protocol=rfc1006-tpkt remote={}", socket.getInetAddress());
                handleRfc1006Session(connectionId, session, input, output);
                return;
            }

            if (protocolKind == ProtocolKind.TLS_CLIENT_HELLO) {
                logger.info(
                    "P3 gateway connection #{} rejected protocol={} (this endpoint expects text command or BER APDU over raw transport)",
                    connectionId,
                    protocolKind
                );
                return;
            }

            logger.warn(
                "P3 gateway connection #{} unexpected protocol={} (this endpoint expects text command or BER APDU over raw transport)",
                connectionId,
                protocolKind
            );
        } catch (Exception ex) {
            if (isExpectedDisconnect(ex)) {
                logger.debug("P3 gateway connection #{} ended before a complete request was received: {}", connectionId, ex.getMessage());
                return;
            }
            logger.warn("P3 gateway connection #{} closed with error: {}", connectionId, ex.getMessage());
        }
    }

    private boolean isExpectedDisconnect(Exception ex) {
        return ex instanceof EOFException
            || ex instanceof SocketException;
    }

    private void handleTextSession(long connectionId, P3GatewaySessionService.SessionState session, PushbackInputStream input, OutputStream output)
        throws Exception {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8));
             PrintWriter writer = new PrintWriter(new BufferedWriter(new OutputStreamWriter(output, StandardCharsets.UTF_8)), true)) {
            if (textWelcomeEnabled) {
                writer.println("OK code=gateway-ready");
            }
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank()) {
                    continue;
                }
                String response = sessionService.handleCommand(session, line);
                writer.println(response);
                if (session.isClosed()) {
                    logger.info("P3 gateway connection #{} text session closed by command {}", connectionId, commandName(line));
                    return;
                }
            }
        }
    }

    private void handleAsn1Session(long connectionId, P3GatewaySessionService.SessionState session, PushbackInputStream input, OutputStream output)
        throws Exception {
        int pduIndex = 0;
        while (true) {
            byte[] pdu = asn1GatewayProtocol.readPdu(input);
            if (pdu == null) {
                logger.info("P3 gateway connection #{} BER session closed by peer after {} APDU(s)", connectionId, pduIndex);
                return;
            }
            pduIndex++;
            logger.info("P3 gateway connection #{} BER APDU #{} len={} first-byte=0x{}", connectionId, pduIndex, pdu.length, toHexByte(pdu[0]));
            byte[] response = asn1GatewayProtocol.handle(session, pdu);
            output.write(response);
            output.flush();
            logger.debug("P3 gateway connection #{} BER APDU #{} response-len={}", connectionId, pduIndex, response.length);
            if (session.isClosed()) {
                logger.info("P3 gateway connection #{} BER session closed by release after {} APDU(s)", connectionId, pduIndex);
                return;
            }
        }
    }

    private void handleRfc1006Session(long connectionId, P3GatewaySessionService.SessionState session, PushbackInputStream input, OutputStream output)
        throws Exception {
        ByteArrayOutputStream segmentedPayload = new ByteArrayOutputStream();
        int pduIndex = 0;
        while (true) {
            CotpFrame frame = readRfc1006Frame(input);
            if (frame == null) {
                logger.info("P3 gateway connection #{} RFC1006 session closed by peer after {} APDU(s)", connectionId, pduIndex);
                return;
            }

            if (frame.type == COTP_PDU_CR) {
                CotpConnectionTpdu request = CotpConnectionTpdu.parse(frame.payload);
                CotpConnectionTpdu confirm = new CotpConnectionTpdu(
                    CotpConnectionTpdu.PDU_CC,
                    request.sourceReference(),
                    request.destinationReference(),
                    request.tpduClass(),
                    request.tpduSize(),
                    request.unknownParameters()
                );
                sendTpktFrame(output, confirm.serialize());
                output.flush();
                logger.info("P3 gateway connection #{} RFC1006 COTP connection confirmed", connectionId);
                continue;
            }

            if (frame.type == COTP_PDU_DR) {
                sendTpktFrame(output, new byte[] {0x06, COTP_PDU_DC, 0x00, 0x00, 0x00, 0x00, 0x00});
                output.flush();
                logger.info("P3 gateway connection #{} RFC1006 disconnect requested by peer", connectionId);
                return;
            }

            if (frame.type != COTP_PDU_DT) {
                logger.warn(
                    "P3 gateway connection #{} ignoring unsupported RFC1006 TPDU type=0x{}",
                    connectionId,
                    toHexByte(frame.type)
                );
                continue;
            }

            segmentedPayload.writeBytes(frame.userData);
            if (!frame.endOfTsdu) {
                continue;
            }

            byte[] pdu = segmentedPayload.toByteArray();
            segmentedPayload.reset();
            if (pdu.length == 0) {
                continue;
            }

            pduIndex++;
            String payloadKind = classifyRfc1006Payload(pdu);
            logger.info(
                "P3 gateway connection #{} RFC1006 payload #{} len={} first-byte=0x{} kind={} first-bytes={}",
                connectionId,
                pduIndex,
                pdu.length,
                toHexByte(pdu[0]),
                payloadKind,
                toHexPreview(pdu, 64)
            );

            if (!isRfc1006PayloadSupportedByAsn1(payloadKind)) {
                logger.warn(
                    "P3 gateway connection #{} RFC1006 payload #{} kind={} is not supported by the ASN.1 gateway handler (expected BER APDU); closing connection",
                    connectionId,
                    pduIndex,
                    payloadKind
                );
                sendRfc1006Disconnect(output);
                return;
            }

            byte[] response = asn1GatewayProtocol.handle(session, pdu);
            sendRfc1006Dt(output, response);
            logger.debug("P3 gateway connection #{} RFC1006 payload #{} response-len={}", connectionId, pduIndex, response.length);
            if (session.isClosed()) {
                logger.info("P3 gateway connection #{} RFC1006 session closed by release after {} payload(s)", connectionId, pduIndex);
                return;
            }
        }
    }

    private CotpFrame readRfc1006Frame(PushbackInputStream input) throws Exception {
        int version = input.read();
        if (version < 0) {
            return null;
        }
        int reserved = input.read();
        int lenHi = input.read();
        int lenLo = input.read();
        if (reserved < 0 || lenHi < 0 || lenLo < 0) {
            throw new EOFException("Connection closed while reading TPKT header");
        }
        if (version != TPKT_VERSION || reserved != TPKT_RESERVED) {
            throw new IllegalArgumentException("Invalid TPKT header");
        }

        int tpktLength = ((lenHi & 0xFF) << 8) | (lenLo & 0xFF);
        if (tpktLength < 7 || tpktLength > MAX_TPKT_LENGTH) {
            throw new IllegalArgumentException("Invalid TPKT frame length: " + tpktLength);
        }

        byte[] cotpTpdu = input.readNBytes(tpktLength - 4);
        if (cotpTpdu.length != tpktLength - 4) {
            throw new EOFException("Truncated TPKT payload");
        }
        int lengthIndicator = cotpTpdu[0] & 0xFF;
        if (lengthIndicator + 1 > cotpTpdu.length || lengthIndicator < 1) {
            throw new IllegalArgumentException("Invalid COTP length indicator: " + lengthIndicator);
        }

        byte type = (byte) (cotpTpdu[1] & 0xF0);
        if (type == COTP_PDU_CR || type == COTP_PDU_CC || type == COTP_PDU_DR || type == COTP_PDU_DC) {
            return new CotpFrame(type, true, new byte[0], cotpTpdu);
        }
        if (type != COTP_PDU_DT) {
            return new CotpFrame(type, true, new byte[0], cotpTpdu);
        }
        if (lengthIndicator < 2 || cotpTpdu[1] != COTP_DT_HEADER[1]) {
            throw new IllegalArgumentException("Unsupported COTP DT header");
        }
        boolean eot = (cotpTpdu[2] & 0x80) != 0;
        int dataOffset = lengthIndicator + 1;
        byte[] userData = new byte[cotpTpdu.length - dataOffset];
        if (userData.length > 0) {
            System.arraycopy(cotpTpdu, dataOffset, userData, 0, userData.length);
        }
        return new CotpFrame(type, eot, userData, cotpTpdu);
    }

    private void sendRfc1006Dt(OutputStream output, byte[] payload) throws Exception {
        byte[] response = payload == null ? new byte[0] : payload;
        byte[] tpdu = new byte[3 + response.length];
        tpdu[0] = 0x02;
        tpdu[1] = COTP_PDU_DT;
        tpdu[2] = (byte) 0x80;
        if (response.length > 0) {
            System.arraycopy(response, 0, tpdu, 3, response.length);
        }
        sendTpktFrame(output, tpdu);
        output.flush();
    }

    private void sendTpktFrame(OutputStream output, byte[] tpdu) throws Exception {
        int length = 4 + tpdu.length;
        if (length > MAX_TPKT_LENGTH) {
            throw new IllegalArgumentException("TPKT frame exceeds maximum allowed length: " + length);
        }
        output.write(TPKT_VERSION);
        output.write(TPKT_RESERVED);
        output.write((length >> 8) & 0xFF);
        output.write(length & 0xFF);
        output.write(tpdu);
    }

    private void sendRfc1006Disconnect(OutputStream output) throws Exception {
        sendTpktFrame(output, new byte[] {0x06, COTP_PDU_DR, 0x00, 0x00, 0x00, 0x00, 0x00});
        output.flush();
    }

    private ProtocolKind detectProtocol(byte[] preview) {
        int firstOctet = preview[0] & 0xFF;
        if (isAsciiCommand(firstOctet)) {
            return ProtocolKind.TEXT_COMMAND;
        }
        if (looksLikeRfc1006Tpkt(preview)) {
            return ProtocolKind.RFC1006_TPKT;
        }
        if (looksLikeTlsClientHello(preview)) {
            return ProtocolKind.TLS_CLIENT_HELLO;
        }
        if (looksLikeBerApdu(preview)) {
            return ProtocolKind.BER_APDU;
        }
        return ProtocolKind.UNKNOWN_BINARY;
    }

    private boolean isAsciiCommand(int firstOctet) {
        return firstOctet >= 0x20 && firstOctet <= 0x7E;
    }

    private boolean looksLikeBerApdu(byte[] preview) {
        if (preview.length < 2) {
            return false;
        }

        int firstOctet = preview[0] & 0xFF;
        if (firstOctet == 0x00 || firstOctet == 0xFF) {
            return false;
        }

        int lengthOctet = preview[1] & 0xFF;
        if ((lengthOctet & 0x80) == 0) {
            return true;
        }

        int lengthByteCount = lengthOctet & 0x7F;
        return lengthByteCount > 0 && lengthByteCount <= 4 && preview.length >= (2 + lengthByteCount);
    }

    private boolean looksLikeRfc1006Tpkt(byte[] preview) {
        return preview.length >= 4
            && (preview[0] & 0xFF) == 0x03
            && (preview[1] & 0xFF) == 0x00
            && (((preview[2] & 0xFF) << 8) | (preview[3] & 0xFF)) >= 4;
    }

    private boolean looksLikeTlsClientHello(byte[] preview) {
        return preview.length >= 3
            && (preview[0] & 0xFF) == 0x16
            && (preview[1] & 0xFF) == 0x03
            && ((preview[2] & 0xFF) >= 0x01 && (preview[2] & 0xFF) <= 0x04);
    }

    private String commandName(String line) {
        String trimmed = line == null ? "" : line.trim();
        if (trimmed.isEmpty()) {
            return "<blank>";
        }
        int separator = trimmed.indexOf(' ');
        return separator < 0 ? trimmed : trimmed.substring(0, separator);
    }

    private String toHexByte(byte value) {
        return String.format("%02X", value & 0xFF);
    }

    private String toHex(byte[] bytes) {
        StringBuilder value = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) {
                value.append(' ');
            }
            value.append(String.format("%02X", bytes[i] & 0xFF));
        }
        return value.toString();
    }

    private String toHexPreview(byte[] bytes, int maxBytes) {
        if (bytes.length <= maxBytes) {
            return toHex(bytes);
        }
        byte[] preview = new byte[maxBytes];
        System.arraycopy(bytes, 0, preview, 0, maxBytes);
        return toHex(preview) + " ...";
    }

    private String classifyRfc1006Payload(byte[] payload) {
        if (payload.length == 0) {
            return "EMPTY";
        }
        int firstOctet = payload[0] & 0xFF;
        if (firstOctet == 0x0D || firstOctet == 0x01 || firstOctet == 0x0E) {
            return "OSI_SESSION_SPDU";
        }
        if (firstOctet == 0x31 || firstOctet == 0x61 || firstOctet == 0x62) {
            return "OSI_PRESENTATION_PPDU";
        }
        if (firstOctet == 0x60 || firstOctet == 0x61 || firstOctet == 0x64) {
            return "ACSE_APDU";
        }
        if (looksLikeBerApdu(payload)) {
            return "BER_APDU";
        }
        return "UNKNOWN_BINARY";
    }

    private boolean isRfc1006PayloadSupportedByAsn1(String payloadKind) {
        return "BER_APDU".equals(payloadKind);
    }

    private enum ProtocolKind {
        TEXT_COMMAND,
        BER_APDU,
        RFC1006_TPKT,
        TLS_CLIENT_HELLO,
        UNKNOWN_BINARY
    }

    private record CotpFrame(byte type, boolean endOfTsdu, byte[] userData, byte[] payload) {
    }

    private static final class NamedDaemonThreadFactory implements ThreadFactory {
        private int counter = 0;

        @Override
        public synchronized Thread newThread(Runnable runnable) {
            Thread thread = new Thread(runnable, "amhs-p3-gateway-client-" + (++counter));
            thread.setDaemon(true);
            return thread;
        }
    }
}
