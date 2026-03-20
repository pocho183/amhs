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
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;
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

import it.amhs.asn1.BerCodec;
import it.amhs.asn1.BerTlv;
import it.amhs.service.protocol.acse.AcseAssociationProtocol;
import it.amhs.service.protocol.acse.AcseModels;
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

    private static final int TAG_CLASS_UNIVERSAL = 0;
    private static final int TAG_CLASS_APPLICATION = 1;
    private static final int TAG_CLASS_CONTEXT = 2;

    private static final int GATEWAY_APDU_MIN_TAG = 0;
    private static final int GATEWAY_APDU_MAX_TAG = 12;

    private final String host;
    private final int port;
    private final boolean tlsEnabled;
    private final boolean needClientAuth;
    private final boolean textWelcomeEnabled;
    private final ListenerProfile listenerProfile;
    private final SSLContext tls;
    private final P3GatewaySessionService sessionService;
    private final P3Asn1GatewayProtocol asn1GatewayProtocol;
    private final AcseAssociationProtocol acseAssociationProtocol;
    private final ExecutorService clientExecutor;
    private final AtomicLong connectionSequence = new AtomicLong(0);

    public P3GatewayServer(
        @Value("${amhs.p3.gateway.host:0.0.0.0}") String host,
        @Value("${amhs.p3.gateway.port:102}") int port,
        @Value("${amhs.p3.gateway.max-sessions:64}") int maxSessions,
        @Value("${amhs.p3.gateway.tls.enabled:false}") boolean tlsEnabled,
        @Value("${amhs.p3.gateway.tls.need-client-auth:false}") boolean needClientAuth,
        @Value("${amhs.p3.gateway.text.welcome-enabled:false}") boolean textWelcomeEnabled,
        @Value("${amhs.p3.gateway.listener-profile:STANDARD_P3}") String listenerProfile,
        SSLContext tls,
        P3GatewaySessionService sessionService,
        P3Asn1GatewayProtocol asn1GatewayProtocol,
        AcseAssociationProtocol acseAssociationProtocol
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
        this.listenerProfile = ListenerProfile.from(listenerProfile);
        this.tls = tls;
        this.sessionService = sessionService;
        this.asn1GatewayProtocol = asn1GatewayProtocol;
        this.acseAssociationProtocol = acseAssociationProtocol;
        this.clientExecutor = Executors.newFixedThreadPool(maxSessions, new NamedDaemonThreadFactory());

        if (this.listenerProfile == ListenerProfile.STANDARD_P3) {
            logger.info("amhs.p3.gateway.listener-profile=STANDARD_P3 enforces RFC1006/TPKT ingress with external X.411 P3 envelope semantics enabled");
        }
    }

    public void start() throws Exception {
        if (tlsEnabled) {
            SSLServerSocket server = (SSLServerSocket) tls.getServerSocketFactory()
                .createServerSocket(port, 50, InetAddress.getByName(host));
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
            logger.info(
                "P3 gateway connection #{} from {}:{} to local-port={}",
                connectionId,
                socket.getInetAddress(),
                socket.getPort(),
                socket.getLocalPort()
            );
            clientExecutor.execute(() -> handleClient(connectionId, socket));
        }
    }

    private void handleClient(long connectionId, Socket socket) {
        try (
            socket;
            PushbackInputStream input = new PushbackInputStream(socket.getInputStream(), 16);
            OutputStream output = socket.getOutputStream()
        ) {
            P3GatewaySessionService.SessionState session = sessionService.newSession();

            byte[] preview = input.readNBytes(8);
            if (preview.length == 0) {
                return;
            }
            input.unread(preview);

            ProtocolKind protocolKind = detectProtocol(preview);
            logger.info(
                "P3 gateway connection #{} protocol-detect kind={} first-octets={}",
                connectionId,
                protocolKind,
                toHex(preview)
            );

            if (!isProtocolAllowed(protocolKind)) {
                logger.warn(
                    "P3 gateway connection #{} rejected protocol={} for listener-profile={} (supported={})",
                    connectionId,
                    protocolKind,
                    listenerProfile,
                    listenerProfile.supportedProtocolsSummary()
                );
                return;
            }

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

            logger.warn("P3 gateway connection #{} unexpected protocol={}", connectionId, protocolKind);
        } catch (Exception ex) {
            if (isExpectedDisconnect(ex)) {
                logger.debug(
                    "P3 gateway connection #{} ended before a complete request was received: {}",
                    connectionId,
                    ex.getMessage()
                );
                return;
            }
            logger.warn("P3 gateway connection #{} closed with error: {}", connectionId, ex.getMessage(), ex);
        }
    }

    private boolean isExpectedDisconnect(Exception ex) {
        return ex instanceof EOFException || ex instanceof SocketException;
    }

    private void handleTextSession(
        long connectionId,
        P3GatewaySessionService.SessionState session,
        PushbackInputStream input,
        OutputStream output
    ) throws Exception {
        try (
            BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8));
            PrintWriter writer = new PrintWriter(new BufferedWriter(new OutputStreamWriter(output, StandardCharsets.UTF_8)), true)
        ) {
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

    private void handleAsn1Session(
        long connectionId,
        P3GatewaySessionService.SessionState session,
        PushbackInputStream input,
        OutputStream output
    ) throws Exception {
        int pduIndex = 0;
        while (true) {
            byte[] pdu = asn1GatewayProtocol.readPdu(input);
            if (pdu == null) {
                logger.info("P3 gateway connection #{} BER session closed by peer after {} APDU(s)", connectionId, pduIndex);
                return;
            }

            pduIndex++;
            String payloadKind = classifyRfc1006Payload(pdu);
            logger.info(
                "P3 gateway connection #{} BER APDU #{} len={} first-byte=0x{} kind={} first-bytes={}",
                connectionId,
                pduIndex,
                pdu.length,
                toHexByte(pdu[0]),
                payloadKind,
                toHexPreview(pdu, 64)
            );

            byte[] applicationPdu = extractApplicationPduFromRfc1006Payload(pdu, payloadKind);
            if (applicationPdu == null) {
                logger.warn(
                    "P3 gateway connection #{} BER APDU #{} kind={} is not supported by the ASN.1 gateway handler",
                    connectionId,
                    pduIndex,
                    payloadKind
                );
                return;
            }

            logger.info(
                "P3 gateway delivering application PDU to ASN.1 handler len={} first-bytes={}",
                applicationPdu.length,
                toHexPreview(applicationPdu, 64)
            );
            
            try {
                BerTlv finalTlv = BerCodec.decodeSingle(applicationPdu);
                if (!isGatewayApdu(finalTlv)) {
                    logger.warn(
                        "P3 gateway refusing to deliver non-gateway APDU to ASN.1 handler tagClass={} constructed={} tagNumber={} len={} first-bytes={}",
                        finalTlv.tagClass(),
                        finalTlv.constructed(),
                        finalTlv.tagNumber(),
                        finalTlv.length(),
                        toHexPreview(applicationPdu, 128)
                    );
                    sendRfc1006Disconnect(output);
                    return;
                }
            } catch (RuntimeException ex) {
                logger.warn("P3 gateway refusing undecodable application PDU: {}", ex.getMessage());
                sendRfc1006Disconnect(output);
                return;
            }
            
            if (isIgnorablePostBindBerControl(applicationPdu)) {
                logger.info(
                    "P3 gateway ignoring benign post-bind BER control payload len={} first-bytes={}",
                    applicationPdu.length,
                    toHexPreview(applicationPdu, 16)
                );
                return;
            }

            try {
                BerTlv finalTlv = BerCodec.decodeSingle(applicationPdu);
                if (!isGatewayApdu(finalTlv)) {
                    logger.warn(
                        "P3 gateway refusing to deliver non-gateway APDU tagClass={} constructed={} tagNumber={} len={} first-bytes={}",
                        finalTlv.tagClass(),
                        finalTlv.constructed(),
                        finalTlv.tagNumber(),
                        finalTlv.length(),
                        toHexPreview(applicationPdu, 128)
                    );
                    sendRfc1006Disconnect(output);
                    return;
                }
            } catch (RuntimeException ex) {
                logger.warn("P3 gateway refusing undecodable application PDU: {}", ex.getMessage());
                sendRfc1006Disconnect(output);
                return;
            }
            
            byte[] response = asn1GatewayProtocol.handle(session, applicationPdu);
            byte[] wrappedResponse = rewrapApplicationPduForRfc1006Response(response, payloadKind, pdu);
            output.write(wrappedResponse);
            output.flush();

            if (session.isClosed()) {
                logger.info("P3 gateway connection #{} BER session closed by release after {} APDU(s)", connectionId, pduIndex);
                return;
            }
        }
    }
    
    private boolean isIgnorablePostBindBerControl(byte[] payload) {
        return payload != null
            && payload.length == 5
            && (payload[0] & 0xFF) == 0x19
            && (payload[1] & 0xFF) == 0x03
            && (payload[2] & 0xFF) == 0x11
            && (payload[3] & 0xFF) == 0x01
            && (payload[4] & 0xFF) == 0x05;
    }

    private void handleRfc1006Session(
        long connectionId,
        P3GatewaySessionService.SessionState session,
        PushbackInputStream input,
        OutputStream output
    ) throws Exception {
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
                sendTpktFrame(output, new byte[] { 0x06, COTP_PDU_DC, 0x00, 0x00, 0x00, 0x00, 0x00 });
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

            byte[] applicationPdu = extractApplicationPduFromRfc1006Payload(pdu, payloadKind);
            if (applicationPdu == null) {
                if (isIgnorablePostBindBerControl(pdu)) {
                    logger.info(
                        "P3 gateway connection #{} ignoring benign post-bind BER control payload #{} len={} first-bytes={}",
                        connectionId,
                        pduIndex,
                        pdu.length,
                        toHexPreview(pdu, 16)
                    );
                    continue;
                }

                logger.warn(
                    "P3 gateway connection #{} RFC1006 payload #{} kind={} is not supported by the ASN.1 gateway handler",
                    connectionId,
                    pduIndex,
                    payloadKind
                );
                sendRfc1006Disconnect(output);
                return;
            }

            logger.info(
                "P3 gateway delivering application PDU to ASN.1 handler len={} first-bytes={}",
                applicationPdu.length,
                toHexPreview(applicationPdu, 64)
            );

            if (isIgnorablePostBindBerControl(applicationPdu)) {
                logger.info(
                    "P3 gateway connection #{} ignoring benign post-bind BER control payload {}",
                    connectionId,
                    toHexPreview(applicationPdu, 16)
                );
                continue;
            }

            try {
                BerTlv finalTlv = BerCodec.decodeSingle(applicationPdu);
                if (!isGatewayApdu(finalTlv)) {
                    logger.warn(
                        "P3 gateway refusing to deliver non-gateway APDU tagClass={} constructed={} tagNumber={} len={} first-bytes={}",
                        finalTlv.tagClass(),
                        finalTlv.constructed(),
                        finalTlv.tagNumber(),
                        finalTlv.length(),
                        toHexPreview(applicationPdu, 128)
                    );
                    sendRfc1006Disconnect(output);
                    return;
                }
            } catch (RuntimeException ex) {
                logger.warn("P3 gateway refusing undecodable application PDU: {}", ex.getMessage());
                sendRfc1006Disconnect(output);
                return;
            }

            byte[] response = asn1GatewayProtocol.handle(session, applicationPdu);
            byte[] wrappedResponse = rewrapApplicationPduForRfc1006Response(response, payloadKind, pdu);

            logger.info("P3 outbound application response len={} first-bytes={}", response.length, toHexPreview(response, 128));
            logger.info("P3 outbound wrapped response len={} first-bytes={}", wrappedResponse.length, toHexPreview(wrappedResponse, 192));

            sendRfc1006Dt(output, wrappedResponse);

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
        logger.info("P3 outbound RFC1006 DT payload len={} first-bytes={}", response.length, toHexPreview(response, 192));

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
        sendTpktFrame(output, new byte[] { 0x06, COTP_PDU_DR, 0x00, 0x00, 0x00, 0x00, 0x00 });
        output.flush();
    }

    private ProtocolKind detectProtocol(byte[] preview) {
        int firstOctet = preview[0] & 0xFF;
        if (looksLikeRfc1006Tpkt(preview)) {
            return ProtocolKind.RFC1006_TPKT;
        }
        if (looksLikeTlsClientHello(preview)) {
            return ProtocolKind.TLS_CLIENT_HELLO;
        }
        if (looksLikeBerApdu(preview)) {
            return ProtocolKind.BER_APDU;
        }
        if (isAsciiCommand(firstOctet)) {
            return ProtocolKind.TEXT_COMMAND;
        }
        return ProtocolKind.UNKNOWN_BINARY;
    }

    private boolean isAsciiCommand(int firstOctet) {
        return firstOctet >= 0x20 && firstOctet <= 0x7E;
    }

    private boolean looksLikeBerApdu(byte[] preview) {
        if (preview == null || preview.length < 2) {
            return false;
        }

        int firstOctet = preview[0] & 0xFF;
        if (firstOctet == 0x00 || firstOctet == 0xFF) {
            return false;
        }

        try {
            BerTlv tlv = BerCodec.decodeSingle(preview);
            int totalLength = tlv.headerLength() + tlv.length();
            return totalLength > 0 && totalLength <= preview.length;
        } catch (RuntimeException ex) {
            return false;
        }
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

    private boolean isProtocolAllowed(ProtocolKind protocolKind) {
        return listenerProfile.supports(protocolKind);
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
        if (bytes == null) {
            return "<null>";
        }
        if (bytes.length <= maxBytes) {
            return toHex(bytes);
        }
        byte[] preview = new byte[maxBytes];
        System.arraycopy(bytes, 0, preview, 0, maxBytes);
        return toHex(preview) + " ...";
    }

    private String classifyRfc1006Payload(byte[] payload) {
        if (payload == null || payload.length == 0) {
            return "EMPTY";
        }

        try {
            BerTlv tlv = BerCodec.decodeSingle(payload);

            if (looksLikeTopLevelAcseApdu(payload)) {
                return "ACSE_APDU";
            }

            if (tlv.tagClass() == TAG_CLASS_UNIVERSAL && tlv.constructed() && tlv.tagNumber() == 17) {
                return "OSI_PRESENTATION_PPDU";
            }

            if (looksLikeBerApdu(payload)) {
                return "BER_APDU";
            }
        } catch (RuntimeException ignored) {
        }

        int firstOctet = payload[0] & 0xFF;
        if (firstOctet == 0x0D || firstOctet == 0x01 || firstOctet == 0x0E) {
            return "OSI_SESSION_SPDU";
        }

        return "UNKNOWN_BINARY";
    }

    private boolean looksLikeTopLevelAcseApdu(byte[] encoded) {
        if (encoded == null || encoded.length < 12) {
            return false;
        }

        try {
            BerTlv tlv = BerCodec.decodeSingle(encoded);
            if (tlv.tagClass() != TAG_CLASS_APPLICATION || !tlv.constructed()) {
                return false;
            }
            if (tlv.tagNumber() < 0 || tlv.tagNumber() > 4) {
                return false;
            }
            if (tlv.length() < 10) {
                return false;
            }

            return acseAssociationProtocol.decode(encoded) != null;
        } catch (RuntimeException ex) {
            return false;
        }
    }

    private Optional<AcseModels.AcseApdu> tryDecodeAcse(byte[] encoded) {
        if (encoded == null || encoded.length == 0) {
            return Optional.empty();
        }

        try {
            return Optional.ofNullable(acseAssociationProtocol.decode(encoded));
        } catch (RuntimeException ex) {
            return Optional.empty();
        }
    }

    private byte[] extractApplicationPduFromRfc1006Payload(byte[] payload, String payloadKind) {
        if (payload == null || payload.length == 0) {
            return null;
        }

        return switch (payloadKind) {
            case "BER_APDU" -> extractApplicationPduFromAsn1Envelope(payload, payloadKind);
            case "OSI_SESSION_SPDU" -> extractApplicationPduFromSessionEnvelope(payload);
            case "OSI_PRESENTATION_PPDU", "ACSE_APDU" -> extractApplicationPduFromAsn1Envelope(payload, payloadKind);
            default -> null;
        };
    }

    private byte[] extractApplicationPduFromSessionEnvelope(byte[] payload) {
        if (payload == null || payload.length < 3) {
            return null;
        }

        int index = sessionParameterStart(payload);
        if (index < 0 || index >= payload.length) {
            logger.warn("P3 gateway session could not parse SPDU header");
            return null;
        }

        while (index + 1 < payload.length) {
            int pi = payload[index] & 0xFF;
            int li = payload[index + 1] & 0xFF;
            index += 2;

            if (index + li > payload.length) {
                logger.warn("P3 gateway session parameter truncated: pi=0x{} li={}", toHexByte((byte) pi), li);
                return null;
            }

            byte[] value = Arrays.copyOfRange(payload, index, index + li);
            index += li;

            if (pi == 0xC1 || pi == 0xC0 || pi == 0xC2) {
                logger.info(
                    "P3 gateway session found SPDU parameter pi=0x{} offset={} li={} first-bytes={}",
                    toHexByte((byte) pi),
                    index - li - 2,
                    li,
                    toHexPreview(value, 192)
                );

                String nestedKind = classifyRfc1006Payload(value);
                logger.info(
                    "P3 gateway session extracted session user-data len={} nested-kind={} first-bytes={}",
                    value.length,
                    nestedKind,
                    toHexPreview(value, 192)
                );

                byte[] extracted = extractApplicationPduFromRfc1006Payload(value, nestedKind);
                if (extracted != null) {
                    logger.info(
                        "P3 gateway session extracted inner application payload len={} first-bytes={}",
                        extracted.length,
                        toHexPreview(extracted, 192)
                    );
                    return extracted;
                }

                return value;
            }
        }

        logger.warn("P3 gateway session could not locate C1/C0/C2 user-data parameter inside SPDU");
        return null;
    }
    
    private byte[] extractApplicationPduFromAsn1Envelope(byte[] candidate, String payloadKind) {
        if (candidate == null || candidate.length == 0) {
            return null;
        }

        byte[] current = candidate;
        String currentKind = payloadKind;

        if ("OSI_PRESENTATION_PPDU".equals(currentKind)) {
            current = unwrapPresentation(current);
            if (current == null) {
                return null;
            }
            currentKind = classifyRfc1006Payload(current);
        }

        if ("ACSE_APDU".equals(currentKind) || isRealAcseApdu(current)) {
            byte[] acseUserData = unwrapAcse(current);
            if (acseUserData == null) {
                return null;
            }

            byte[] gateway = findGatewayApdu(acseUserData);
            if (gateway != null) {
                return gateway;
            }

            // recurse into the ACSE user-data if it is still wrapped
            String nestedKind = classifyRfc1006Payload(acseUserData);
            if (!"BER_APDU".equals(nestedKind)) {
                return extractApplicationPduFromAsn1Envelope(acseUserData, nestedKind);
            }

            return acseUserData;
        }

        try {
            BerTlv tlv = BerCodec.decodeSingle(current);

            if (isGatewayApdu(tlv)) {
                return current;
            }

            if (!tlv.constructed()) {
                return null;
            }

            for (BerTlv child : BerCodec.decodeAll(tlv.value())) {
                byte[] childEncoded = BerCodec.encode(child);
                byte[] found = extractApplicationPduFromAsn1Envelope(
                    childEncoded,
                    classifyRfc1006Payload(childEncoded)
                );
                if (found != null) {
                    return found;
                }
            }
        } catch (RuntimeException ignored) {
        }

        return null;
    }

    private byte[] unwrapPresentation(byte[] ppdu) {
        try {
            BerTlv root = BerCodec.decodeSingle(ppdu);

            if (root.tagClass() != TAG_CLASS_UNIVERSAL || !root.constructed() || root.tagNumber() != 17) {
                logger.debug("unwrapPresentation: not a presentation PPDU");
                return null;
            }

            List<BerTlv> children = BerCodec.decodeAll(root.value());

            // Prefer normal-mode-parameters [2]
            for (BerTlv child : children) {
                if (child.tagClass() == TAG_CLASS_CONTEXT && child.tagNumber() == 2 && child.constructed()) {
                    byte[] found = findPresentationFinalPayload(child);
                    logPresentationResult(found);
                    if (found != null) {
                        return found;
                    }
                }
            }

            // Fallback: search everywhere
            for (BerTlv child : children) {
                byte[] found = findPresentationFinalPayload(child);
                if (found != null) {
                    logPresentationResult(found);
                    return found;
                }
            }

            logPresentationResult(null);
            return null;
        } catch (RuntimeException ex) {
            logger.debug("Failed to unwrap presentation PPDU: {}", ex.getMessage());
            return null;
        }
    }

    private void logPresentationResult(byte[] found) {
        logger.info(
            "P3 gateway presentation unwrap result len={} first-bytes={}",
            found == null ? -1 : found.length,
            found == null ? "<null>" : toHexPreview(found, 192)
        );
    }

    private byte[] findPresentationFinalPayload(BerTlv node) {
        if (node == null) {
            return null;
        }

        byte[] encoded = BerCodec.encode(node);

        // 1) Accept only real ACSE APDUs directly
        if (isRealAcseApdu(encoded)) {
            return encoded;
        }

        // 2) Accept direct gateway APDU directly
        if (isGatewayApdu(node)) {
            return encoded;
        }

        // 3) Never accept tiny mode selector / control fragments
        if (isTinyPresentationControl(node)) {
            return null;
        }

        if (!node.constructed()) {
            return null;
        }

        List<BerTlv> children;
        try {
            children = BerCodec.decodeAll(node.value());
        } catch (RuntimeException ex) {
            return null;
        }

        // First pass: prefer direct ACSE children
        for (BerTlv child : children) {
            byte[] childEncoded = BerCodec.encode(child);
            if (isRealAcseApdu(childEncoded)) {
                return childEncoded;
            }
        }

        // Second pass: prefer direct gateway APDU children
        for (BerTlv child : children) {
            if (isGatewayApdu(child)) {
                return BerCodec.encode(child);
            }
        }

        // Third pass: recurse deeper
        for (BerTlv child : children) {
            byte[] found = findPresentationFinalPayload(child);
            if (found != null) {
                return found;
            }
        }

        return null;
    }

    private boolean isRealAcseApdu(byte[] encoded) {
        if (encoded == null || encoded.length < 10) {
            return false;
        }

        try {
            BerTlv tlv = BerCodec.decodeSingle(encoded);

            if (tlv.tagClass() != TAG_CLASS_APPLICATION || !tlv.constructed()) {
                return false;
            }

            int tag = tlv.tagNumber();
            if (tag < 0 || tag > 4) {
                return false;
            }

            return acseAssociationProtocol.decode(encoded) != null;
        } catch (RuntimeException ex) {
            return false;
        }
    }

    private boolean isTinyPresentationControl(BerTlv tlv) {
        if (tlv == null) {
            return false;
        }

        byte[] encoded = BerCodec.encode(tlv);

        // e.g. A0 03 80 01 01
        if (encoded.length <= 8) {
            return true;
        }

        if (tlv.tagClass() == TAG_CLASS_CONTEXT && tlv.constructed()) {
            try {
                List<BerTlv> nested = BerCodec.decodeAll(tlv.value());
                if (nested.size() == 1 && BerCodec.encode(nested.get(0)).length <= 8) {
                    return true;
                }
            } catch (RuntimeException ignored) {
            }
        }

        return false;
    }

    private byte[] findPresentationPayloadDeep(BerTlv node) {
        if (node == null) {
            return null;
        }

        byte[] encoded = BerCodec.encode(node);

        // Accept only real final payloads.
        if (isValidAcsePayload(encoded)) {
            return encoded;
        }
        if (isGatewayApdu(node)) {
            return encoded;
        }

        // Tiny presentation control fragments must never be returned directly.
        if (isTinyPresentationControlFragment(node)) {
            return null;
        }

        if (!node.constructed()) {
            return null;
        }

        List<BerTlv> children;
        try {
            children = BerCodec.decodeAll(node.value());
        } catch (RuntimeException ex) {
            return null;
        }

        // Pass 1: prefer direct ACSE children.
        for (BerTlv child : children) {
            byte[] childEncoded = BerCodec.encode(child);
            if (isValidAcsePayload(childEncoded)) {
                return childEncoded;
            }
        }

        // Pass 2: prefer direct gateway APDU children.
        for (BerTlv child : children) {
            if (isGatewayApdu(child)) {
                return BerCodec.encode(child);
            }
        }

        // Pass 3: recurse into children, but never stop on generic context containers.
        for (BerTlv child : children) {
            byte[] found = findPresentationPayloadDeep(child);
            if (found != null) {
                return found;
            }
        }

        return null;
    }

    private boolean isValidAcsePayload(byte[] encoded) {
        if (encoded == null || encoded.length < 10) {
            return false;
        }

        try {
            BerTlv tlv = BerCodec.decodeSingle(encoded);

            if (tlv.tagClass() != TAG_CLASS_APPLICATION || !tlv.constructed()) {
                return false;
            }

            int tag = tlv.tagNumber();
            if (tag < 0 || tag > 4) {
                return false;
            }

            return acseAssociationProtocol.decode(encoded) != null;
        } catch (RuntimeException ex) {
            return false;
        }
    }

    private boolean isTinyPresentationControlFragment(BerTlv tlv) {
        if (tlv == null) {
            return false;
        }

        byte[] encoded = BerCodec.encode(tlv);

        // Typical fragments like:
        // A0 03 80 01 01
        // A1 06 06 04 xx xx xx xx
        // short selectors / OIDs / mode values
        if (encoded.length <= 8) {
            return true;
        }

        // Also reject a constructed context node with only one tiny scalar child.
        if (tlv.tagClass() == TAG_CLASS_CONTEXT && tlv.constructed()) {
            try {
                List<BerTlv> nested = BerCodec.decodeAll(tlv.value());
                if (nested.size() == 1 && BerCodec.encode(nested.get(0)).length <= 8) {
                    return true;
                }
            } catch (RuntimeException ignored) {
            }
        }

        return false;
    }
   
    private byte[] unwrapAcse(byte[] acseApdu) {
        try {
            BerTlv acse = BerCodec.decodeSingle(acseApdu);
            return unwrapAcseNode(acse);
        } catch (RuntimeException ex) {
            logger.debug("Failed to unwrap ACSE APDU: {}", ex.getMessage());
            return null;
        }
    }

    private byte[] unwrapAcseNode(BerTlv node) {
        if (node == null) {
            return null;
        }

        try {
            if (node.tagClass() == TAG_CLASS_CONTEXT && node.tagNumber() == 30) {
                byte[] externalOrInner = unwrapExternalOrNested(node.value());
                if (externalOrInner != null) {
                    return externalOrInner;
                }
            }

            if (node.constructed()) {
                for (BerTlv child : BerCodec.decodeAll(node.value())) {
                    byte[] found = unwrapAcseNode(child);
                    if (found != null) {
                        return found;
                    }
                }
            }
        } catch (RuntimeException ignored) {
        }

        return null;
    }

    private byte[] unwrapExternalOrNested(byte[] data) {
        if (data == null || data.length < 2) {
            return null;
        }

        try {
            BerTlv tlv = BerCodec.decodeSingle(data);

            if (isGatewayApdu(tlv)) {
                return BerCodec.encode(tlv);
            }

            byte[] encoded = BerCodec.encode(tlv);
            if (looksLikeTopLevelAcseApdu(encoded)) {
                return encoded;
            }

            if (tlv.tagClass() == TAG_CLASS_UNIVERSAL && tlv.constructed() && tlv.tagNumber() == 17) {
                return encoded;
            }

            if (tlv.constructed()) {
                for (BerTlv child : BerCodec.decodeAll(tlv.value())) {
                    byte[] found = unwrapExternalOrNested(BerCodec.encode(child));
                    if (found != null) {
                        return found;
                    }
                }
            }
        } catch (RuntimeException ignored) {
        }

        return null;
    }

    private byte[] findGatewayApdu(byte[] data) {
        if (data == null || data.length == 0) {
            return null;
        }

        try {
            BerTlv tlv = BerCodec.decodeSingle(data);

            if (isLikelyGatewayApdu(tlv, data)) {
                return BerCodec.encode(tlv);
            }

            if (!tlv.constructed()) {
                return null;
            }

            for (BerTlv child : BerCodec.decodeAll(tlv.value())) {
                byte[] found = findGatewayApdu(BerCodec.encode(child));
                if (found != null) {
                    return found;
                }
            }

            return null;
        } catch (RuntimeException ex) {
            logger.debug("Failed to find gateway APDU: {}", ex.getMessage());
            return null;
        }
    }

    private boolean isLikelyGatewayApdu(BerTlv tlv, byte[] encoded) {
        if (!isGatewayApdu(tlv)) {
            return false;
        }

        if (encoded == null || encoded.length < 8) {
            return false;
        }

        // Reject tiny control fragments like A0 03 80 01 01
        if (encoded.length <= 6) {
            return false;
        }

        return true;
    }

    private byte[] rewrapApplicationPduForRfc1006Response(byte[] applicationResponse, String inboundKind, byte[] inboundPayload) {
        if (applicationResponse == null) {
            return new byte[0];
        }

        if ("BER_APDU".equals(inboundKind)) {
            byte[] preserved = replaceInboundGatewayApdu(inboundPayload, applicationResponse);
            return preserved != null ? preserved : applicationResponse;
        }

        if ("ACSE_APDU".equals(inboundKind)) {
            byte[] requestAcse = findPreferredAcseForResponse(inboundPayload);
            return wrapAcseEnvelope(applicationResponse, requestAcse);
        }

        if ("OSI_PRESENTATION_PPDU".equals(inboundKind)) {
            byte[] requestAcse = findPreferredAcseForResponse(inboundPayload);
            byte[] acseResponse = wrapAcseEnvelope(applicationResponse, requestAcse);
            return wrapPresentationEnvelope(acseResponse, inboundPayload);
        }

        if ("OSI_SESSION_SPDU".equals(inboundKind)) {
            byte[] sessionUserData = extractSessionUserDataParameter(inboundPayload);
            String nestedKind = classifyRfc1006Payload(sessionUserData);

            logger.info(
                "P3 session rewrap template kind={} first-bytes={}",
                nestedKind,
                sessionUserData == null ? "<none>" : toHexPreview(sessionUserData, 192)
            );

            byte[] sessionPayload;
            if ("OSI_PRESENTATION_PPDU".equals(nestedKind)) {
                byte[] requestAcse = findPreferredAcseForResponse(sessionUserData);
                byte[] acseResponse = wrapAcseEnvelope(applicationResponse, requestAcse);
                sessionPayload = wrapPresentationEnvelope(acseResponse, sessionUserData);
                logger.info("P3 session rebuilt PPDU len={} first-bytes={}", sessionPayload.length, toHexPreview(sessionPayload, 192));
            } else if ("ACSE_APDU".equals(nestedKind)) {
                byte[] requestAcse = findPreferredAcseForResponse(sessionUserData);
                sessionPayload = wrapAcseEnvelope(applicationResponse, requestAcse);
            } else {
                sessionPayload = applicationResponse;
            }

            byte[] rewrittenSession = replaceSessionPresentationPayload(inboundPayload, sessionPayload);
            return rewrittenSession != null ? rewrittenSession : sessionPayload;
        }

        byte[] preserved = replaceInboundGatewayApdu(inboundPayload, applicationResponse);
        return preserved != null ? preserved : applicationResponse;
    }

    private byte[] findPreferredAcseForResponse(byte[] data) {
        if (data == null || data.length == 0) {
            return null;
        }

        if (tryDecodeAcse(data).isPresent()) {
            return data;
        }

        String kind = classifyRfc1006Payload(data);
        if ("OSI_SESSION_SPDU".equals(kind)) {
            byte[] sessionUserData = extractSessionUserDataParameter(data);
            return findPreferredAcseForResponse(sessionUserData);
        }

        if ("OSI_PRESENTATION_PPDU".equals(kind)) {
            return extractTopLevelAcseFromPresentation(data);
        }

        try {
            BerTlv tlv = BerCodec.decodeSingle(data);
            if (!tlv.constructed()) {
                return null;
            }
            for (BerTlv child : BerCodec.decodeAll(tlv.value())) {
                byte[] encoded = BerCodec.encode(child);
                byte[] found = findPreferredAcseForResponse(encoded);
                if (found != null) {
                    return found;
                }
            }
        } catch (RuntimeException ex) {
            logger.debug("Failed to find ACSE seed for response: {}", ex.getMessage());
        }

        return null;
    }

    private byte[] extractTopLevelAcseFromPresentation(byte[] ppdu) {
        try {
            BerTlv root = BerCodec.decodeSingle(ppdu);
            if (!root.constructed()) {
                return null;
            }

            for (BerTlv child : BerCodec.decodeAll(root.value())) {
                byte[] encodedChild = BerCodec.encode(child);
                if (looksLikeTopLevelAcseApdu(encodedChild)) {
                    return encodedChild;
                }
            }

            for (BerTlv child : BerCodec.decodeAll(root.value())) {
                if (!child.constructed()) {
                    continue;
                }
                byte[] nested = extractTopLevelAcseFromPresentation(BerCodec.encode(child));
                if (nested != null) {
                    return nested;
                }
            }

            return null;
        } catch (RuntimeException ex) {
            logger.debug("Failed to extract top-level ACSE from PPDU: {}", ex.getMessage());
            return null;
        }
    }

    private byte[] wrapAcseEnvelope(byte[] payload, byte[] inboundAcse) {
        logger.info(
            "P3 ACSE wrapping payload len={} inbound-acse-first-bytes={}",
            payload.length,
            inboundAcse == null ? "<null>" : toHexPreview(inboundAcse, 192)
        );

        try {
            if (inboundAcse != null && inboundAcse.length > 0) {
                Optional<AcseModels.AcseApdu> decoded = tryDecodeAcse(inboundAcse);
                if (decoded.isPresent()) {
                    AcseModels.AcseApdu apdu = decoded.get();

                    if (apdu instanceof AcseModels.AARQApdu) {
                        Optional<String> applicationContextName = extractApplicationContextNameFromAarq(inboundAcse);

                        AcseModels.AAREApdu aare = new AcseModels.AAREApdu(
                            applicationContextName,
                            true,
                            Optional.empty(),
                            Optional.of(new AcseModels.ResultSourceDiagnostic(1, 0)),
                            Optional.of(payload),
                            List.of(),
                            Set.of()
                        );

                        byte[] encoded = acseAssociationProtocol.encode(aare);
                        logger.info("P3 ACSE built blind AARE len={} first-bytes={}", encoded.length, toHexPreview(encoded, 192));
                        return encoded;
                    }

                    if (apdu instanceof AcseModels.RLRQApdu) {
                        AcseModels.RLREApdu rlre = new AcseModels.RLREApdu(true);
                        byte[] encoded = acseAssociationProtocol.encode(rlre);
                        logger.info("P3 ACSE built RLRE len={} first-bytes={}", encoded.length, toHexPreview(encoded, 192));
                        return encoded;
                    }
                }
            }
        } catch (RuntimeException ex) {
            logger.warn("Failed to inspect inbound ACSE APDU: {}", ex.getMessage(), ex);
        }

        AcseModels.AAREApdu fallback = new AcseModels.AAREApdu(
            Optional.empty(),
            true,
            Optional.empty(),
            Optional.of(new AcseModels.ResultSourceDiagnostic(1, 0)),
            Optional.of(payload),
            List.of(),
            Set.of()
        );

        byte[] encoded = acseAssociationProtocol.encode(fallback);
        logger.info("P3 ACSE built fallback AARE len={} first-bytes={}", encoded.length, toHexPreview(encoded, 192));
        return encoded;
    }

    private byte[] wrapPresentationEnvelope(byte[] payload, byte[] inboundPresentation) {
        byte[] userData = BerCodec.encode(new BerTlv(TAG_CLASS_CONTEXT, true, 30, 0, payload.length, payload));
        try {
            if (inboundPresentation != null && inboundPresentation.length > 0) {
                BerTlv inbound = BerCodec.decodeSingle(inboundPresentation);
                return BerCodec.encode(
                    new BerTlv(
                        mapPresentationResponseClass(inbound),
                        true,
                        mapPresentationResponseTag(inbound),
                        0,
                        userData.length,
                        userData
                    )
                );
            }
        } catch (RuntimeException ex) {
            logger.debug("Failed to preserve inbound presentation envelope: {}", ex.getMessage());
        }

        return BerCodec.encode(new BerTlv(TAG_CLASS_APPLICATION, true, 1, 0, userData.length, userData));
    }

    private byte[] replaceInboundGatewayApdu(byte[] inboundPayload, byte[] applicationResponse) {
        if (inboundPayload == null || inboundPayload.length == 0) {
            return null;
        }

        try {
            BerTlv root = BerCodec.decodeSingle(inboundPayload);
            BerTlv rewritten = replaceGatewayApduInTlv(root, applicationResponse);
            return rewritten == null ? null : BerCodec.encode(rewritten);
        } catch (RuntimeException ex) {
            logger.debug("Failed to replace inbound gateway APDU: {}", ex.getMessage());
            return null;
        }
    }

    private BerTlv replaceGatewayApduInTlv(BerTlv tlv, byte[] replacement) {
        if (isGatewayApdu(tlv)) {
            return BerCodec.decodeSingle(replacement);
        }

        if (!tlv.constructed()) {
            return null;
        }

        List<BerTlv> nested = BerCodec.decodeAll(tlv.value());
        for (int i = 0; i < nested.size(); i++) {
            BerTlv updatedChild = replaceGatewayApduInTlv(nested.get(i), replacement);
            if (updatedChild == null) {
                continue;
            }

            nested.set(i, updatedChild);
            byte[] encodedChildren = BerCodec.encodeAll(nested);
            return new BerTlv(
                tlv.tagClass(),
                tlv.constructed(),
                tlv.tagNumber(),
                tlv.headerLength(),
                encodedChildren.length,
                encodedChildren
            );
        }

        return null;
    }

    private byte[] extractSessionUserDataParameter(byte[] spdu) {
        SessionParameterMatch preferred = findSessionParameterByScan(spdu, 0xC1);
        if (preferred != null) {
            return preferred.value();
        }

        SessionParameterMatch fallbackC0 = findSessionParameterByScan(spdu, 0xC0);
        if (fallbackC0 != null) {
            return fallbackC0.value();
        }

        SessionParameterMatch fallbackC2 = findSessionParameterByScan(spdu, 0xC2);
        if (fallbackC2 != null) {
            return fallbackC2.value();
        }

        return null;
    }
    
    private SessionParameterMatch findSessionParameterByScan(byte[] spdu, int targetPi) {
        if (spdu == null || spdu.length < 4) {
            return null;
        }

        for (int index = 1; index + 2 <= spdu.length; index++) {
            int pi = spdu[index] & 0xFF;
            if (pi != targetPi) {
                continue;
            }

            int li = spdu[index + 1] & 0xFF;
            int valueStart = index + 2;
            int valueEnd = valueStart + li;

            if (valueEnd > spdu.length) {
                continue;
            }

            byte[] value = Arrays.copyOfRange(spdu, valueStart, valueEnd);
            if (!looksLikeBerApdu(value)) {
                continue;
            }

            logger.info(
                "P3 gateway session found SPDU parameter pi=0x{} offset={} li={} first-bytes={}",
                toHexByte((byte) pi),
                index,
                li,
                toHexPreview(value, 128)
            );

            return new SessionParameterMatch(index, pi, li, value);
        }

        return null;
    }

    private SessionParameterMatch findSessionParameter(byte[] spdu, int targetPi) {
    	int index = sessionParameterStart(spdu);
        if (index < 0) {
            return null;
        }

        while (index + 1 < spdu.length) {
            int pi = spdu[index] & 0xFF;
            int li = spdu[index + 1] & 0xFF;
            int valueStart = index + 2;
            int valueEnd = valueStart + li;

            if (valueEnd > spdu.length) {
                logger.warn("Invalid SPDU parameter bounds: pi=0x{} li={}", toHexByte((byte) pi), li);
                return null;
            }

            byte[] value = Arrays.copyOfRange(spdu, valueStart, valueEnd);

            if (pi == targetPi && looksLikeBerApdu(value)) {
                logger.info(
                    "P3 gateway session found SPDU parameter pi=0x{} offset={} li={} first-bytes={}",
                    toHexByte((byte) pi),
                    index,
                    li,
                    toHexPreview(value, 128)
                );
                return new SessionParameterMatch(index, pi, li, value);
            }

            index = valueEnd;
        }

        return null;
    }

    private byte[] replaceSessionPresentationPayload(byte[] inboundSessionPayload, byte[] newPresentationOrAcsePayload) {
        if (inboundSessionPayload == null || inboundSessionPayload.length < 4 || newPresentationOrAcsePayload == null) {
            return null;
        }

        if (newPresentationOrAcsePayload.length > 255) {
            throw new IllegalArgumentException(
                "Session parameter payload too large for one-octet LI: " + newPresentationOrAcsePayload.length
            );
        }

        SessionParameterMatch match = findSessionParameterByScan(inboundSessionPayload, 0xC1);
        if (match == null) {
            match = findSessionParameterByScan(inboundSessionPayload, 0xC0);
        }
        if (match == null) {
            match = findSessionParameterByScan(inboundSessionPayload, 0xC2);
        }
        if (match == null) {
            logger.warn("P3 session rewrite failed: no C1/C0/C2 BER parameter found");
            return null;
        }

        int paramsStart = sessionParameterStart(inboundSessionPayload);
        if (paramsStart < 0 || paramsStart > match.offset()) {
            logger.warn("P3 session rewrite failed: invalid SPDU parameter start");
            return null;
        }

        ByteArrayOutputStream params = new ByteArrayOutputStream();

        // copy parameters before the matched one
        params.writeBytes(Arrays.copyOfRange(inboundSessionPayload, paramsStart, match.offset()));

        // replace matched parameter
        params.write((byte) match.pi());
        params.write((byte) newPresentationOrAcsePayload.length);
        params.writeBytes(newPresentationOrAcsePayload);

        // copy parameters after the matched one
        int tailStart = match.offset() + 2 + match.li();
        if (tailStart < inboundSessionPayload.length) {
            params.writeBytes(Arrays.copyOfRange(inboundSessionPayload, tailStart, inboundSessionPayload.length));
        }

        byte[] paramBytes = params.toByteArray();

        ByteArrayOutputStream out = new ByteArrayOutputStream();

        // SPDU code
        out.write(mapSessionResponseCode(inboundSessionPayload[0]));

        // extended LI form
        out.write(0xFF);
        out.write((paramBytes.length >> 8) & 0xFF);
        out.write(paramBytes.length & 0xFF);

        out.writeBytes(paramBytes);
        return out.toByteArray();
    }

    private int sessionParameterStart(byte[] spdu) {
        if (spdu == null || spdu.length < 2) {
            return -1;
        }

        if (!isSessionSpduCode(spdu[0])) {
            return -1;
        }

        int index = 1;
        int li = spdu[index] & 0xFF;
        index++;

        if (li == 0xFF) {
            // Extended LI: next 2 octets carry the SPDU length
            if (index + 1 >= spdu.length) {
                return -1;
            }

            int bodyLength = ((spdu[index] & 0xFF) << 8) | (spdu[index + 1] & 0xFF);
            index += 2;

            // Parameters begin immediately after SI + extended LI
            // Total bytes should be: 1 (SI) + 3 (LI field) + bodyLength
            int expectedTotal = 1 + 3 + bodyLength;
            if (expectedTotal != spdu.length) {
                logger.debug(
                    "P3 gateway session SPDU extended-length mismatch: expectedTotal={} actual={}",
                    expectedTotal,
                    spdu.length
                );
            }

            return index; // <-- usually 4
        }

        // Short LI form
        int expectedTotal = 1 + 1 + li;
        if (expectedTotal != spdu.length) {
            logger.debug(
                "P3 gateway session SPDU short-length mismatch: expectedTotal={} actual={}",
                expectedTotal,
                spdu.length
            );
        }

        return index; // <-- usually 2
    }

    private boolean looksLikeValidSessionParameterStream(byte[] spdu, int start) {
        if (start < 0 || start >= spdu.length) {
            return false;
        }

        int index = start;
        boolean sawAtLeastOneParameter = false;

        while (index + 1 < spdu.length) {
            int li = spdu[index + 1] & 0xFF;
            int valueStart = index + 2;
            int valueEnd = valueStart + li;

            if (valueEnd > spdu.length) {
                return false;
            }

            sawAtLeastOneParameter = true;
            index = valueEnd;
        }

        return sawAtLeastOneParameter && index == spdu.length;
    }

    private Optional<String> extractApplicationContextNameFromAarq(byte[] inboundAcse) {
        if (inboundAcse == null || inboundAcse.length == 0) {
            return Optional.empty();
        }

        try {
            BerTlv aarq = BerCodec.decodeSingle(inboundAcse);
            if (aarq.tagClass() != TAG_CLASS_APPLICATION || !aarq.constructed() || aarq.tagNumber() != 0) {
                return Optional.empty();
            }

            List<BerTlv> fields = BerCodec.decodeAll(aarq.value());
            return BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 1).map(field -> {
                BerTlv oid = BerCodec.decodeSingle(field.value());
                if (!oid.isUniversal() || oid.tagNumber() != 6) {
                    throw new IllegalArgumentException("AARQ application-context-name is not an OBJECT IDENTIFIER");
                }
                return decodeOidValue(oid.value());
            });
        } catch (RuntimeException ex) {
            logger.debug("Failed to extract AARQ application-context-name: {}", ex.getMessage());
            return Optional.empty();
        }
    }

    private int mapPresentationResponseClass(BerTlv inboundPresentation) {
        if (inboundPresentation.tagClass() == TAG_CLASS_APPLICATION && inboundPresentation.tagNumber() == 1) {
            return TAG_CLASS_UNIVERSAL;
        }
        return inboundPresentation.tagClass();
    }

    private int mapPresentationResponseTag(BerTlv inboundPresentation) {
        if (inboundPresentation.tagClass() == TAG_CLASS_APPLICATION && inboundPresentation.tagNumber() == 1) {
            return 17;
        }
        return inboundPresentation.tagNumber();
    }

    private boolean isGatewayApdu(BerTlv tlv) {
        return tlv != null
            && tlv.tagClass() == TAG_CLASS_CONTEXT
            && tlv.constructed()
            && tlv.tagNumber() >= GATEWAY_APDU_MIN_TAG
            && tlv.tagNumber() <= GATEWAY_APDU_MAX_TAG;
    }

    private boolean isSessionSpduCode(byte value) {
        int firstOctet = value & 0xFF;
        return firstOctet == 0x0D || firstOctet == 0x01 || firstOctet == 0x0E;
    }

    private byte mapSessionResponseCode(byte inboundCode) {
        int code = inboundCode & 0xFF;
        return switch (code) {
            case 0x0D -> (byte) 0x0E;
            default -> inboundCode;
        };
    }

    private String decodeOidValue(byte[] oidBytes) {
        if (oidBytes == null || oidBytes.length == 0) {
            throw new IllegalArgumentException("BER OBJECT IDENTIFIER is empty");
        }

        int first = oidBytes[0] & 0xFF;
        int firstArc = Math.min(first / 40, 2);
        int secondArc = first - (firstArc * 40);

        StringBuilder oid = new StringBuilder();
        oid.append(firstArc).append('.').append(secondArc);

        long value = 0;
        for (int i = 1; i < oidBytes.length; i++) {
            int octet = oidBytes[i] & 0xFF;
            value = (value << 7) | (octet & 0x7F);
            if ((octet & 0x80) == 0) {
                oid.append('.').append(value);
                value = 0;
            }
        }

        if (value != 0) {
            throw new IllegalArgumentException("Invalid BER OBJECT IDENTIFIER encoding");
        }

        return oid.toString();
    }

    private enum ProtocolKind {
        TEXT_COMMAND,
        BER_APDU,
        RFC1006_TPKT,
        TLS_CLIENT_HELLO,
        UNKNOWN_BINARY
    }

    private enum ListenerProfile {
        STANDARD_P3,
        GATEWAY_MULTI_PROTOCOL;

        private static ListenerProfile from(String value) {
            if (value == null || value.isBlank()) {
                return STANDARD_P3;
            }
            try {
                return ListenerProfile.valueOf(value.trim().toUpperCase());
            } catch (IllegalArgumentException ex) {
                throw new IllegalArgumentException(
                    "Invalid amhs.p3.gateway.listener-profile value '" + value
                        + "'. Supported values: STANDARD_P3, GATEWAY_MULTI_PROTOCOL"
                );
            }
        }

        private boolean supports(ProtocolKind protocolKind) {
            if (this == GATEWAY_MULTI_PROTOCOL) {
                return protocolKind == ProtocolKind.BER_APDU || protocolKind == ProtocolKind.RFC1006_TPKT;
            }
            return protocolKind == ProtocolKind.RFC1006_TPKT;
        }

        private String supportedProtocolsSummary() {
            if (this == GATEWAY_MULTI_PROTOCOL) {
                return "BER_APDU, RFC1006_TPKT";
            }
            return "RFC1006_TPKT";
        }
    }

    private record CotpFrame(byte type, boolean endOfTsdu, byte[] userData, byte[] payload) {}
    private record SessionParameterMatch(int offset, int pi, int li, byte[] value) {}

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