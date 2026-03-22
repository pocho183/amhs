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
import java.util.ArrayList;
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

        logger.info(
            "AMHS P3 gateway listener-profile={} supported={}",
            this.listenerProfile,
            this.listenerProfile.supportedProtocolsSummary()
        );
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

            if (!listenerProfile.supports(protocolKind)) {
                logger.warn(
                    "P3 gateway connection #{} rejected protocol={} for listener-profile={} supported={}",
                    connectionId,
                    protocolKind,
                    listenerProfile,
                    listenerProfile.supportedProtocolsSummary()
                );
                return;
            }

            switch (protocolKind) {
                case TEXT_COMMAND -> handleTextSession(connectionId, session, input, output);
                case BER_APDU -> handleBerSession(connectionId, session, input, output);
                case RFC1006_TPKT -> handleRfc1006Session(connectionId, session, input, output);
                default -> logger.warn("P3 gateway connection #{} unsupported protocol={}", connectionId, protocolKind);
            }

        } catch (Exception ex) {
            if (ex instanceof EOFException || ex instanceof SocketException) {
                logger.debug("P3 gateway connection #{} ended: {}", connectionId, ex.getMessage());
            } else {
                logger.warn("P3 gateway connection #{} error: {}", connectionId, ex.getMessage(), ex);
            }
        }
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
                    logger.info(
                        "P3 gateway connection #{} text session closed by command {}",
                        connectionId,
                        commandName(line)
                    );
                    return;
                }
            }
        }
    }

    private void handleBerSession(
        long connectionId,
        P3GatewaySessionService.SessionState session,
        PushbackInputStream input,
        OutputStream output
    ) throws Exception {
        int pduIndex = 0;

        while (true) {
            byte[] pdu = asn1GatewayProtocol.readPdu(input);
            if (pdu == null) {
                logger.info("P3 gateway connection #{} BER session closed after {} APDU(s)", connectionId, pduIndex);
                return;
            }

            pduIndex++;

            logger.info(
                "P3 gateway connection #{} BER APDU #{} len={} first-bytes={}",
                connectionId,
                pduIndex,
                pdu.length,
                toHexPreview(pdu, 128)
            );

            if (isIgnorablePostBindBerControl(pdu)) {
                logger.info(
                    "P3 gateway connection #{} ignoring post-bind BER control len={} first-bytes={}",
                    connectionId,
                    pdu.length,
                    toHexPreview(pdu, 16)
                );
                continue;
            }

            byte[] response = asn1GatewayProtocol.handle(session, pdu);
            output.write(response);
            output.flush();

            if (session.isClosed()) {
                logger.info("P3 gateway connection #{} BER session closed by release", connectionId);
                return;
            }
        }
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
                logger.info("P3 gateway connection #{} RFC1006 session closed after {} payload(s)", connectionId, pduIndex);
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
                    "P3 gateway connection #{} ignoring unsupported TPDU type=0x{}",
                    connectionId,
                    toHexByte(frame.type)
                );
                continue;
            }

            segmentedPayload.writeBytes(frame.userData);
            if (!frame.endOfTsdu) {
                continue;
            }

            byte[] payload = segmentedPayload.toByteArray();
            segmentedPayload.reset();

            if (payload.length == 0) {
                continue;
            }

            pduIndex++;
            String kind = classifyPayload(payload);

            logger.info(
                "P3 gateway connection #{} RFC1006 payload #{} len={} kind={} first-bytes={}",
                connectionId,
                pduIndex,
                payload.length,
                kind,
                toHexPreview(payload, 192)
            );

            if (isIgnorablePostBindBerControl(payload)) {
                logger.info(
                    "P3 gateway connection #{} ignoring post-bind BER control payload #{} len={} first-bytes={}",
                    connectionId,
                    pduIndex,
                    payload.length,
                    toHexPreview(payload, 16)
                );
                continue;
            }

            byte[] applicationPdu = extractApplicationPdu(payload, kind);
            if (applicationPdu == null) {
                logger.warn(
                    "P3 gateway connection #{} payload #{} unsupported kind={} first-bytes={}",
                    connectionId,
                    pduIndex,
                    kind,
                    toHexPreview(payload, 192)
                );
                sendRfc1006Disconnect(output);
                return;
            }

            logger.info(
                "P3 gateway delivering application PDU to ASN.1 handler len={} first-bytes={}",
                applicationPdu.length,
                toHexPreview(applicationPdu, 128)
            );

            if (isIgnorablePostBindBerControl(applicationPdu)) {
                logger.info(
                    "P3 gateway connection #{} ignoring extracted post-bind control first-bytes={}",
                    connectionId,
                    toHexPreview(applicationPdu, 16)
                );
                continue;
            }

            byte[] applicationResponse = asn1GatewayProtocol.handle(session, applicationPdu);
            byte[] wrappedResponse = rewrapResponse(payload, kind, applicationResponse);

            logger.info(
                "P3 outbound application response len={} first-bytes={}",
                applicationResponse.length,
                toHexPreview(applicationResponse, 128)
            );
            logger.info(
                "P3 outbound wrapped response len={} first-bytes={}",
                wrappedResponse.length,
                toHexPreview(wrappedResponse, 192)
            );

            sendRfc1006Dt(output, wrappedResponse);

            if (session.isClosed()) {
                logger.info("P3 gateway connection #{} RFC1006 session closed by release", connectionId);
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

        if (lengthIndicator < 2) {
            throw new IllegalArgumentException("Unsupported COTP DT header");
        }

        boolean eot = (cotpTpdu[2] & 0x80) != 0;
        int dataOffset = lengthIndicator + 1;
        byte[] userData = Arrays.copyOfRange(cotpTpdu, dataOffset, cotpTpdu.length);

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
            throw new IllegalArgumentException("TPKT frame too large: " + length);
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
        int first = preview[0] & 0xFF;

        if (looksLikeRfc1006(preview)) {
            return ProtocolKind.RFC1006_TPKT;
        }
        if (looksLikeTlsClientHello(preview)) {
            return ProtocolKind.TLS_CLIENT_HELLO;
        }
        if (looksLikeBer(preview)) {
            return ProtocolKind.BER_APDU;
        }
        if (first >= 0x20 && first <= 0x7E) {
            return ProtocolKind.TEXT_COMMAND;
        }
        return ProtocolKind.UNKNOWN_BINARY;
    }

    private boolean looksLikeRfc1006(byte[] preview) {
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

    private boolean looksLikeBer(byte[] preview) {
        if (preview == null || preview.length < 2) {
            return false;
        }

        int first = preview[0] & 0xFF;
        if (first == 0x00 || first == 0xFF) {
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

    private String classifyPayload(byte[] payload) {
        if (payload == null || payload.length == 0) {
            return "EMPTY";
        }

        try {
            BerTlv tlv = BerCodec.decodeSingle(payload);

            if (looksLikeTopLevelAcse(payload)) {
                return "ACSE_APDU";
            }
            if (tlv.tagClass() == TAG_CLASS_UNIVERSAL && tlv.constructed() && tlv.tagNumber() == 17) {
                return "OSI_PRESENTATION_PPDU";
            }
            if (looksLikeBer(payload)) {
                return "BER_APDU";
            }
        } catch (RuntimeException ignored) {
        }

        int first = payload[0] & 0xFF;
        if (first == 0x0D || first == 0x01 || first == 0x0E) {
            return "OSI_SESSION_SPDU";
        }

        return "UNKNOWN_BINARY";
    }

    private byte[] extractApplicationPdu(byte[] payload, String kind) {
        if (payload == null || payload.length == 0) {
            return null;
        }

        return switch (kind) {
            case "BER_APDU" -> payload;
            case "OSI_SESSION_SPDU" -> {
                byte[] sessionUserData = extractSessionUserData(payload);
                if (sessionUserData == null) {
                    yield null;
                }
                yield extractApplicationPdu(sessionUserData, classifyPayload(sessionUserData));
            }
            case "OSI_PRESENTATION_PPDU" -> {
                byte[] ppduUserData = unwrapPresentation(payload);
                if (ppduUserData == null) {
                    yield null;
                }
                yield extractApplicationPdu(ppduUserData, classifyPayload(ppduUserData));
            }
            case "ACSE_APDU" -> unwrapAcse(payload);
            default -> null;
        };
    }

    private byte[] rewrapResponse(byte[] inboundPayload, String inboundKind, byte[] applicationResponse) {
        if (applicationResponse == null) {
            return new byte[0];
        }

        if ("BER_APDU".equals(inboundKind)) {
            return applicationResponse;
        }

        if ("ACSE_APDU".equals(inboundKind)) {
            byte[] inboundAcse = findPreferredAcseForResponse(inboundPayload);
            if (inboundAcse == null) {
                return applicationResponse;
            }
            return wrapAcseEnvelope(applicationResponse, inboundAcse);
        }

        if ("OSI_PRESENTATION_PPDU".equals(inboundKind)) {
            byte[] inboundAcse = findPreferredAcseForResponse(inboundPayload);

            if (inboundAcse == null) {
                return wrapPresentationEnvelope(applicationResponse);
            }

            byte[] acseResponse = wrapAcseEnvelope(applicationResponse, inboundAcse);
            return wrapPresentationEnvelope(acseResponse);
        }

        if ("OSI_SESSION_SPDU".equals(inboundKind)) {
            byte[] sessionUserData = extractSessionUserData(inboundPayload);
            if (sessionUserData == null) {
                return applicationResponse;
            }

            String nestedKind = classifyPayload(sessionUserData);
            byte[] nestedResponse;

            if ("OSI_PRESENTATION_PPDU".equals(nestedKind)) {
                byte[] inboundAcse = findPreferredAcseForResponse(sessionUserData);

                if (inboundAcse == null) {
                    nestedResponse = wrapPresentationEnvelope(applicationResponse);
                } else {
                    byte[] acseResponse = wrapAcseEnvelope(applicationResponse, inboundAcse);
                    nestedResponse = wrapPresentationEnvelope(acseResponse);
                }
            } else if ("ACSE_APDU".equals(nestedKind)) {
                byte[] inboundAcse = findPreferredAcseForResponse(sessionUserData);
                if (inboundAcse == null) {
                    nestedResponse = applicationResponse;
                } else {
                    nestedResponse = wrapAcseEnvelope(applicationResponse, inboundAcse);
                }
            } else {
                nestedResponse = applicationResponse;
            }

            byte[] rebuilt = replaceSessionUserData(inboundPayload, nestedResponse);
            return rebuilt != null ? rebuilt : nestedResponse;
        }

        return applicationResponse;
    }

    private byte[] findPreferredAcseForResponse(byte[] data) {
        if (data == null || data.length == 0) {
            return null;
        }

        if (isRealAcseApdu(data)) {
            return data;
        }

        String kind = classifyPayload(data);

        if ("OSI_SESSION_SPDU".equals(kind)) {
            byte[] sessionUserData = extractSessionUserData(data);
            return findPreferredAcseForResponse(sessionUserData);
        }

        if ("OSI_PRESENTATION_PPDU".equals(kind)) {
            try {
                BerTlv root = BerCodec.decodeSingle(data);
                if (!root.constructed()) {
                    return null;
                }

                for (BerTlv child : BerCodec.decodeAll(root.value())) {
                    byte[] encodedChild = BerCodec.encode(child);
                    byte[] found = findPreferredAcseForResponse(encodedChild);
                    if (found != null) {
                        return found;
                    }
                }
            } catch (RuntimeException ex) {
                logger.debug("Failed to search ACSE inside presentation: {}", ex.getMessage());
            }
            return null;
        }

        try {
            BerTlv tlv = BerCodec.decodeSingle(data);
            if (!tlv.constructed()) {
                return null;
            }

            for (BerTlv child : BerCodec.decodeAll(tlv.value())) {
                byte[] encodedChild = BerCodec.encode(child);
                byte[] found = findPreferredAcseForResponse(encodedChild);
                if (found != null) {
                    return found;
                }
            }
        } catch (RuntimeException ex) {
            logger.debug("Failed to search nested ACSE: {}", ex.getMessage());
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

    private byte[] extractSessionUserData(byte[] spdu) {
        int start = sessionParameterStart(spdu);
        if (start < 0) {
            logger.warn("P3 gateway session could not parse SPDU header");
            return null;
        }

        int index = start;
        while (index + 1 < spdu.length) {
            int pi = spdu[index] & 0xFF;
            int li = spdu[index + 1] & 0xFF;
            int valueStart = index + 2;
            int valueEnd = valueStart + li;

            if (valueEnd > spdu.length) {
                logger.warn("P3 gateway session parameter truncated: pi=0x{} li={}", toHexByte((byte) pi), li);
                return null;
            }

            byte[] value = Arrays.copyOfRange(spdu, valueStart, valueEnd);
            if (pi == 0xC1 || pi == 0xC0 || pi == 0xC2) {
                logger.info(
                    "P3 gateway session found SPDU parameter pi=0x{} offset={} li={} first-bytes={}",
                    toHexByte((byte) pi),
                    index,
                    li,
                    toHexPreview(value, 192)
                );
                return value;
            }

            index = valueEnd;
        }

        return null;
    }

    private byte[] replaceSessionUserData(byte[] spdu, byte[] newValue) {
        if (spdu == null || spdu.length < 4 || newValue == null) {
            return null;
        }

        int start = sessionParameterStart(spdu);
        if (start < 0) {
            return null;
        }

        List<SessionParameter> params = parseSessionParameters(spdu, start);
        if (params.isEmpty()) {
            return null;
        }

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        boolean replaced = false;

        for (SessionParameter param : params) {
            byte[] value = param.value();
            if (param.pi() == 0xC1 || param.pi() == 0xC0 || param.pi() == 0xC2) {
                value = newValue;
                replaced = true;
            }
            writeSessionParameter(body, param.pi(), value);
        }

        if (!replaced) {
            return null;
        }

        byte[] bodyBytes = body.toByteArray();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(mapSessionResponseCode(spdu[0]));
        out.write(0xFF);
        out.write((bodyBytes.length >> 8) & 0xFF);
        out.write(bodyBytes.length & 0xFF);
        out.writeBytes(bodyBytes);

        logger.info(
            "P3 session rebuilt PPDU len={} first-bytes={}",
            out.size(),
            toHexPreview(out.toByteArray(), 192)
        );

        return out.toByteArray();
    }

    private List<SessionParameter> parseSessionParameters(byte[] spdu, int start) {
        List<SessionParameter> params = new ArrayList<>();
        int index = start;

        while (index + 1 < spdu.length) {
            int pi = spdu[index] & 0xFF;
            int li = spdu[index + 1] & 0xFF;
            int valueStart = index + 2;
            int valueEnd = valueStart + li;

            if (valueEnd > spdu.length) {
                throw new IllegalArgumentException(
                    "Invalid session parameter bounds: pi=0x" + toHexByte((byte) pi) + " li=" + li
                );
            }

            params.add(new SessionParameter(pi, Arrays.copyOfRange(spdu, valueStart, valueEnd)));
            index = valueEnd;
        }

        return params;
    }

    private void writeSessionParameter(ByteArrayOutputStream out, int pi, byte[] value) {
        if (value == null) {
            value = new byte[0];
        }
        if (value.length > 255) {
            throw new IllegalArgumentException(
                "Session parameter too large for one-octet LI: pi=0x" + toHexByte((byte) pi) + " len=" + value.length
            );
        }

        out.write(pi & 0xFF);
        out.write(value.length & 0xFF);
        out.writeBytes(value);
    }

    private int sessionParameterStart(byte[] spdu) {
        if (spdu == null || spdu.length < 2) {
            return -1;
        }

        int si = spdu[0] & 0xFF;
        if (si != 0x0D && si != 0x01 && si != 0x0E) {
            return -1;
        }

        int li = spdu[1] & 0xFF;
        if (li == 0xFF) {
            return spdu.length >= 4 ? 4 : -1;
        }
        return 2;
    }

    private byte[] unwrapPresentation(byte[] ppdu) {
        try {
            BerTlv root = BerCodec.decodeSingle(ppdu);

            if (root.tagClass() != TAG_CLASS_UNIVERSAL || !root.constructed() || root.tagNumber() != 17) {
                logger.debug("unwrapPresentation: not a presentation PPDU");
                return null;
            }

            List<BerTlv> children = BerCodec.decodeAll(root.value());

            logger.info(
                "P3 gateway presentation root children count={} first-bytes={}",
                children.size(),
                toHexPreview(ppdu, 192)
            );

            // PASS 1:
            // direct children only, skip tiny control fragments, prefer real ACSE or direct gateway APDU
            for (int i = 0; i < children.size(); i++) {
                BerTlv child = children.get(i);
                byte[] childEncoded = BerCodec.encode(child);

                logger.info(
                    "P3 gateway presentation child[{}] tagClass={} constructed={} tagNumber={} len={} first-bytes={}",
                    i,
                    child.tagClass(),
                    child.constructed(),
                    child.tagNumber(),
                    child.length(),
                    toHexPreview(childEncoded, 128)
                );

                if (isTinyPresentationControl(child)) {
                    logger.info(
                        "P3 gateway presentation child[{}] skipped as tiny control fragment",
                        i
                    );
                    continue;
                }

                if (isRealAcseApdu(childEncoded)) {
                    logger.info(
                        "P3 gateway presentation selected direct ACSE child[{}] len={} first-bytes={}",
                        i,
                        childEncoded.length,
                        toHexPreview(childEncoded, 128)
                    );
                    return childEncoded;
                }

                if (isGatewayApdu(child)) {
                    logger.info(
                        "P3 gateway presentation selected direct gateway child[{}] len={} first-bytes={}",
                        i,
                        childEncoded.length,
                        toHexPreview(childEncoded, 128)
                    );
                    return childEncoded;
                }
            }

            // PASS 2:
            // recurse only if no direct match
            for (int i = 0; i < children.size(); i++) {
                BerTlv child = children.get(i);

                if (isTinyPresentationControl(child)) {
                    continue;
                }

                byte[] found = findPresentationFinalPayload(child);
                if (found != null) {
                    logger.info(
                        "P3 gateway presentation selected recursive child[{}] len={} first-bytes={}",
                        i,
                        found.length,
                        toHexPreview(found, 128)
                    );
                    return found;
                }
            }

            logger.info("P3 gateway presentation unwrap result len=-1 first-bytes=<null>");
            return null;
        } catch (RuntimeException ex) {
            logger.debug("Failed to unwrap presentation PPDU: {}", ex.getMessage());
            return null;
        }
    }

    private byte[] findPresentationFinalPayload(BerTlv node) {
        if (node == null) {
            return null;
        }

        byte[] encoded = BerCodec.encode(node);

        if (isTinyPresentationControl(node)) {
            return null;
        }

        if (isRealAcseApdu(encoded)) {
            return encoded;
        }

        if (isGatewayApdu(node)) {
            return encoded;
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

        // Prefer direct real payloads before deeper recursion
        for (BerTlv child : children) {
            byte[] childEncoded = BerCodec.encode(child);

            if (isTinyPresentationControl(child)) {
                continue;
            }

            if (isRealAcseApdu(childEncoded)) {
                return childEncoded;
            }

            if (isGatewayApdu(child)) {
                return childEncoded;
            }
        }

        for (BerTlv child : children) {
            if (isTinyPresentationControl(child)) {
                continue;
            }

            byte[] found = findPresentationFinalPayload(child);
            if (found != null) {
                return found;
            }
        }

        return null;
    }

    private boolean isTinyPresentationControl(BerTlv tlv) {
        if (tlv == null) {
            return false;
        }

        byte[] encoded = BerCodec.encode(tlv);

        // Explicitly reject the exact fragment seen in your trace:
        // A0 03 80 01 01
        if (encoded.length == 5
            && (encoded[0] & 0xFF) == 0xA0
            && (encoded[1] & 0xFF) == 0x03
            && (encoded[2] & 0xFF) == 0x80
            && (encoded[3] & 0xFF) == 0x01
            && (encoded[4] & 0xFF) == 0x01) {
            return true;
        }

        // Reject very small presentation control nodes
        if (encoded.length <= 8) {
            return true;
        }

        if (tlv.tagClass() == TAG_CLASS_CONTEXT && tlv.constructed()) {
            try {
                List<BerTlv> nested = BerCodec.decodeAll(tlv.value());
                if (nested.size() == 1) {
                    byte[] child = BerCodec.encode(nested.get(0));
                    if (child.length <= 8) {
                        return true;
                    }
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
                return unwrapExternalOrNested(node.value());
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
        if (data == null || data.length == 0) {
            return null;
        }

        try {
            BerTlv tlv = BerCodec.decodeSingle(data);
            byte[] encoded = BerCodec.encode(tlv);

            if (isGatewayApdu(tlv)) {
                return encoded;
            }

            if (looksLikeTopLevelAcse(encoded)) {
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
                        logger.info("P3 ACSE built AARE len={} first-bytes={}", encoded.length, toHexPreview(encoded, 192));
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

    private byte[] wrapPresentationEnvelope(byte[] payload) {
        if (payload == null) {
            payload = new byte[0];
        }

        byte[] userData = BerCodec.encode(
            new BerTlv(TAG_CLASS_CONTEXT, true, 30, 0, payload.length, payload)
        );

        return BerCodec.encode(
            new BerTlv(TAG_CLASS_UNIVERSAL, true, 17, 0, userData.length, userData)
        );
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

    private boolean looksLikeTopLevelAcse(byte[] encoded) {
        if (encoded == null || encoded.length < 10) {
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
            return acseAssociationProtocol.decode(encoded) != null;
        } catch (RuntimeException ex) {
            return false;
        }
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

    private boolean isGatewayApdu(BerTlv tlv) {
        return tlv != null
            && tlv.tagClass() == TAG_CLASS_CONTEXT
            && tlv.constructed()
            && tlv.tagNumber() >= GATEWAY_APDU_MIN_TAG
            && tlv.tagNumber() <= GATEWAY_APDU_MAX_TAG;
    }

    private byte mapSessionResponseCode(byte inboundCode) {
        return (byte) (((inboundCode & 0xFF) == 0x0D) ? 0x0E : inboundCode);
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
        return toHex(Arrays.copyOf(bytes, maxBytes)) + " ...";
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
    private record SessionParameter(int pi, byte[] value) {}

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