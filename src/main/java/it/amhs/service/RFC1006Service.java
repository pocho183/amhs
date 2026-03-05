package it.amhs.service;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.EOFException;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Date;
import java.util.HashSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.io.ByteArrayOutputStream;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import it.amhs.domain.AMHSMessage;
import it.amhs.domain.AMHSPriority;
import it.amhs.domain.AMHSProfile;
import it.amhs.repository.AMHSMessageRepository;

@Service
public class RFC1006Service {

    private static final Logger logger = LoggerFactory.getLogger(RFC1006Service.class);
    private static final byte TPKT_VERSION = 0x03;
    private static final byte TPKT_RESERVED = 0x00;
    private static final byte[] COTP_DATA_HEADER = new byte[] { 0x02, (byte) 0xF0, (byte) 0x80 };
    private static final byte COTP_PDU_CR = (byte) 0xE0;
    private static final byte COTP_PDU_CC = (byte) 0xD0;
    private static final byte COTP_PDU_DR = (byte) 0x80;
    private static final byte COTP_PDU_DC = (byte) 0xC0;
    private static final byte COTP_PDU_ER = 0x70;
    private static final byte COTP_PDU_ED = 0x10;
    private static final byte COTP_PDU_DT = (byte) 0xF0;
    private static final int MAX_TPKT_LENGTH = 65_535;
    private static final int MAX_DT_USER_DATA_PER_FRAME = 16_384;
    private static final int MAX_ACSE_USER_INFORMATION_SIZE = 4_096;
    static final String ICAO_AMHS_P1_OID = "2.6.0.1.6.1";
    static final int RFC1006_CLASS_0 = 0;
    static final int RFC1006_CLASS_0_LEGACY_OPTIONS = 0x0A;

    private final AMHSMessageRepository amhsMessagesRepository;
    private final MTAService mtaService;
    private final P1BerMessageParser p1BerMessageParser;
    private final P1AssociationProtocol p1AssociationProtocol;
    private final AcseAssociationProtocol acseAssociationProtocol;
    private final String localMtaName;
    private final String localRoutingDomain;
    private final ThreadPoolExecutor priorityExecutor;
    private final int idleTimeoutMillis;
    private final boolean requireAcseAuthentication;
    private final String expectedAcseAuthenticationValue;

    public RFC1006Service(
        AMHSMessageRepository amhsMessagesRepository,
        MTAService mtaService,
        P1BerMessageParser p1BerMessageParser,
        P1AssociationProtocol p1AssociationProtocol,
        AcseAssociationProtocol acseAssociationProtocol,
        @Value("${amhs.mta.local-name:LOCAL-MTA}") String localMtaName,
        @Value("${amhs.mta.routing-domain:LOCAL}") String localRoutingDomain,
        @Value("${rfc1006.idle-timeout-ms:300000}") int idleTimeoutMillis,
        @Value("${amhs.acse.require-authentication-value:false}") boolean requireAcseAuthentication,
        @Value("${amhs.acse.expected-authentication-value:}") String expectedAcseAuthenticationValue
    ) {
        this.amhsMessagesRepository = amhsMessagesRepository;
        this.mtaService = mtaService;
        this.p1BerMessageParser = p1BerMessageParser;
        this.p1AssociationProtocol = p1AssociationProtocol;
        this.acseAssociationProtocol = acseAssociationProtocol;
        this.localMtaName = localMtaName;
        this.localRoutingDomain = localRoutingDomain;
        this.idleTimeoutMillis = idleTimeoutMillis;
        this.requireAcseAuthentication = requireAcseAuthentication;
        this.expectedAcseAuthenticationValue = expectedAcseAuthenticationValue == null ? "" : expectedAcseAuthenticationValue;
        this.priorityExecutor = new ThreadPoolExecutor(
            1,
            1,
            0L,
            TimeUnit.MILLISECONDS,
            new PriorityBlockingQueue<>()
        );
    }

    public void handleClient(Socket socket) {
        try (InputStream in = socket.getInputStream(); OutputStream out = socket.getOutputStream()) {
            socket.setSoTimeout(idleTimeoutMillis);
            CertificateIdentity identity = extractCertificateIdentity(socket);
            ByteArrayOutputStream segmentedPayload = new ByteArrayOutputStream();
            P1AssociationState associationState = new P1AssociationState(false, MAX_DT_USER_DATA_PER_FRAME);

            while (true) {
                COTPFrame frame = readFramedPayload(in);
                if (frame == null) {
                    break;
                }

                if (frame.type == COTP_PDU_CR) {
                    CotpConnectionTpdu request = CotpConnectionTpdu.parse(frame.payload);
                    validateClassNegotiation(request.tpduClass());
                    associationState.negotiatedMaxUserData = Math.min(MAX_DT_USER_DATA_PER_FRAME, request.negotiatedMaxUserData());
                    sendConnectionConfirm(out, request);
                    continue;
                }

                if (frame.type == COTP_PDU_DR) {
                    logger.info("Peer requested RFC1006 disconnect");
                    sendDisconnectConfirm(out);
                    break;
                }

                if (frame.type == COTP_PDU_ER) {
                    logger.warn("Received COTP ER TPDU; closing association");
                    associationState.active = false;
                    break;
                }

                if (frame.type == COTP_PDU_ED) {
                    logger.warn("Expedited data TPDU is not supported in this profile");
                    sendErrorTpdu(out, (byte) 0x01);
                    continue;
                }

                if (frame.type != COTP_PDU_DT) {
                    throw new IllegalArgumentException("Unsupported COTP TPDU type: 0x" + Integer.toHexString(frame.type & 0xFF));
                }

                if (frame.payload.length > associationState.negotiatedMaxUserData) {
                    throw new IllegalArgumentException("COTP DT segment exceeds negotiated maximum user data");
                }
                segmentedPayload.write(frame.payload);
                if (!frame.endOfTSDU) {
                    continue;
                }

                byte[] payload = segmentedPayload.toByteArray();
                segmentedPayload.reset();

                String message = new String(payload, StandardCharsets.UTF_8).trim();

                if (isLikelyP1AssociationPdu(payload)) {
                    handleP1AssociationPdu(payload, out, associationState, identity);
                    if (!associationState.active()) {
                        break;
                    }
                    continue;
                }

                if (message.startsWith("RETRIEVE")) {
                    handleRetrieve(message, out);
                    continue;
                }

                if (payload.length > 0 && (payload[0] & 0xFF) == 0x30) {
                    String diagnostic = "Raw BER message without P1 association is rejected; send P1 Bind and Transfer PDUs";
                    logger.warn(diagnostic);
                    sendRFC1006(out, diagnostic + "\n");
                    continue;
                }

                IncomingMessage incoming = parseIncomingMessage(payload, message, identity);
                try {
                    storeWithStrictPriority(incoming);
                    String ack = "Message-ID: " + incoming.messageId + "\n"
                        + "From: " + incoming.from + "\n"
                        + "To: " + incoming.to + "\n"
                        + "Status: RECEIVED\n";
                    sendRFC1006(out, ack);
                } catch (IllegalArgumentException ex) {
                    logger.warn("AMHS message rejected: {}", ex.getMessage());
                    String nack = "Message-ID: " + incoming.messageId + "\n"
                        + "Status: REJECTED\n"
                        + "Error: " + ex.getMessage() + "\n";
                    sendRFC1006(out, nack);
                }
            }
        } catch (SocketTimeoutException timeout) {
            logger.info("RFC1006 idle timeout reached, closing client session after {} ms", idleTimeoutMillis);
        } catch (SocketException | EOFException disconnect) {
            logger.info("RFC1006 peer disconnected: {}", disconnect.getMessage());
        } catch (Exception e) {
            logger.error("RFC1006 handling error", e);
        } finally {
            try {
                socket.close();
            } catch (Exception ignored) {
            }
        }
    }

    private boolean isLikelyP1AssociationPdu(byte[] payload) {
        if (payload.length == 0) {
            return false;
        }
        int first = payload[0] & 0xFF;
        return (first >= 0xA0 && first <= 0xAF) || (first >= 0x60 && first <= 0x64);
    }

    private void handleP1AssociationPdu(
        byte[] payload,
        OutputStream out,
        P1AssociationState associationState,
        CertificateIdentity identity
    ) throws Exception {
        if ((payload[0] & 0xFF) >= 0x60 && (payload[0] & 0xFF) <= 0x64) {
            handleAcseAssociationPdu(payload, out, associationState, identity);
            return;
        }

        P1AssociationProtocol.Pdu pdu;
        try {
            pdu = p1AssociationProtocol.decode(payload);
        } catch (IllegalArgumentException ex) {
            logger.warn("Invalid P1 association PDU: {}", ex.getMessage());
            sendRFC1006(out, p1AssociationProtocol.encodeError("invalid-pdu", ex.getMessage()));
            return;
        }

        if (pdu instanceof P1AssociationProtocol.BindPdu bindPdu) {
            associationState.bound = true;
            associationState.active = true;
            logger.info("Accepted P1 bind for abstract syntax {}", bindPdu.abstractSyntaxOid());
            sendRFC1006(out, p1AssociationProtocol.encodeBindResult(true, "bind-accepted"));
            return;
        }

        if (pdu instanceof P1AssociationProtocol.ReleasePdu) {
            associationState.bound = false;
            associationState.active = false;
            sendRFC1006(out, p1AssociationProtocol.encodeReleaseResult());
            return;
        }

        if (pdu instanceof P1AssociationProtocol.AbortPdu abortPdu) {
            associationState.bound = false;
            associationState.active = false;
            logger.warn("P1 association aborted by peer: {}", abortPdu.diagnostic());
            return;
        }

        if (pdu instanceof P1AssociationProtocol.ErrorPdu errorPdu) {
            logger.warn("Peer reported P1 error {}: {}", errorPdu.code(), errorPdu.diagnostic());
            return;
        }

        if (pdu instanceof P1AssociationProtocol.TransferPdu transferPdu) {
            if (!associationState.bound()) {
                sendRFC1006(out, p1AssociationProtocol.encodeError("association", "P1 transfer received before successful bind"));
                return;
            }

            P1BerMessageParser.ParsedP1Message berMessage = p1BerMessageParser.parse(transferPdu.messagePayload());
            IncomingMessage incoming = new IncomingMessage(
                berMessage.messageId() == null ? UUID.randomUUID().toString() : berMessage.messageId(),
                berMessage.from(),
                berMessage.to(),
                berMessage.body(),
                berMessage.profile(),
                berMessage.priority(),
                berMessage.subject(),
                AMHSChannelService.DEFAULT_CHANNEL_NAME,
                identity.cn(),
                identity.ou(),
                berMessage.filingTime(),
                berMessage.transferEnvelope().mtsIdentifier().flatMap(P1BerMessageParser.MTSIdentifier::localIdentifier).orElse(null),
                berMessage.transferEnvelope().contentTypeOid().orElse(null),
                appendTraceHop(
                    berMessage.transferEnvelope().traceInformation().map(t -> String.join(">", t.hops())).orElse(null),
                    Instant.now(),
                    localMtaName,
                    localRoutingDomain
                ),
                berMessage.transferEnvelope().perRecipientFields().isEmpty()
                    ? null
                    : berMessage.transferEnvelope().perRecipientFields().stream()
                        .map(p -> p.recipient() + p.responsibility().map(r -> "(" + r + ")").orElse(""))
                        .collect(java.util.stream.Collectors.joining(",")),
                System.nanoTime()
            );

            storeWithStrictPriority(incoming);
            sendRFC1006(out, p1AssociationProtocol.encodeTransferResult(
                true,
                incoming.mtsIdentifier != null ? incoming.mtsIdentifier : incoming.messageId,
                List.of(new P1AssociationProtocol.RecipientTransferResult(incoming.to, 0, java.util.Optional.of("delivered")))
            ));
        }
    }

    private void handleAcseAssociationPdu(byte[] payload, OutputStream out, P1AssociationState associationState, CertificateIdentity identity) throws Exception {
        AcseModels.AcseApdu apdu;
        try {
            apdu = acseAssociationProtocol.decode(payload);
        } catch (IllegalArgumentException ex) {
            logger.warn("Invalid ACSE association APDU: {}", ex.getMessage());
            sendRFC1006(out, p1AssociationProtocol.encodeError("invalid-acse-pdu", ex.getMessage()));
            return;
        }

        if (apdu instanceof AcseModels.AARQApdu aarq) {
            validateAarqForAmhsP1(aarq, identity.cn(), identity.ou());
            associationState.bound = true;
            associationState.active = true;
            logger.info("Accepted ACSE AARQ for application context {}", aarq.applicationContextName());
            sendRFC1006(out, acseAssociationProtocol.encode(new AcseModels.AAREApdu(true, java.util.Optional.of("accepted"))));
            return;
        }

        if (apdu instanceof AcseModels.RLRQApdu) {
            associationState.bound = false;
            associationState.active = false;
            sendRFC1006(out, acseAssociationProtocol.encode(new AcseModels.RLREApdu(true)));
            return;
        }

        if (apdu instanceof AcseModels.ABRTApdu abrt) {
            associationState.bound = false;
            associationState.active = false;
            logger.warn("ACSE association aborted by peer: {}", abrt.diagnostic().orElse(""));
            return;
        }

        logger.info("Received ACSE {} while waiting for P1 transfer PDUs", apdu.getClass().getSimpleName());
    }

    void validateClassNegotiation(int tpduClass) {
        if (tpduClass == RFC1006_CLASS_0_LEGACY_OPTIONS) {
            logger.debug("Accepting legacy COTP class/options value 0x0A for class 0 interoperability");
            return;
        }
        if (tpduClass != RFC1006_CLASS_0) {
            throw new IllegalArgumentException("Unsupported COTP class negotiation " + tpduClass + "; only class 0 is supported");
        }
    }

    void validateAarqForAmhsP1(AcseModels.AARQApdu aarq, String certificateCn, String certificateOu) {
        if (!ICAO_AMHS_P1_OID.equals(aarq.applicationContextName())) {
            throw new IllegalArgumentException("Unsupported ACSE application-context OID " + aarq.applicationContextName());
        }

        validateAarqPresentationContexts(aarq);
        validateAarqEntityTitles(aarq);
        validateAarqAuthentication(aarq);
        validateAarqUserInformation(aarq);

        if (StringUtils.hasText(certificateCn) || StringUtils.hasText(certificateOu)) {
            String callingAe = aarq.callingAeTitle().map(this::normalized).orElse("");
            if (!StringUtils.hasText(callingAe)) {
                throw new IllegalArgumentException("ACSE calling AE-title is mandatory when peer certificate identity is present");
            }
            String certCn = normalized(certificateCn);
            String certOu = normalized(certificateOu);
            if (!callingAe.equals(certCn) && !callingAe.equals(certOu)) {
                throw new IllegalArgumentException("ACSE calling AE-title is not bound to peer certificate identity");
            }
        }

        if (StringUtils.hasText(expectedAcseAuthenticationValue)) {
            String suppliedAuth = aarq.authenticationValue().map(v -> new String(v, StandardCharsets.UTF_8)).orElse("");
            if (!expectedAcseAuthenticationValue.equals(suppliedAuth)) {
                throw new IllegalArgumentException("ACSE authentication-value verification failed");
            }
        }
    }

    private void validateAarqPresentationContexts(AcseModels.AARQApdu aarq) {
        if (aarq.presentationContextOids().isEmpty()) {
            throw new IllegalArgumentException("ACSE presentation-layer negotiation is missing presentation contexts");
        }
        if (!aarq.presentationContextOids().contains(ICAO_AMHS_P1_OID)) {
            throw new IllegalArgumentException("ACSE presentation contexts do not negotiate AMHS P1 abstract syntax");
        }
        Set<String> seen = new HashSet<>();
        for (String oid : aarq.presentationContextOids()) {
            if (!StringUtils.hasText(oid)) {
                throw new IllegalArgumentException("ACSE presentation context OID must not be empty");
            }
            if (!seen.add(oid)) {
                throw new IllegalArgumentException("ACSE presentation contexts must not contain duplicates");
            }
        }
    }

    private void validateAarqEntityTitles(AcseModels.AARQApdu aarq) {
        validateAeTitlePair("calling", aarq.callingApTitle().isPresent(), aarq.callingAeTitle().isPresent(), aarq.callingAeQualifier().isPresent());
        validateAeTitlePair("called", aarq.calledApTitle().isPresent(), aarq.calledAeTitle().isPresent(), aarq.calledAeQualifier().isPresent());
    }

    private void validateAeTitlePair(String side, boolean hasApTitle, boolean hasAeTitle, boolean hasAeQualifier) {
        if (hasApTitle && !hasAeTitle && !hasAeQualifier) {
            throw new IllegalArgumentException("ACSE " + side + " AP-title requires AE-title or AE-qualifier");
        }
        if ((hasAeTitle || hasAeQualifier) && !hasApTitle) {
            throw new IllegalArgumentException("ACSE " + side + " AE-title/AE-qualifier requires AP-title");
        }
    }

    private void validateAarqAuthentication(AcseModels.AARQApdu aarq) {
        if (requireAcseAuthentication && aarq.authenticationValue().isEmpty()) {
            throw new IllegalArgumentException("ACSE authentication-value is mandatory");
        }
        if (aarq.authenticationValue().isPresent() && aarq.authenticationValue().get().length == 0) {
            throw new IllegalArgumentException("ACSE authentication-value cannot be empty when provided");
        }
    }

    private void validateAarqUserInformation(AcseModels.AARQApdu aarq) {
        if (aarq.userInformation().isEmpty()) {
            throw new IllegalArgumentException("ACSE user-information is mandatory for AMHS association information");
        }
        int size = aarq.userInformation().get().length;
        if (size == 0) {
            throw new IllegalArgumentException("ACSE user-information must carry association information");
        }
        if (size > MAX_ACSE_USER_INFORMATION_SIZE) {
            throw new IllegalArgumentException("ACSE user-information exceeds profile maximum size");
        }
    }

    private String normalized(String value) {
        return value == null ? "" : value.trim().toUpperCase();
    }

    private void storeWithStrictPriority(IncomingMessage incoming) {
        PriorityFutureTask task = new PriorityFutureTask(incoming, () -> mtaService.storeX400Message(
            incoming.from,
            incoming.to,
            incoming.body,
            incoming.messageId,
            incoming.profile,
            incoming.priority,
            incoming.subject,
            incoming.channel,
            incoming.certificateCn,
            incoming.certificateOu,
            incoming.filingTime,
            incoming.from,
            incoming.to,
            null,
            null,
            null,
            null,
            incoming.mtsIdentifier,
            incoming.contentTypeOid,
            incoming.traceInformation,
            incoming.perRecipientFields
        ));
        priorityExecutor.execute(task);
        try {
            task.get();
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("AMHS message interrupted while waiting for priority queue", ex);
        } catch (ExecutionException ex) {
            Throwable cause = ex.getCause();
            if (cause instanceof IllegalArgumentException iae) {
                throw iae;
            }
            throw new IllegalStateException("Failed to process AMHS message", cause);
        }
    }

    private IncomingMessage parseIncomingMessage(byte[] rawPayload, String message, CertificateIdentity identity) {
        if (rawPayload.length > 0 && (rawPayload[0] & 0xFF) == 0x30) {
            P1BerMessageParser.ParsedP1Message berMessage = p1BerMessageParser.parse(rawPayload);
            return new IncomingMessage(
                berMessage.messageId() == null ? UUID.randomUUID().toString() : berMessage.messageId(),
                requireNonBlank(berMessage.from(), "from"),
                requireNonBlank(berMessage.to(), "to"),
                requireNonBlank(berMessage.body(), "body"),
                berMessage.profile(),
                berMessage.priority(),
                berMessage.subject(),
                AMHSChannelService.DEFAULT_CHANNEL_NAME,
                identity.cn(),
                identity.ou(),
                berMessage.filingTime(),
                berMessage.transferEnvelope().mtsIdentifier().flatMap(P1BerMessageParser.MTSIdentifier::localIdentifier).orElse(null),
                berMessage.transferEnvelope().contentTypeOid().orElse(null),
                appendTraceHop(
                    berMessage.transferEnvelope().traceInformation().map(t -> String.join(">", t.hops())).orElse(null),
                    Instant.now(),
                    localMtaName,
                    localRoutingDomain
                ),
                berMessage.transferEnvelope().perRecipientFields().isEmpty()
                    ? null
                    : berMessage.transferEnvelope().perRecipientFields().stream()
                        .map(p -> p.recipient() + p.responsibility().map(r -> "(" + r + ")").orElse(""))
                        .collect(java.util.stream.Collectors.joining(",")),
                System.nanoTime()
            );
        }

        Map<String, String> headers = new HashMap<>();
        String body = "";

        String[] parts = message.split(",|\\n");
        for (String part : parts) {
            if (!part.contains(":")) {
                continue;
            }
            String[] kv = part.split(":", 2);
            String key = kv[0].trim();
            String value = kv[1].trim();

            if (key.equalsIgnoreCase("Body")) {
                body = value;
            } else {
                headers.put(key, value);
            }
        }

        String messageId = headers.getOrDefault("Message-ID", UUID.randomUUID().toString());
        String from = requiredHeader(headers, "From");
        String to = requiredHeader(headers, "To");
        AMHSProfile profile = parseProfile(headers.getOrDefault("Profile", "P3"));
        AMHSPriority priority = parsePriority(headers.getOrDefault("Priority", "GG"));
        String subject = headers.getOrDefault("Subject", "");
        String channel = headers.getOrDefault("Channel", AMHSChannelService.DEFAULT_CHANNEL_NAME);
        Date filingTime = parseFilingTime(headers.get("Filing-Time"));

        return new IncomingMessage(
            messageId,
            from,
            to,
            requireNonBlank(body, "body"),
            profile,
            priority,
            subject,
            channel,
            identity.cn(),
            identity.ou(),
            filingTime,
            null,
            null,
            null,
            null,
            System.nanoTime()
        );
    }

    private String requiredHeader(Map<String, String> headers, String key) {
        return requireNonBlank(headers.get(key), key.toLowerCase());
    }

    private String requireNonBlank(String value, String fieldName) {
        if (!StringUtils.hasText(value)) {
            throw new IllegalArgumentException("Missing or blank AMHS field '" + fieldName + "'");
        }
        return value.trim();
    }

    static String appendTraceHop(String existingTrace, Instant arrivalInstant, String localMtaName, String routingDomain) {
        String arrival = arrivalInstant == null ? Instant.now().toString() : arrivalInstant.toString();
        String mta = StringUtils.hasText(localMtaName) ? localMtaName.trim() : "LOCAL-MTA";
        String domain = StringUtils.hasText(routingDomain) ? routingDomain.trim() : "LOCAL";
        String hop = mta + "@" + domain + "[" + arrival + "]";
        if (!StringUtils.hasText(existingTrace)) {
            return hop;
        }
        return existingTrace.trim() + ">" + hop;
    }

    private void handleRetrieve(String command, OutputStream out) throws Exception {
        String response;
        if (command.equalsIgnoreCase("RETRIEVE ALL")) {
            List<AMHSMessage> allMsgs = amhsMessagesRepository.findAll();
            if (allMsgs.isEmpty()) {
                response = "No messages.\n";
            } else {
                response = allMsgs.stream().map(m -> String.format(
                    "ID: %s | From: %s | Channel: %s | Priority: %s | State: %s | Filing-Time: %s | Body: %s",
                    m.getMessageId(),
                    m.getSender(),
                    m.getChannelName(),
                    m.getPriority(),
                    m.getLifecycleState(),
                    m.getFilingTime(),
                    m.getBody()
                )).collect(java.util.stream.Collectors.joining("\n---\n")) + "\n";
            }
        } else if (command.toUpperCase().startsWith("RETRIEVE ")) {
            String messageId = command.substring("RETRIEVE ".length()).trim();
            response = amhsMessagesRepository.findByMessageId(messageId)
                .map(m -> String.format(
                    "From: %s\nTo: %s\nChannel: %s\nProfile: %s\nPriority: %s\nState: %s\nFiling-Time: %s\nBody: %s\n",
                    m.getSender(),
                    m.getRecipient(),
                    m.getChannelName(),
                    m.getProfile(),
                    m.getPriority(),
                    m.getLifecycleState(),
                    m.getFilingTime(),
                    m.getBody()
                ))
                .orElse("Message-ID " + messageId + " not found.\n");
        } else {
            response = "Unknown command.\n";
        }
        sendRFC1006(out, response);
    }

    private AMHSProfile parseProfile(String value) {
        try {
            return AMHSProfile.valueOf(value.trim().toUpperCase());
        } catch (Exception ex) {
            logger.warn("Unsupported profile '{}', defaulting to P3", value);
            return AMHSProfile.P3;
        }
    }

    private AMHSPriority parsePriority(String value) {
        try {
            return AMHSPriority.valueOf(value.trim().toUpperCase());
        } catch (Exception ex) {
            logger.warn("Unsupported priority '{}', defaulting to GG", value);
            return AMHSPriority.GG;
        }
    }

    private Date parseFilingTime(String filingTimeHeader) {
        if (filingTimeHeader == null || filingTimeHeader.isBlank()) {
            return Date.from(Instant.now());
        }

        try {
            return Date.from(Instant.parse(filingTimeHeader.trim()));
        } catch (Exception ignored) {
        }

        try {
            SimpleDateFormat format = new SimpleDateFormat("yyyyMMddHHmmss");
            format.setTimeZone(TimeZone.getTimeZone("UTC"));
            return format.parse(filingTimeHeader.trim());
        } catch (ParseException ex) {
            logger.warn("Invalid Filing-Time '{}', defaulting to now", filingTimeHeader);
            return Date.from(Instant.now());
        }
    }

    private CertificateIdentity extractCertificateIdentity(Socket socket) {
        if (!(socket instanceof SSLSocket sslSocket)) {
            return new CertificateIdentity(null, null);
        }
        try {
            Principal principal = sslSocket.getSession().getPeerPrincipal();
            return parseDn(principal.getName());
        } catch (SSLPeerUnverifiedException ex) {
            logger.info("Client certificate not provided");
            return new CertificateIdentity(null, null);
        } catch (Exception ex) {
            logger.warn("Failed to parse client certificate identity", ex);
            return new CertificateIdentity(null, null);
        }
    }

    private CertificateIdentity parseDn(String dn) throws Exception {
        String cn = null;
        String ou = null;
        LdapName ldapName = new LdapName(dn);
        for (Rdn rdn : ldapName.getRdns()) {
            if ("CN".equalsIgnoreCase(rdn.getType())) {
                cn = String.valueOf(rdn.getValue());
            }
            if ("OU".equalsIgnoreCase(rdn.getType())) {
                ou = String.valueOf(rdn.getValue());
            }
        }
        return new CertificateIdentity(cn, ou);
    }

    private COTPFrame readFramedPayload(InputStream in) throws Exception {
        int first = in.read();
        if (first == -1) {
            return null;
        }

        int second = in.read();
        if (second == -1) {
            throw new EOFException("Connection closed while reading frame header");
        }

        if (first == TPKT_VERSION && second == TPKT_RESERVED) {
            int lenHi = in.read();
            int lenLo = in.read();
            if (lenHi == -1 || lenLo == -1) {
                throw new EOFException("Connection closed while reading TPKT length");
            }
            int tpktLength = ((lenHi & 0xFF) << 8) | (lenLo & 0xFF);
            if (tpktLength < 7 || tpktLength > MAX_TPKT_LENGTH) {
                throw new IllegalArgumentException("Invalid TPKT frame length: " + tpktLength);
            }

            byte[] cotpTpdu = readFully(in, tpktLength - 4);
            if (cotpTpdu.length < 2) {
                throw new IllegalArgumentException("COTP TPDU is too short");
            }
            int lengthIndicator = cotpTpdu[0] & 0xFF;
            if (lengthIndicator + 1 > cotpTpdu.length) {
                throw new IllegalArgumentException("Invalid COTP length indicator: " + lengthIndicator);
            }
            byte type = (byte) (cotpTpdu[1] & (byte) 0xF0);

            if (type == COTP_PDU_CR || type == COTP_PDU_CC || type == COTP_PDU_DR || type == COTP_PDU_DC || type == COTP_PDU_ER) {
                return new COTPFrame(type, true, cotpTpdu);
            }

            if (type == COTP_PDU_ED) {
                if (lengthIndicator < 2) {
                    throw new IllegalArgumentException("Invalid COTP ED header length indicator: " + lengthIndicator);
                }
                boolean eot = (cotpTpdu[2] & (byte) 0x80) != 0;
                int dataOffset = lengthIndicator + 1;
                byte[] userData = new byte[cotpTpdu.length - dataOffset];
                System.arraycopy(cotpTpdu, dataOffset, userData, 0, userData.length);
                return new COTPFrame(type, eot, userData);
            }

            if (type == COTP_PDU_DT) {
                if (lengthIndicator < 2) {
                    throw new IllegalArgumentException("Invalid COTP DT header length indicator: " + lengthIndicator);
                }
                if (cotpTpdu[1] != COTP_DATA_HEADER[1]) {
                    throw new IllegalArgumentException("Unsupported COTP DT TPDU code: " + String.format("0x%02X", cotpTpdu[1]));
                }
                boolean eot = (cotpTpdu[2] & (byte) 0x80) != 0;
                int dataOffset = lengthIndicator + 1;
                byte[] userData = new byte[cotpTpdu.length - dataOffset];
                System.arraycopy(cotpTpdu, dataOffset, userData, 0, userData.length);
                return new COTPFrame(type, eot, userData);
            }

            throw new IllegalArgumentException("Unsupported COTP TPDU type: " + String.format("0x%02X", cotpTpdu[1]));
        }

        int legacyLength = ((first & 0xFF) << 8) | (second & 0xFF);
        return new COTPFrame(COTP_PDU_DT, true, readFully(in, legacyLength));
    }

    private byte[] readFully(InputStream in, int length) throws Exception {
        byte[] data = new byte[length];
        int offset = 0;
        while (offset < length) {
            int read = in.read(data, offset, length - offset);
            if (read == -1) {
                throw new EOFException("Connection closed while reading payload");
            }
            offset += read;
        }
        return data;
    }

    private void sendRFC1006(OutputStream out, String message) throws Exception {
        byte[] msgBytes = message.getBytes(StandardCharsets.UTF_8);
        sendRFC1006(out, msgBytes);
    }

    private void sendRFC1006(OutputStream out, byte[] msgBytes) throws Exception {
        int offset = 0;

        while (offset < msgBytes.length || msgBytes.length == 0) {
            int chunkLen = Math.min(MAX_DT_USER_DATA_PER_FRAME, msgBytes.length - offset);
            boolean eot = offset + chunkLen >= msgBytes.length;
            sendDtFrame(out, msgBytes, offset, chunkLen, eot);
            offset += chunkLen;
            if (msgBytes.length == 0) {
                break;
            }
        }
        out.flush();
    }

    private void sendConnectionConfirm(OutputStream out, CotpConnectionTpdu requestTpdu) throws Exception {
        CotpConnectionTpdu confirm = new CotpConnectionTpdu(
            CotpConnectionTpdu.PDU_CC,
            requestTpdu.sourceReference(),
            requestTpdu.destinationReference(),
            requestTpdu.tpduClass(),
            requestTpdu.tpduSize(),
            requestTpdu.unknownParameters()
        );
        sendTpktFrame(out, confirm.serialize());
        out.flush();
    }

    private void sendDisconnectConfirm(OutputStream out) throws Exception {
        byte[] tpdu = new byte[] {0x06, COTP_PDU_DC, 0x00, 0x00, 0x00, 0x00, 0x00};
        sendTpktFrame(out, tpdu);
        out.flush();
    }

    private void sendErrorTpdu(OutputStream out, byte rejectCause) throws Exception {
        byte[] tpdu = new byte[] {0x02, COTP_PDU_ER, rejectCause};
        sendTpktFrame(out, tpdu);
        out.flush();
    }

    private void sendDtFrame(OutputStream out, byte[] bytes, int offset, int chunkLength, boolean eot) throws Exception {
        byte[] dtTpdu = new byte[3 + chunkLength];
        dtTpdu[0] = COTP_DATA_HEADER[0];
        dtTpdu[1] = COTP_DATA_HEADER[1];
        dtTpdu[2] = eot ? (byte) 0x80 : 0x00;
        if (chunkLength > 0) {
            System.arraycopy(bytes, offset, dtTpdu, 3, chunkLength);
        }
        sendTpktFrame(out, dtTpdu);
    }

    private void sendTpktFrame(OutputStream out, byte[] cotpTpdu) throws Exception {
        int tpktLength = 4 + cotpTpdu.length;
        if (tpktLength > MAX_TPKT_LENGTH) {
            throw new IllegalArgumentException("TPKT frame exceeds maximum allowed length: " + tpktLength);
        }
        ByteBuffer bb = ByteBuffer.allocate(tpktLength);
        bb.put(TPKT_VERSION);
        bb.put(TPKT_RESERVED);
        bb.putShort((short) tpktLength);
        bb.put(cotpTpdu);
        out.write(bb.array());
    }

    private record CertificateIdentity(String cn, String ou) {
    }

    private static final class P1AssociationState {
        private boolean bound;
        private boolean active;
        private int negotiatedMaxUserData;

        private P1AssociationState(boolean bound, int negotiatedMaxUserData) {
            this.bound = bound;
            this.active = true;
            this.negotiatedMaxUserData = negotiatedMaxUserData;
        }

        private boolean bound() {
            return bound;
        }

        private boolean active() {
            return active;
        }
    }

    private record COTPFrame(byte type, boolean endOfTSDU, byte[] payload) {
    }

    private record IncomingMessage(
        String messageId,
        String from,
        String to,
        String body,
        AMHSProfile profile,
        AMHSPriority priority,
        String subject,
        String channel,
        String certificateCn,
        String certificateOu,
        Date filingTime,
        String mtsIdentifier,
        String contentTypeOid,
        String traceInformation,
        String perRecipientFields,
        long sequence
    ) {
    }

    private static final class PriorityFutureTask extends FutureTask<AMHSMessage> implements Comparable<PriorityFutureTask> {

        private final IncomingMessage incoming;

        private PriorityFutureTask(IncomingMessage incoming, java.util.concurrent.Callable<AMHSMessage> callable) {
            super(callable);
            this.incoming = incoming;
        }

        @Override
        public int compareTo(PriorityFutureTask other) {
            int byPriority = Integer.compare(priorityWeight(this.incoming.priority), priorityWeight(other.incoming.priority));
            if (byPriority != 0) {
                return byPriority;
            }
            int byFilingTime = this.incoming.filingTime.compareTo(other.incoming.filingTime);
            if (byFilingTime != 0) {
                return byFilingTime;
            }
            return Long.compare(this.incoming.sequence, other.incoming.sequence);
        }

        private static int priorityWeight(AMHSPriority priority) {
            return switch (priority) {
                case SS -> 0;
                case DD -> 1;
                case FF -> 2;
                case GG -> 3;
                case KK -> 4;
            };
        }
    }
}
