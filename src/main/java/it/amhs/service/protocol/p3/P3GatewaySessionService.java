package it.amhs.service.protocol.p3;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import it.amhs.api.X400MessageRequest;
import it.amhs.compliance.AMHSComplianceValidator;
import it.amhs.domain.AMHSChannel;
import it.amhs.domain.AMHSDeliveryReport;
import it.amhs.domain.AMHSMessage;
import it.amhs.domain.AMHSMessageState;
import it.amhs.repository.AMHSDeliveryReportRepository;
import it.amhs.repository.AMHSMessageRepository;
import it.amhs.service.address.ORAddress;
import it.amhs.service.channel.AMHSChannelService;
import it.amhs.service.message.X400MessageService;
import it.amhs.service.relay.RelayRoutingService;
import it.amhs.service.relay.RelayRoutingService.AMHSMessageEnvelope;

@Service
public class P3GatewaySessionService {

    private static final Logger logger = LoggerFactory.getLogger(P3GatewaySessionService.class);

    private final X400MessageService x400MessageService;
    private final AMHSComplianceValidator complianceValidator;
    private final AMHSChannelService channelService;
    private final RelayRoutingService relayRoutingService;
    private final AMHSMessageRepository messageRepository;
    private final AMHSDeliveryReportRepository deliveryReportRepository;
    private final long defaultStatusWaitTimeoutMs;
    private final long defaultStatusRetryIntervalMs;
    private final boolean authRequired;
    private final String expectedUsername;
    private final String expectedPassword;
    private final String defaultProtocolIndex;
    private final String defaultProtocolAddress;
    private final String defaultServerAddress;
    private final ConcurrentMap<String, Long> submissionCorrelationTable = new ConcurrentHashMap<>();

    public P3GatewaySessionService(
        X400MessageService x400MessageService,
        AMHSComplianceValidator complianceValidator,
        AMHSChannelService channelService,
        RelayRoutingService relayRoutingService,
        AMHSMessageRepository messageRepository,
        AMHSDeliveryReportRepository deliveryReportRepository,
        @Value("${amhs.p3.gateway.status.wait-timeout-ms:10000}") long defaultStatusWaitTimeoutMs,
        @Value("${amhs.p3.gateway.status.retry-interval-ms:1000}") long defaultStatusRetryIntervalMs,
        @Value("${amhs.p3.gateway.auth.required:true}") boolean authRequired,
        @Value("${amhs.p3.gateway.auth.username:}") String expectedUsername,
        @Value("${amhs.p3.gateway.auth.password:}") String expectedPassword,
        @Value("${amhs.p3.gateway.protocol-index:RFC1006}") String defaultProtocolIndex,
        @Value("${amhs.p3.gateway.protocol-address:127.0.0.1:102}") String defaultProtocolAddress,
        @Value("${amhs.p3.gateway.server-address:AMHS-P3-GATEWAY}") String defaultServerAddress
    ) {
        this.x400MessageService = x400MessageService;
        this.complianceValidator = complianceValidator;
        this.channelService = channelService;
        this.relayRoutingService = relayRoutingService;
        this.messageRepository = messageRepository;
        this.deliveryReportRepository = deliveryReportRepository;
        this.defaultStatusWaitTimeoutMs = Math.max(0L, defaultStatusWaitTimeoutMs);
        this.defaultStatusRetryIntervalMs = Math.max(1L, defaultStatusRetryIntervalMs);
        this.authRequired = authRequired;
        this.expectedUsername = expectedUsername;
        this.expectedPassword = expectedPassword;
        this.defaultProtocolIndex = defaultProtocolIndex;
        this.defaultProtocolAddress = defaultProtocolAddress;
        this.defaultServerAddress = defaultServerAddress;
    }

    public SessionState newSession() {
        return new SessionState();
    }

    public String handleCommand(SessionState state, String rawCommand) {
        String trimmed = rawCommand == null ? "" : rawCommand.trim();
        if (!StringUtils.hasText(trimmed)) {
            return "ERR code=invalid-command detail=Empty command";
        }

        String[] segments = trimmed.split("\\s+", 2);
        String operation = segments[0].toUpperCase();
        Map<String, String> attributes = segments.length > 1 ? parseAttributes(segments[1]) : Map.of();

        return switch (operation) {
            case "BIND" -> bind(state, attributes);
            case "SUBMIT" -> submit(state, attributes);
            case "RETRIEVE", "REPORT", "STATUS" -> retrieveStatus(state, attributes);
            case "READ" -> readMailbox(state, attributes);
            case "UNBIND", "RELEASE", "QUIT" -> unbind(state);
            default -> "ERR code=unsupported-operation detail=Unsupported operation " + operation;
        };
    }

    private String bind(SessionState state, Map<String, String> attributes) {
        String username = attributes.getOrDefault("username", "");
        String password = attributes.getOrDefault("password", "");
        String senderAddress = attributes.getOrDefault("sender", "");
        String channelName = attributes.getOrDefault("channel", AMHSChannelService.DEFAULT_CHANNEL_NAME);

        if (!StringUtils.hasText(senderAddress)) {
            logger.warn("P3 bind rejected: missing sender address");
            return "ERR code=invalid-or-address detail=Missing sender address";
        }

        ORAddress parsedSender;
        try {
            parsedSender = ORAddress.parse(senderAddress);
            complianceValidator.validateIcaoOrAddress(parsedSender.toCanonicalString(), "sender");
        } catch (IllegalArgumentException ex) {
            logger.warn("P3 bind rejected: invalid sender address reason={}", ex.getMessage());
            return "ERR code=invalid-or-address detail=" + ex.getMessage();
        }

        if (authRequired) {
            if (!StringUtils.hasText(username) || !StringUtils.hasText(password)) {
                logger.warn("P3 bind rejected: missing credentials for sender={}", parsedSender.toCanonicalString());
                return "ERR code=auth-failed detail=Missing credentials";
            }
            if (!expectedUsername.equals(username) || !expectedPassword.equals(password)) {
                logger.warn("P3 bind rejected: invalid credentials username={}", username);
                return "ERR code=auth-failed detail=Invalid credentials";
            }
        }

        try {
            complianceValidator.validateAuthenticatedIdentityBinding(parsedSender.toCanonicalString(), username);
        } catch (IllegalArgumentException ex) {
            logger.warn("P3 bind rejected: identity binding failed username={} reason={}", username, ex.getMessage());
            return "ERR code=authz-failed detail=" + ex.getMessage();
        }

        AMHSChannel channel;
        try {
            channel = channelService.requireEnabledChannel(channelName);
        } catch (IllegalArgumentException ex) {
            logger.warn("P3 bind rejected: channel policy failure channel={} reason={}", channelName, ex.getMessage());
            return "ERR code=channel-policy detail=" + ex.getMessage();
        }

        state.bound = true;
        state.username = username;
        state.senderOrAddress = parsedSender.toCanonicalString();
        state.channelName = channel.getName();
        state.lastReadReportId = null;
        logger.info("P3 bind accepted sender={} username={} channel={}", state.senderOrAddress, state.username, state.channelName);
        return "OK code=bind-accepted sender=" + state.senderOrAddress;
    }

    private String submit(SessionState state, Map<String, String> attributes) {
        if (!state.bound) {
            logger.warn("P3 submit rejected: submit before bind");
            return "ERR code=association detail=Submit received before bind";
        }

        String recipientAddress = attributes.getOrDefault("recipient", "");
        String body = attributes.getOrDefault("body", "");
        String subject = attributes.getOrDefault("subject", null);

        if (!StringUtils.hasText(recipientAddress)) {
            logger.warn("P3 submit rejected: missing recipient sender={} channel={}", state.senderOrAddress, state.channelName);
            return "ERR code=invalid-or-address detail=Missing recipient address";
        }
        if (!StringUtils.hasText(body)) {
            logger.warn("P3 submit rejected: empty body sender={} channel={}", state.senderOrAddress, state.channelName);
            return "ERR code=invalid-message detail=Body cannot be empty";
        }

        ORAddress sender = ORAddress.parse(state.senderOrAddress);
        ORAddress recipient;
        try {
            recipient = ORAddress.parse(recipientAddress);
            complianceValidator.validateIcaoOrAddress(recipient.toCanonicalString(), "recipient");
        } catch (IllegalArgumentException ex) {
            logger.warn("P3 submit rejected: invalid recipient reason={}", ex.getMessage());
            return "ERR code=invalid-or-address detail=" + ex.getMessage();
        }

        if (relayRoutingService.hasRoutesConfigured()
            && relayRoutingService.findNextHop(new AMHSMessageEnvelope(recipient, ""), 0).isEmpty()) {
            logger.warn("P3 submit rejected: no route for recipient={} channel={}", recipient.toCanonicalString(), state.channelName);
            return "ERR code=routing-policy detail=No route found for recipient";
        }

        String submissionId = deterministicSubmissionId(state.senderOrAddress, recipient.toCanonicalString(), body, subject == null ? "" : subject);

        X400MessageRequest request = new X400MessageRequest(
            submissionId,
            body,
            subject,
            null,
            null,
            null,
            null,
            defaultProtocolIndex,
            defaultProtocolAddress,
            defaultServerAddress,
            sender.get("CN"),
            sender.get("OU1"),
            sender.get("OU2"),
            sender.get("OU3"),
            sender.get("OU4"),
            sender.get("O"),
            sender.get("PRMD"),
            sender.get("ADMD"),
            sender.get("C"),
            recipient.get("CN"),
            recipient.get("OU1"),
            recipient.get("OU2"),
            recipient.get("OU3"),
            recipient.get("OU4"),
            recipient.get("O"),
            recipient.get("PRMD"),
            recipient.get("ADMD"),
            recipient.get("C"),
            state.channelName,
            state.username,
            null
        );

        AMHSMessage storedMessage = x400MessageService.storeFromP3(request);
        submissionCorrelationTable.put(submissionId, storedMessage.getId());
        logger.info(
            "P3 submit accepted sender={} recipient={} channel={} submissionId={} messageId={}",
            state.senderOrAddress,
            recipient.toCanonicalString(),
            state.channelName,
            submissionId,
            storedMessage.getId()
        );
        return "OK code=submitted submission-id=" + submissionId + " message-id=" + storedMessage.getId();
    }

    private String retrieveStatus(SessionState state, Map<String, String> attributes) {
        if (!state.bound) {
            logger.warn("P3 status rejected: operation before bind");
            return "ERR code=association detail=Status operation received before bind";
        }

        String submissionId = attributes.getOrDefault("submission-id", "").trim();
        if (!StringUtils.hasText(submissionId)) {
            logger.warn("P3 status rejected: missing submission-id");
            return "ERR code=invalid-command detail=Missing submission-id";
        }

        long waitTimeoutMs = parseLong(attributes.get("wait-timeout-ms"), defaultStatusWaitTimeoutMs);
        long retryIntervalMs = Math.max(1L, parseLong(attributes.get("retry-interval-ms"), defaultStatusRetryIntervalMs));
        Instant deadline = Instant.now().plusMillis(Math.max(0L, waitTimeoutMs));

        StatusSnapshot snapshot = loadStatus(submissionId);
        while (snapshot != null && snapshot.drStatus.equals("PENDING") && waitTimeoutMs > 0 && Instant.now().isBefore(deadline)) {
            long remainingMs = Math.max(1L, Duration.between(Instant.now(), deadline).toMillis());
            try {
                Thread.sleep(Math.min(retryIntervalMs, remainingMs));
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                return "ERR code=interrupted detail=Status wait interrupted";
            }
            snapshot = loadStatus(submissionId);
        }

        if (snapshot == null) {
            return "ERR code=unknown-submission detail=Unknown submission-id";
        }

        StringBuilder response = new StringBuilder("OK code=status")
            .append(" submission-id=").append(submissionId)
            .append(" message-id=").append(snapshot.message.getId())
            .append(" state=").append(snapshot.message.getLifecycleState())
            .append(" dr-status=").append(snapshot.drStatus)
            .append(" ipn-status=").append(snapshot.ipnStatus);

        if (snapshot.message.getNextRetryAt() != null) {
            response.append(" next-retry-at=").append(snapshot.message.getNextRetryAt().toInstant());
        }
        if (snapshot.message.getDrExpirationAt() != null) {
            response.append(" timeout-at=").append(snapshot.message.getDrExpirationAt().toInstant());
        }
        if (snapshot.latestReport != null && StringUtils.hasText(snapshot.latestReport.getX411DiagnosticCode())) {
            response.append(" diagnostic=").append(snapshot.latestReport.getX411DiagnosticCode());
        }
        return response.toString();
    }

    private StatusSnapshot loadStatus(String submissionId) {
        Long internalMessageId = submissionCorrelationTable.get(submissionId);
        Optional<AMHSMessage> maybeMessage = internalMessageId != null
            ? messageRepository.findById(internalMessageId)
            : Optional.empty();
        if (maybeMessage.isEmpty()) {
            maybeMessage = messageRepository.findByMessageId(submissionId);
        }
        if (maybeMessage.isEmpty()) {
            return null;
        }

        AMHSMessage message = maybeMessage.get();
        submissionCorrelationTable.put(submissionId, message.getId());
        Optional<AMHSDeliveryReport> latestReport = deliveryReportRepository.findByMessage(message).stream()
            .max((left, right) -> left.getGeneratedAt().compareTo(right.getGeneratedAt()));

        String drStatus = latestReport.map(report -> report.getDeliveryStatus().name()).orElse("PENDING");
        String ipnStatus = resolveIpnStatus(message, latestReport.isPresent());
        return new StatusSnapshot(message, latestReport.orElse(null), drStatus, ipnStatus);
    }

    private String resolveIpnStatus(AMHSMessage message, boolean hasReport) {
        if (message.getIpnRequest() == null || message.getIpnRequest() <= 0) {
            return "NOT-REQUESTED";
        }
        if (hasReport || message.getLifecycleState() == AMHSMessageState.REPORTED) {
            return "REPORTED";
        }
        return "PENDING";
    }

    private long parseLong(String maybeNumber, long fallback) {
        if (!StringUtils.hasText(maybeNumber)) {
            return fallback;
        }
        try {
            return Long.parseLong(maybeNumber.trim());
        } catch (NumberFormatException ex) {
            return fallback;
        }
    }


    private String readMailbox(SessionState state, Map<String, String> attributes) {
        if (!state.bound) {
            logger.warn("P3 read rejected: operation before bind");
            return "ERR code=association detail=Read operation received before bind";
        }

        String recipient = attributes.getOrDefault("recipient", state.senderOrAddress);
        if (!StringUtils.hasText(recipient)) {
            logger.warn("P3 read rejected: missing recipient");
            return "ERR code=invalid-or-address detail=Missing recipient address";
        }

        long waitTimeoutMs = parseLong(attributes.get("wait-timeout-ms"), defaultStatusWaitTimeoutMs);
        long retryIntervalMs = Math.max(1L, parseLong(attributes.get("retry-interval-ms"), defaultStatusRetryIntervalMs));
        Instant deadline = Instant.now().plusMillis(Math.max(0L, waitTimeoutMs));

        AMHSDeliveryReport report = loadNextReport(recipient, state.lastReadReportId);
        while (report == null && waitTimeoutMs > 0 && Instant.now().isBefore(deadline)) {
            long remainingMs = Math.max(1L, Duration.between(Instant.now(), deadline).toMillis());
            try {
                Thread.sleep(Math.min(retryIntervalMs, remainingMs));
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                return "ERR code=interrupted detail=Read wait interrupted";
            }
            report = loadNextReport(recipient, state.lastReadReportId);
        }

        if (report == null) {
            return "OK code=read-empty recipient=" + recipient;
        }

        state.lastReadReportId = report.getId();
        return "OK code=read"
            + " report-id=" + report.getId()
            + " message-id=" + report.getMessage().getMessageId()
            + " recipient=" + report.getRecipient()
            + " report-type=" + report.getReportType()
            + " dr-status=" + report.getDeliveryStatus()
            + (StringUtils.hasText(report.getX411DiagnosticCode()) ? " diagnostic=" + report.getX411DiagnosticCode() : "");
    }

    private AMHSDeliveryReport loadNextReport(String recipient, Long afterId) {
        long cursor = afterId == null ? 0L : Math.max(0L, afterId);
        return deliveryReportRepository.findByRecipientIgnoreCaseAndIdGreaterThanOrderByIdAsc(recipient, cursor).stream()
            .findFirst()
            .orElse(null);
    }

    private String unbind(SessionState state) {
        state.bound = false;
        state.username = null;
        state.senderOrAddress = null;
        state.channelName = null;
        state.lastReadReportId = null;
        state.closed = true;
        logger.info("P3 release completed");
        return "OK code=release";
    }

    private Map<String, String> parseAttributes(String rawAttributes) {
        Map<String, String> attributes = new LinkedHashMap<>();
        Arrays.stream(rawAttributes.split(";"))
            .map(String::trim)
            .filter(StringUtils::hasText)
            .forEach(token -> {
                String[] kv = token.split("=", 2);
                if (kv.length == 2) {
                    attributes.put(kv[0].trim().toLowerCase(), kv[1].trim());
                }
            });
        return attributes;
    }

    static String deterministicSubmissionId(String sender, String recipient, String body, String subject) {
        String payload = sender + "|" + recipient + "|" + subject + "|" + body;
        return UUID.nameUUIDFromBytes(payload.getBytes(StandardCharsets.UTF_8)).toString();
    }

    public static final class SessionState {
        private boolean bound;
        private String username;
        private String senderOrAddress;
        private String channelName;
        private boolean closed;
        private Long lastReadReportId;

        public boolean isClosed() {
            return closed;
        }
    }

    private record StatusSnapshot(AMHSMessage message, AMHSDeliveryReport latestReport, String drStatus, String ipnStatus) {
    }
}
