package it.amhs.service.protocol.p3;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import it.amhs.api.X400MessageRequest;
import it.amhs.domain.AMHSMessage;
import it.amhs.service.address.ORAddress;
import it.amhs.service.message.X400MessageService;

@Service
public class P3GatewaySessionService {

    private final X400MessageService x400MessageService;
    private final boolean authRequired;
    private final String expectedUsername;
    private final String expectedPassword;
    private final String defaultProtocolIndex;
    private final String defaultProtocolAddress;
    private final String defaultServerAddress;

    public P3GatewaySessionService(
        X400MessageService x400MessageService,
        @Value("${amhs.p3.gateway.auth.required:true}") boolean authRequired,
        @Value("${amhs.p3.gateway.auth.username:}") String expectedUsername,
        @Value("${amhs.p3.gateway.auth.password:}") String expectedPassword,
        @Value("${amhs.p3.gateway.protocol-index:RFC1006}") String defaultProtocolIndex,
        @Value("${amhs.p3.gateway.protocol-address:127.0.0.1:102}") String defaultProtocolAddress,
        @Value("${amhs.p3.gateway.server-address:AMHS-P3-GATEWAY}") String defaultServerAddress
    ) {
        this.x400MessageService = x400MessageService;
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
            case "UNBIND", "RELEASE", "QUIT" -> unbind(state);
            default -> "ERR code=unsupported-operation detail=Unsupported operation " + operation;
        };
    }

    private String bind(SessionState state, Map<String, String> attributes) {
        String username = attributes.getOrDefault("username", "");
        String password = attributes.getOrDefault("password", "");
        String senderAddress = attributes.getOrDefault("sender", "");

        if (!StringUtils.hasText(senderAddress)) {
            return "ERR code=invalid-or-address detail=Missing sender address";
        }

        ORAddress parsedSender;
        try {
            parsedSender = ORAddress.parse(senderAddress);
        } catch (IllegalArgumentException ex) {
            return "ERR code=invalid-or-address detail=" + ex.getMessage();
        }

        if (authRequired) {
            if (!StringUtils.hasText(username) || !StringUtils.hasText(password)) {
                return "ERR code=auth-failed detail=Missing credentials";
            }
            if (!expectedUsername.equals(username) || !expectedPassword.equals(password)) {
                return "ERR code=auth-failed detail=Invalid credentials";
            }
        }

        state.bound = true;
        state.username = username;
        state.senderOrAddress = parsedSender.toCanonicalString();
        return "OK code=bind-accepted sender=" + state.senderOrAddress;
    }

    private String submit(SessionState state, Map<String, String> attributes) {
        if (!state.bound) {
            return "ERR code=association detail=Submit received before bind";
        }

        String recipientAddress = attributes.getOrDefault("recipient", "");
        String body = attributes.getOrDefault("body", "");
        String subject = attributes.getOrDefault("subject", null);

        if (!StringUtils.hasText(recipientAddress)) {
            return "ERR code=invalid-or-address detail=Missing recipient address";
        }
        if (!StringUtils.hasText(body)) {
            return "ERR code=invalid-message detail=Body cannot be empty";
        }

        ORAddress sender = ORAddress.parse(state.senderOrAddress);
        ORAddress recipient;
        try {
            recipient = ORAddress.parse(recipientAddress);
        } catch (IllegalArgumentException ex) {
            return "ERR code=invalid-or-address detail=" + ex.getMessage();
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
            null,
            state.username,
            null
        );

        AMHSMessage storedMessage = x400MessageService.storeFromP3(request);
        return "OK code=submitted submission-id=" + submissionId + " message-id=" + storedMessage.getId();
    }

    private String unbind(SessionState state) {
        state.bound = false;
        state.username = null;
        state.senderOrAddress = null;
        state.closed = true;
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
        private boolean closed;

        public boolean isClosed() {
            return closed;
        }
    }
}
