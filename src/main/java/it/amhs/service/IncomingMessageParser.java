package it.amhs.service;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;
import java.util.UUID;

import org.springframework.util.StringUtils;

import it.amhs.domain.AMHSPriority;
import it.amhs.domain.AMHSProfile;

final class IncomingMessageParser {

    private final P1BerMessageParser p1BerMessageParser;
    private final String localMtaName;
    private final String localRoutingDomain;

    IncomingMessageParser(P1BerMessageParser p1BerMessageParser, String localMtaName, String localRoutingDomain) {
        this.p1BerMessageParser = p1BerMessageParser;
        this.localMtaName = localMtaName;
        this.localRoutingDomain = localRoutingDomain;
    }

    RFC1006Service.IncomingMessage parse(byte[] rawPayload, String message, String certificateCn, String certificateOu) {
        if (rawPayload.length > 0 && (rawPayload[0] & 0xFF) == 0x30) {
            P1BerMessageParser.ParsedP1Message berMessage = p1BerMessageParser.parse(rawPayload);
            return new RFC1006Service.IncomingMessage(
                berMessage.messageId() == null ? UUID.randomUUID().toString() : berMessage.messageId(),
                requireNonBlank(berMessage.from(), "from"),
                requireNonBlank(berMessage.to(), "to"),
                requireNonBlank(berMessage.body(), "body"),
                berMessage.profile(),
                berMessage.priority(),
                berMessage.subject(),
                AMHSChannelService.DEFAULT_CHANNEL_NAME,
                certificateCn,
                certificateOu,
                berMessage.filingTime(),
                berMessage.transferEnvelope().mtsIdentifier().flatMap(P1BerMessageParser.MTSIdentifier::localIdentifier).orElse(null),
                berMessage.transferEnvelope().contentTypeOid().orElse(null),
                RFC1006Service.appendTraceHop(
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

        Map<String, String> headers = parseKeyValuePayload(message);
        String body = firstNonBlank(headers.get("Body"), headers.get("Text"), message);

        String messageId = headers.getOrDefault("Message-ID", UUID.randomUUID().toString());
        String from = resolveFrom(headers, certificateCn, certificateOu);
        String to = resolveTo(headers);
        AMHSProfile profile = parseProfile(headers.getOrDefault("Profile", "P3"));
        AMHSPriority priority = parsePriority(headers.getOrDefault("Priority", "GG"));
        String subject = headers.getOrDefault("Subject", "");
        String channel = headers.getOrDefault("Channel", AMHSChannelService.DEFAULT_CHANNEL_NAME);
        Date filingTime = parseFilingTime(headers.get("Filing-Time"));

        return new RFC1006Service.IncomingMessage(
            messageId,
            from,
            to,
            requireNonBlank(body, "body"),
            profile,
            priority,
            subject,
            channel,
            certificateCn,
            certificateOu,
            filingTime,
            null,
            null,
            null,
            null,
            System.nanoTime()
        );
    }

    private Map<String, String> parseKeyValuePayload(String message) {
        Map<String, String> headers = new HashMap<>();
        for (String line : message.split("\\n")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith(";") || (trimmed.startsWith("[") && trimmed.endsWith("]"))) {
                continue;
            }

            String[] kv = null;
            if (trimmed.contains(":")) {
                kv = trimmed.split(":", 2);
            } else if (trimmed.contains("=")) {
                kv = trimmed.split("=", 2);
            }

            if (kv == null || kv.length != 2) {
                continue;
            }

            String key = kv[0].trim();
            String value = kv[1].trim();
            if (!key.isEmpty()) {
                headers.put(key, value);
            }
        }
        return headers;
    }

    private String resolveFrom(Map<String, String> headers, String certificateCn, String certificateOu) {
        String from = firstNonBlank(
            headers.get("From"),
            buildLegacyAddress(headers, ""),
            buildLegacyAddress(headers, "_Reader"),
            firstNonBlank(certificateCn, certificateOu)
        );
        return requireNonBlank(from, "from");
    }

    private String resolveTo(Map<String, String> headers) {
        String to = firstNonBlank(
            headers.get("To"),
            headers.get("Recipient"),
            buildLegacyAddress(headers, "_Recipient")
        );
        return requireNonBlank(to, "to");
    }

    private String buildLegacyAddress(Map<String, String> headers, String suffix) {
        String ou = headers.get("OU" + suffix);
        String o = headers.get("O" + suffix);
        String prmd = headers.get("PRMD" + suffix);
        String admd = headers.get("ADMD" + suffix);
        String c = headers.get("C" + suffix);

        if (!StringUtils.hasText(ou) && !StringUtils.hasText(o) && !StringUtils.hasText(prmd)
            && !StringUtils.hasText(admd) && !StringUtils.hasText(c)) {
            return null;
        }

        StringBuilder value = new StringBuilder();
        appendPart(value, "OU", ou);
        appendPart(value, "O", o);
        appendPart(value, "PRMD", prmd);
        appendPart(value, "ADMD", admd);
        appendPart(value, "C", c);
        return value.toString();
    }

    private void appendPart(StringBuilder builder, String key, String value) {
        if (!StringUtils.hasText(value)) {
            return;
        }
        if (!builder.isEmpty()) {
            builder.append(";");
        }
        builder.append(key).append("=").append(value.trim());
    }

    private String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return null;
    }

    private String requireNonBlank(String value, String fieldName) {
        if (!StringUtils.hasText(value)) {
            throw new IllegalArgumentException("Missing or blank AMHS field '" + fieldName + "'");
        }
        return value.trim();
    }

    private AMHSProfile parseProfile(String value) {
        try {
            return AMHSProfile.valueOf(value.trim().toUpperCase());
        } catch (Exception ignored) {
            return AMHSProfile.P3;
        }
    }

    private AMHSPriority parsePriority(String value) {
        try {
            return AMHSPriority.valueOf(value.trim().toUpperCase());
        } catch (Exception ignored) {
            return AMHSPriority.GG;
        }
    }

    private Date parseFilingTime(String filingTimeHeader) {
        if (!StringUtils.hasText(filingTimeHeader)) {
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
            return Date.from(Instant.now());
        }
    }
}
