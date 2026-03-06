package it.amhs.service;

import it.amhs.asn1.BerCodec;
import it.amhs.domain.AMHSPriority;
import it.amhs.domain.AMHSProfile;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.*;

public final class IncomingMessageParser {

    private static final Logger LOGGER = LoggerFactory.getLogger(IncomingMessageParser.class);

    private final P1BerMessageParser p1BerMessageParser;
    private final String localMtaName;
    private final String localRoutingDomain;

    public IncomingMessageParser(P1BerMessageParser p1BerMessageParser, String localMtaName, String localRoutingDomain) {
        this.p1BerMessageParser = p1BerMessageParser;
        this.localMtaName = localMtaName;
        this.localRoutingDomain = localRoutingDomain;
    }

    public RFC1006Service.IncomingMessage parse(byte[] rawPayload, String message, String certificateCn, String certificateOu) {
        LOGGER.info("Incoming message received. RawPayload bytes={}, messageLength={}, certCN={}, certOU={}",
                rawPayload != null ? rawPayload.length : 0,
                message != null ? message.length() : 0,
                certificateCn, certificateOu);

        if (isBerEncoded(rawPayload)) {
            int firstByte = rawPayload.length > 0 ? rawPayload[0] & 0xFF : -1;
            LOGGER.info("Payload first byte=0x{}", firstByte >= 0 ? String.format("%02X", firstByte) : "none");

            try {
                P1BerMessageParser.ParsedP1Message berMessage = p1BerMessageParser.parse(rawPayload);

                return new RFC1006Service.IncomingMessage(
                        berMessage.messageId() != null ? berMessage.messageId() : UUID.randomUUID().toString(),
                        firstNonBlank(berMessage.from(), "UNKNOWN_FROM"),
                        firstNonBlank(berMessage.to(), "UNKNOWN_TO"),
                        firstNonBlank(berMessage.body(), bytesToHex(rawPayload)),
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
                                berMessage.transferEnvelope().traceInformation()
                                        .map(t -> String.join(">", t.hops())).orElse(null),
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
            } catch (IllegalArgumentException e) {
                LOGGER.warn("BER parsing failed: {}. Falling back to raw key-value parsing.", e.getMessage());
            }
        } else {
            LOGGER.info("Payload not detected as BER, falling back to key-value parsing");
        }

        Map<String, String> headers = parseKeyValuePayload(message);
        LOGGER.info("Parsed headers: {}", headers);

        String from = resolveFrom(headers, certificateCn, certificateOu);
        String to = resolveTo(headers);
        String body = firstNonBlank(headers.get("Body"), headers.get("Text"), message, bytesToHex(rawPayload));

        if (!StringUtils.hasText(from)) {
            LOGGER.warn("Cannot resolve 'from': using placeholder");
            from = "UNKNOWN_FROM";
        }

        if (!StringUtils.hasText(to)) {
            LOGGER.warn("Cannot resolve 'to': using placeholder");
            to = "UNKNOWN_TO";
        }

        if (!StringUtils.hasText(body)) {
            LOGGER.warn("Cannot resolve 'body': using placeholder (raw HEX)");
            body = rawPayload != null ? bytesToHex(rawPayload) : "EMPTY_BODY";
        }

        String messageId = headers.getOrDefault("Message-ID", UUID.randomUUID().toString());
        AMHSProfile profile = parseProfile(headers.getOrDefault("Profile", "P3"));
        AMHSPriority priority = parsePriority(headers.getOrDefault("Priority", "GG"));
        String subject = headers.getOrDefault("Subject", "");
        String channel = headers.getOrDefault("Channel", AMHSChannelService.DEFAULT_CHANNEL_NAME);
        Date filingTime = parseFilingTime(headers.get("Filing-Time"));

        return new RFC1006Service.IncomingMessage(
                messageId, from, to, body, profile, priority, subject, channel,
                certificateCn, certificateOu, filingTime,
                null, null, null, null,
                System.nanoTime()
        );
    }

    Map<String, String> parseKeyValuePayload(String message) {
        Map<String, String> headers = new HashMap<>();
        if (message == null) return headers;

        for (String line : message.split("\\n")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith(";") || (trimmed.startsWith("[") && trimmed.endsWith("]"))) continue;

            String[] kv = trimmed.contains(":") ? trimmed.split(":", 2)
                    : trimmed.contains("=") ? trimmed.split("=", 2)
                    : null;

            if (kv == null || kv.length != 2) continue;

            String key = kv[0].trim();
            String value = kv[1].trim();
            if (!key.isEmpty()) headers.put(key, value);
        }
        return headers;
    }

    private boolean isBerEncoded(byte[] payload) {
        if (payload == null || payload.length == 0) return false;
        int first = payload[0] & 0xFF;
        return first == 0x30 || (first >= 0x60 && first <= 0x65) || (first >= 0xA0 && first <= 0xAF);
    }

    private String resolveFrom(Map<String, String> headers, String certificateCn, String certificateOu) {
        return firstNonBlank(
                headers.get("From"),
                buildLegacyAddress(headers, ""),
                buildLegacyAddress(headers, "_Reader"),
                firstNonBlank(certificateCn, certificateOu),
                "UNKNOWN_FROM"
        );
    }

    private String resolveTo(Map<String, String> headers) {
        return firstNonBlank(
                headers.get("To"),
                headers.get("Recipient"),
                buildLegacyAddress(headers, "_Recipient"),
                "UNKNOWN_TO"
        );
    }

    private String buildLegacyAddress(Map<String, String> headers, String suffix) {
        String ou = headers.get("OU" + suffix);
        String o = headers.get("O" + suffix);
        String prmd = headers.get("PRMD" + suffix);
        String admd = headers.get("ADMD" + suffix);
        String c = headers.get("C" + suffix);

        if (!StringUtils.hasText(ou) && !StringUtils.hasText(o) && !StringUtils.hasText(prmd)
                && !StringUtils.hasText(admd) && !StringUtils.hasText(c)) return null;

        StringBuilder value = new StringBuilder();
        appendPart(value, "OU", ou);
        appendPart(value, "O", o);
        appendPart(value, "PRMD", prmd);
        appendPart(value, "ADMD", admd);
        appendPart(value, "C", c);
        return value.toString();
    }

    private void appendPart(StringBuilder builder, String key, String value) {
        if (!StringUtils.hasText(value)) return;
        if (builder.length() > 0) builder.append(";");
        builder.append(key).append("=").append(value.trim());
    }

    String firstNonBlank(String... values) {
        if (values == null) return null;
        for (String v : values) {
            if (StringUtils.hasText(v)) return v.trim();
        }
        return null;
    }

    private String bytesToHex(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return "";
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02X", b));
        return sb.toString();
    }

    AMHSProfile parseProfile(String value) {
        try { return AMHSProfile.valueOf(value.trim().toUpperCase()); }
        catch (Exception ignored) { return AMHSProfile.P3; }
    }

    AMHSPriority parsePriority(String value) {
        try { return AMHSPriority.valueOf(value.trim().toUpperCase()); }
        catch (Exception ignored) { return AMHSPriority.GG; }
    }

    Date parseFilingTime(String filingTimeHeader) {
        if (!StringUtils.hasText(filingTimeHeader)) return Date.from(Instant.now());

        try { return Date.from(Instant.parse(filingTimeHeader.trim())); }
        catch (Exception ignored) {}

        try {
            SimpleDateFormat format = new SimpleDateFormat("yyyyMMddHHmmss");
            format.setTimeZone(TimeZone.getTimeZone("UTC"));
            return format.parse(filingTimeHeader.trim());
        } catch (ParseException ex) {
            return Date.from(Instant.now());
        }
    }
}