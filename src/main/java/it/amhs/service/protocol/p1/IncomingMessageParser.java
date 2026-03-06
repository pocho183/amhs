package it.amhs.service.protocol.p1;

import it.amhs.asn1.BerCodec;
import it.amhs.domain.AMHSPriority;
import it.amhs.domain.AMHSProfile;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import it.amhs.service.channel.AMHSChannelService;
import it.amhs.service.protocol.rfc1006.RFC1006Service;

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

        Optional<RFC1006Service.IncomingMessage> berParsed = tryParseBerPayload(rawPayload, certificateCn, certificateOu);
        if (berParsed.isPresent()) {
            return berParsed.get();
        }

        LOGGER.info("Payload not detected as BER, falling back to key-value parsing");

        Map<String, String> headers = parseKeyValuePayload(message);
        LOGGER.info("Parsed headers: {}", headers);

        String from = resolveFrom(headers, certificateCn, certificateOu);
        String to = resolveTo(headers);
        String textBody = isLikelyTextPayload(rawPayload) ? message : null;
        String body = firstNonBlank(headers.get("Body"), headers.get("Text"), textBody, bytesToHex(rawPayload));

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

    public Map<String, String> parseKeyValuePayload(String message) {
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

    private Optional<RFC1006Service.IncomingMessage> tryParseBerPayload(byte[] rawPayload, String certificateCn, String certificateOu) {
        if (rawPayload == null || rawPayload.length == 0) {
            return Optional.empty();
        }

        List<Integer> berOffsets = candidateBerOffsets(rawPayload);
        LOGGER.info("BER candidate scan found {} offsets in payload of {} bytes", berOffsets.size(), rawPayload.length);
        for (int offset : berOffsets) {
            byte[] candidate = offset == 0 ? rawPayload : Arrays.copyOfRange(rawPayload, offset, rawPayload.length);
            int firstByte = candidate[0] & 0xFF;
            LOGGER.info("Attempting BER parse at payload offset {} (first byte=0x{})", offset, String.format("%02X", firstByte));

            try {
                P1BerMessageParser.ParsedP1Message berMessage = p1BerMessageParser.parse(candidate);
                return Optional.of(toIncomingMessage(berMessage, candidate, certificateCn, certificateOu));
            } catch (IllegalArgumentException e) {
                LOGGER.debug("BER parsing failed at offset {}: {}", offset, e.getMessage());
            }
        }

        return Optional.empty();
    }

    private List<Integer> candidateBerOffsets(byte[] rawPayload) {
        Set<Integer> offsets = new LinkedHashSet<>();
        if (isBerEncoded(rawPayload)) {
            offsets.add(0);
        }

        int scanLimit = Math.min(rawPayload.length - 1, 512);
        for (int i = 1; i <= scanLimit; i++) {
            int tag = rawPayload[i] & 0xFF;
            if (tag == 0x30 || (tag >= 0x60 && tag <= 0x65) || (tag >= 0xA0 && tag <= 0xAF)) {
                offsets.add(i);
            }
        }

        return new ArrayList<>(offsets);
    }

    private RFC1006Service.IncomingMessage toIncomingMessage(
            P1BerMessageParser.ParsedP1Message berMessage,
            byte[] parsedPayload,
            String certificateCn,
            String certificateOu) {
        return new RFC1006Service.IncomingMessage(
                berMessage.messageId() != null ? berMessage.messageId() : UUID.randomUUID().toString(),
                firstNonBlank(berMessage.from(), "UNKNOWN_FROM"),
                firstNonBlank(berMessage.to(), "UNKNOWN_TO"),
                firstNonBlank(berMessage.body(), bytesToHex(parsedPayload)),
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
    }

    private boolean isLikelyTextPayload(byte[] payload) {
        if (payload == null || payload.length == 0) {
            return false;
        }

        String decoded = new String(payload, StandardCharsets.UTF_8);
        int suspicious = 0;
        for (int i = 0; i < decoded.length(); i++) {
            char c = decoded.charAt(i);
            if (c == '\uFFFD' || (Character.isISOControl(c) && c != '\n' && c != '\r' && c != '\t')) {
                suspicious++;
            }
        }
        return suspicious * 5 <= decoded.length();
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

    public String firstNonBlank(String... values) {
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

    public AMHSProfile parseProfile(String value) {
        try { return AMHSProfile.valueOf(value.trim().toUpperCase()); }
        catch (Exception ignored) { return AMHSProfile.P3; }
    }

    public AMHSPriority parsePriority(String value) {
        try { return AMHSPriority.valueOf(value.trim().toUpperCase()); }
        catch (Exception ignored) { return AMHSPriority.GG; }
    }

    public Date parseFilingTime(String filingTimeHeader) {
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
