package it.amhs.service;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.TimeZone;

import org.springframework.stereotype.Component;

import it.amhs.asn1.BerCodec;
import it.amhs.asn1.BerTlv;
import it.amhs.domain.AMHSPriority;
import it.amhs.domain.AMHSProfile;

@Component
public class P1BerMessageParser {

    public ParsedP1Message parse(byte[] payload) {
        BerTlv root = BerCodec.decodeSingle(payload);
        if (!root.isUniversal() || root.tagNumber() != 16 || !root.constructed()) {
            throw new IllegalArgumentException("P1 BER payload must be a SEQUENCE");
        }

        List<BerTlv> fields = BerCodec.decodeAll(root.value());

        String from = requiredIa5(fields, 0, "from");
        String to = requiredIa5(fields, 1, "to");
        String body = requiredUtf8(fields, 2, "body");
        AMHSProfile profile = parseProfile(optionalEnumerated(fields, 3).orElse(0));
        AMHSPriority priority = parsePriority(optionalEnumerated(fields, 4).orElse(3));
        String subject = optionalUtf8(fields, 5).orElse("");
        String messageId = optionalIa5(fields, 6).orElse(null);
        Date filingTime = parseFilingTime(fields);

        return new ParsedP1Message(from, to, body, profile, priority, subject, messageId, filingTime);
    }

    private Date parseFilingTime(List<BerTlv> fields) {
        Optional<BerTlv> utc = BerCodec.findOptional(fields, 2, 7);
        Optional<BerTlv> generalized = BerCodec.findOptional(fields, 2, 8);

        BerTlv selected = null;
        if (generalized.isPresent()) {
            selected = generalized.get();
        } else if (utc.isPresent()) {
            selected = utc.get();
        }

        if (selected == null) {
            return Date.from(Instant.now());
        }

        String value = new String(selected.value(), StandardCharsets.US_ASCII);
        try {
            if (selected.tagNumber() == 8) {
                SimpleDateFormat generalizedFormat = new SimpleDateFormat("yyyyMMddHHmmss'Z'", Locale.ROOT);
                generalizedFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
                return generalizedFormat.parse(value);
            }
            SimpleDateFormat utcFormat = new SimpleDateFormat("yyMMddHHmmss'Z'", Locale.ROOT);
            utcFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
            return utcFormat.parse(value);
        } catch (ParseException ex) {
            throw new IllegalArgumentException("Invalid BER filing time: " + value, ex);
        }
    }

    private String requiredIa5(List<BerTlv> fields, int contextTag, String field) {
        return optionalIa5(fields, contextTag)
            .orElseThrow(() -> new IllegalArgumentException("Missing BER field '" + field + "'"));
    }

    private Optional<String> optionalIa5(List<BerTlv> fields, int contextTag) {
        return BerCodec.findOptional(fields, 2, contextTag)
            .map(value -> new String(value.value(), StandardCharsets.US_ASCII));
    }

    private String requiredUtf8(List<BerTlv> fields, int contextTag, String field) {
        return optionalUtf8(fields, contextTag)
            .orElseThrow(() -> new IllegalArgumentException("Missing BER field '" + field + "'"));
    }

    private Optional<String> optionalUtf8(List<BerTlv> fields, int contextTag) {
        return BerCodec.findOptional(fields, 2, contextTag)
            .map(value -> new String(value.value(), StandardCharsets.UTF_8));
    }

    private Optional<Integer> optionalEnumerated(List<BerTlv> fields, int contextTag) {
        return BerCodec.findOptional(fields, 2, contextTag)
            .map(value -> {
                if (value.value().length == 0 || value.value().length > 4) {
                    throw new IllegalArgumentException("Invalid BER ENUMERATED length for context tag " + contextTag);
                }
                int number = 0;
                for (byte b : value.value()) {
                    number = (number << 8) | (b & 0xFF);
                }
                return number;
            });
    }

    private AMHSProfile parseProfile(int profileValue) {
        return switch (profileValue) {
            case 0 -> AMHSProfile.P3;
            case 1 -> AMHSProfile.P7;
            default -> throw new IllegalArgumentException("Unsupported BER profile value: " + profileValue);
        };
    }

    private AMHSPriority parsePriority(int priorityValue) {
        return switch (priorityValue) {
            case 0 -> AMHSPriority.SS;
            case 1 -> AMHSPriority.DD;
            case 2 -> AMHSPriority.FF;
            case 3 -> AMHSPriority.GG;
            case 4 -> AMHSPriority.KK;
            default -> throw new IllegalArgumentException("Unsupported BER priority value: " + priorityValue);
        };
    }

    public record ParsedP1Message(
        String from,
        String to,
        String body,
        AMHSProfile profile,
        AMHSPriority priority,
        String subject,
        String messageId,
        Date filingTime
    ) {
    }
}
