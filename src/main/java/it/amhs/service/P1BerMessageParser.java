package it.amhs.service;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.TimeZone;
import java.util.stream.Collectors;

import org.springframework.stereotype.Component;

import it.amhs.asn1.BerCodec;
import it.amhs.asn1.BerTlv;
import it.amhs.domain.AMHSPriority;
import it.amhs.domain.AMHSProfile;
import it.amhs.service.ExtensibilityContainers.ExtensionContainer;
import it.amhs.service.ExtensibilityContainers.SecurityParameters;

@Component
public class P1BerMessageParser {

    public ParsedP1Message parse(byte[] payload) {
        BerTlv root = BerCodec.decodeSingle(payload);
        if (!root.isUniversal() || root.tagNumber() != 16 || !root.constructed()) {
            throw new IllegalArgumentException("P1 BER payload must be a SEQUENCE");
        }

        List<BerTlv> fields = BerCodec.decodeAll(root.value());

        TransferEnvelope transferEnvelope = parseTransferEnvelope(fields);

        String from = transferEnvelope.originator()
            .map(this::mapOriginator)
            .orElseGet(() -> requiredIa5(fields, 0, "from"));
        String to = transferEnvelope.primaryRecipient().orElseGet(() -> requiredIa5(fields, 1, "to"));
        String body = requiredUtf8(fields, 2, "body");
        AMHSProfile profile = parseProfile(optionalEnumerated(fields, 3).orElse(0));
        AMHSPriority priority = parsePriority(optionalEnumerated(fields, 4).orElse(3));
        String subject = optionalUtf8(fields, 5).orElse("");
        String messageId = transferEnvelope.mtsIdentifier().flatMap(MTSIdentifier::localIdentifier)
            .orElseGet(() -> optionalIa5(fields, 6).orElse(null));
        Date filingTime = transferEnvelope.mtsIdentifier().flatMap(MTSIdentifier::filingTime)
            .orElseGet(() -> parseFilingTime(fields));

        return new ParsedP1Message(from, to, body, profile, priority, subject, messageId, filingTime, transferEnvelope);
    }


    private String mapOriginator(String originator) {
        try {
            return ORNameMapper.fromLegacyIa5(originator).orAddress().toCanonicalString();
        } catch (IllegalArgumentException ex) {
            return originator;
        }
    }

    private TransferEnvelope parseTransferEnvelope(List<BerTlv> fields) {
        Optional<BerTlv> envelopeTlv = BerCodec.findOptional(fields, 2, 9).filter(BerTlv::constructed);
        if (envelopeTlv.isEmpty()) {
            return new TransferEnvelope(Optional.empty(), List.of(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), List.of());
        }

        List<BerTlv> envelopeFields = BerCodec.decodeAll(envelopeTlv.get().value());
        Optional<MTSIdentifier> mtsIdentifier = BerCodec.findOptional(envelopeFields, 2, X411TagMap.ENVELOPE_MTS_IDENTIFIER)
            .filter(BerTlv::constructed)
            .map(this::parseMtsIdentifier);

        List<PerRecipientFields> perRecipientFields = BerCodec.findOptional(envelopeFields, 2, X411TagMap.ENVELOPE_PER_RECIPIENT)
            .filter(BerTlv::constructed)
            .map(this::parsePerRecipientFields)
            .orElse(List.of());

        Optional<TraceInformation> traceInformation = BerCodec.findOptional(envelopeFields, 2, X411TagMap.ENVELOPE_TRACE)
            .filter(BerTlv::constructed)
            .map(this::parseTraceInformation);

        Optional<String> contentTypeOid = BerCodec.findOptional(envelopeFields, 2, X411TagMap.ENVELOPE_CONTENT_TYPE)
            .map(this::parseContentTypeOid);

        Optional<String> originator = BerCodec.findOptional(envelopeFields, 2, X411TagMap.ENVELOPE_ORIGINATOR)
            .map(value -> new String(value.value(), StandardCharsets.US_ASCII));

        Optional<SecurityParameters> securityParameters = BerCodec.findOptional(envelopeFields, 2, X411TagMap.ENVELOPE_SECURITY_PARAMETERS)
            .filter(BerTlv::constructed)
            .map(this::parseSecurityParameters);

        List<ExtensibilityContainers.UnknownExtension> unknownExtensions = parseUnknownEnvelopeExtensions(envelopeFields);
        return new TransferEnvelope(mtsIdentifier, perRecipientFields, traceInformation, contentTypeOid, originator, securityParameters, unknownExtensions);
    }

    private List<ExtensibilityContainers.UnknownExtension> parseUnknownEnvelopeExtensions(List<BerTlv> envelopeFields) {
        ExtensionContainer container = new ExtensionContainer();
        for (BerTlv tlv : envelopeFields) {
            if (tlv.tagClass() != 2) {
                continue;
            }
            int tag = tlv.tagNumber();
            if (tag > X411TagMap.ENVELOPE_EXTENSIONS) {
                container.add(tlv);
            }
        }
        return container.unknownExtensions();
    }

    private SecurityParameters parseSecurityParameters(BerTlv securityTlv) {
        List<BerTlv> fields = BerCodec.decodeAll(securityTlv.value());
        String label = BerCodec.findOptional(fields, 2, 0).map(v -> new String(v.value(), StandardCharsets.UTF_8)).orElse("UNCLASSIFIED");
        String token = BerCodec.findOptional(fields, 2, 1).map(v -> new String(v.value(), StandardCharsets.US_ASCII)).orElse("NONE");
        String oid = BerCodec.findOptional(fields, 2, 2).map(v -> new String(v.value(), StandardCharsets.US_ASCII)).orElse("1.2.840.113549.1.1.1");
        SecurityParameters parameters = new SecurityParameters(label, token, oid);
        parameters.validate();
        return parameters;
    }

    private MTSIdentifier parseMtsIdentifier(BerTlv mtsIdentifierTlv) {
        List<BerTlv> mtsFields = BerCodec.decodeAll(mtsIdentifierTlv.value());
        Optional<String> localIdentifier = BerCodec.findOptional(mtsFields, 2, 0)
            .map(value -> new String(value.value(), StandardCharsets.US_ASCII));
        Optional<Date> filingTime = parseOptionalFilingTime(mtsFields);
        return new MTSIdentifier(localIdentifier, filingTime);
    }

    private List<PerRecipientFields> parsePerRecipientFields(BerTlv perRecipientTlv) {
        List<BerTlv> entries = BerCodec.decodeAll(perRecipientTlv.value());
        return entries.stream()
            .filter(BerTlv::constructed)
            .map(entry -> {
                List<BerTlv> fields = BerCodec.decodeAll(entry.value());
                String recipient = BerCodec.findOptional(fields, 2, 0)
                    .map(value -> new String(value.value(), StandardCharsets.US_ASCII))
                    .orElse("UNKNOWN");
                Optional<Integer> responsibility = BerCodec.findOptional(fields, 2, 1)
                    .map(this::parseIntegerValue);
                Optional<Integer> deliveryFlags = BerCodec.findOptional(fields, 2, 2)
                    .map(this::parseIntegerValue);
                List<String> extensionIds = BerCodec.findOptional(fields, 2, 3)
                    .filter(BerTlv::constructed)
                    .map(this::parseStringList)
                    .orElse(List.of());
                return new PerRecipientFields(recipient, responsibility, deliveryFlags, extensionIds);
            })
            .collect(Collectors.toList());
    }

    private List<String> parseStringList(BerTlv listTlv) {
        List<String> values = new ArrayList<>();
        for (BerTlv item : BerCodec.decodeAll(listTlv.value())) {
            values.add(new String(item.value(), StandardCharsets.UTF_8));
        }
        return values;
    }

    private TraceInformation parseTraceInformation(BerTlv traceTlv) {
        List<BerTlv> hops = BerCodec.decodeAll(traceTlv.value());
        List<String> hopNames = hops.stream()
            .map(hop -> {
                if (!hop.constructed()) {
                    return bytesToHex(hop.value());
                }
                List<BerTlv> hopFields = BerCodec.decodeAll(hop.value());
                return BerCodec.findOptional(hopFields, 2, 0)
                    .map(value -> new String(value.value(), StandardCharsets.US_ASCII))
                    .orElse(bytesToHex(hop.value()));
            })
            .collect(Collectors.toList());
        return new TraceInformation(hopNames);
    }

    private String parseContentTypeOid(BerTlv contentTypeField) {
        BerTlv oidSource = contentTypeField;
        if (contentTypeField.constructed()) {
            List<BerTlv> nested = BerCodec.decodeAll(contentTypeField.value());
            oidSource = nested.stream()
                .filter(item -> item.isUniversal() && item.tagNumber() == 6)
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("TransferEnvelope content type does not include an OBJECT IDENTIFIER"));
        }

        if (!oidSource.isUniversal() || oidSource.tagNumber() != 6) {
            throw new IllegalArgumentException("TransferEnvelope content type must be an OBJECT IDENTIFIER");
        }
        return decodeOid(oidSource.value());
    }

    private Date parseFilingTime(List<BerTlv> fields) {
        return parseOptionalFilingTime(fields).orElseGet(() -> Date.from(Instant.now()));
    }

    private Optional<Date> parseOptionalFilingTime(List<BerTlv> fields) {
        Optional<BerTlv> utc = BerCodec.findOptional(fields, 2, 7);
        Optional<BerTlv> generalized = BerCodec.findOptional(fields, 2, 8);

        BerTlv selected = null;
        if (generalized.isPresent()) {
            selected = generalized.get();
        } else if (utc.isPresent()) {
            selected = utc.get();
        }

        if (selected == null) {
            return Optional.empty();
        }

        String value = new String(selected.value(), StandardCharsets.US_ASCII);
        try {
            if (selected.tagNumber() == 8) {
                SimpleDateFormat generalizedFormat = new SimpleDateFormat("yyyyMMddHHmmss'Z'", Locale.ROOT);
                generalizedFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
                return Optional.of(generalizedFormat.parse(value));
            }
            SimpleDateFormat utcFormat = new SimpleDateFormat("yyMMddHHmmss'Z'", Locale.ROOT);
            utcFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
            return Optional.of(utcFormat.parse(value));
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
            .map(this::parseIntegerValue);
    }

    private int parseIntegerValue(BerTlv value) {
        if (value.value().length == 0 || value.value().length > 4) {
            throw new IllegalArgumentException("Invalid BER INTEGER/ENUMERATED length");
        }
        int number = 0;
        for (byte b : value.value()) {
            number = (number << 8) | (b & 0xFF);
        }
        return number;
    }

    private String decodeOid(byte[] encoded) {
        if (encoded.length == 0) {
            throw new IllegalArgumentException("BER OBJECT IDENTIFIER is empty");
        }
        StringBuilder oid = new StringBuilder();
        int first = encoded[0] & 0xFF;
        oid.append(first / 40).append('.').append(first % 40);
        long value = 0;
        for (int i = 1; i < encoded.length; i++) {
            int octet = encoded[i] & 0xFF;
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

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    private AMHSProfile parseProfile(int profileValue) {
        return switch (profileValue) {
            case 0 -> AMHSProfile.P1;
            case 1 -> AMHSProfile.P3;
            case 2 -> AMHSProfile.P7;
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
        Date filingTime,
        TransferEnvelope transferEnvelope
    ) {
    }

    public record TransferEnvelope(
        Optional<MTSIdentifier> mtsIdentifier,
        List<PerRecipientFields> perRecipientFields,
        Optional<TraceInformation> traceInformation,
        Optional<String> contentTypeOid,
        Optional<String> originator,
        Optional<SecurityParameters> securityParameters,
        List<ExtensibilityContainers.UnknownExtension> unknownExtensions
    ) {

        public Optional<String> primaryRecipient() {
            if (perRecipientFields.isEmpty()) {
                return Optional.empty();
            }
            return Optional.ofNullable(perRecipientFields.get(0).recipient());
        }
    }

    public record MTSIdentifier(Optional<String> localIdentifier, Optional<Date> filingTime) {
    }

    public record PerRecipientFields(String recipient, Optional<Integer> responsibility, Optional<Integer> deliveryFlags, List<String> extensionIds) {
    }

    public record TraceInformation(List<String> hops) {
    }
}
