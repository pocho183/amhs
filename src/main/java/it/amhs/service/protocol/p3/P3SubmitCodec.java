package it.amhs.service.protocol.p3;

import static it.amhs.service.protocol.p3.P3WireSupport.*;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import it.amhs.asn1.BerCodec;
import it.amhs.asn1.BerTlv;
import it.amhs.service.protocol.p3.P3OperationModels.P3Error;
import it.amhs.service.protocol.p3.P3OperationModels.SubmitRequest;
import it.amhs.service.protocol.p3.P3OperationModels.SubmitResult;

@Component
public class P3SubmitCodec {

    private static final int SUBMIT_REQUEST_TAG = 2;
    private static final int SUBMIT_RESPONSE_TAG = 3;
    private static final int ERROR_TAG = 8;
    private static final DateTimeFormatter X400_TIME_FORMAT = DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);

    public boolean isLikelySubmitRequest(byte[] encodedApdu) {
        if (encodedApdu == null || encodedApdu.length == 0) {
            return false;
        }

        try {
            BerTlv apdu = BerCodec.decodeSingle(encodedApdu);

            if (apdu.tagClass() == TAG_CLASS_CONTEXT
                && apdu.constructed()
                && apdu.tagNumber() == SUBMIT_REQUEST_TAG) {
                return true;
            }

            // Real P3 submit argument inside ROS invoke:
            // 30 82 ... = SEQUENCE
            return apdu.tagClass() == TAG_CLASS_UNIVERSAL
                && apdu.constructed()
                && apdu.tagNumber() == 16
                && encodedApdu.length > 80;

        } catch (RuntimeException ex) {
            return false;
        }
    }

    public SubmitRequest decodeSubmitRequest(byte[] encodedApdu) {
        BerTlv apdu = BerCodec.decodeSingle(encodedApdu);

        if (apdu.tagClass() == TAG_CLASS_CONTEXT
            && apdu.constructed()
            && apdu.tagNumber() == SUBMIT_REQUEST_TAG) {

            Map<Integer, String> fields = decodeContextUtf8Fields(apdu.value());

            return new SubmitRequest(
                value(fields.get(0)),
                value(fields.get(1)),
                value(fields.get(2)),
                encodedApdu
            );
        }

        if (apdu.tagClass() == TAG_CLASS_UNIVERSAL
            && apdu.constructed()
            && apdu.tagNumber() == 16) {

            List<String> orAddresses = new ArrayList<>();
            collectOrAddresses(apdu, orAddresses);

            String recipient = orAddresses.size() >= 2 ? orAddresses.get(1) : "";
            String subject = "";
            String body = extractBodyText(apdu);
            return new SubmitRequest(recipient, subject, body, encodedApdu);
        }
        throw new IllegalArgumentException("Not a submit request APDU");
    }
    
    private String extractBodyText(BerTlv root) {
        List<String> texts = new ArrayList<>();
        collectBodyText(root, texts);

        return texts.stream()
            .filter(s -> s.length() > 8)
            .filter(s -> !s.startsWith("KH"))
            .filter(s -> !s.equals("ICAO"))
            .filter(s -> !s.equals("Local"))
            .filter(s -> !s.equals("technosky"))
            .filter(s -> !s.startsWith("VDTI"))
            .reduce((a, b) -> a.length() >= b.length() ? a : b)
            .orElse("");
    }

    private void collectBodyText(BerTlv node, List<String> out) {
        if (node == null) {
            return;
        }

        try {
            if (!node.constructed()) {
                int tag = node.tagNumber();

                // UTF8String, PrintableString, IA5String, VisibleString, GeneralString
                if (tag == 12 || tag == 19 || tag == 22 || tag == 26 || tag == 27) {
                    String text = new String(node.value(), java.nio.charset.StandardCharsets.UTF_8).trim();
                    if (!text.isBlank()) {
                        out.add(text);
                    }
                }

                // OCTET STRING may contain nested BER body content
                if (tag == 4 && node.value() != null && node.value().length > 2) {
                    try {
                        BerTlv nested = BerCodec.decodeSingle(node.value());
                        collectBodyText(nested, out);
                    } catch (RuntimeException ignored) {
                        String raw = new String(node.value(), java.nio.charset.StandardCharsets.UTF_8).trim();
                        if (!raw.isBlank()) {
                            out.add(raw);
                        }
                    }
                }

                return;
            }

            for (BerTlv child : BerCodec.decodeAll(node.value())) {
                collectBodyText(child, out);
            }
        } catch (RuntimeException ignored) {
        }
    }
    
    private void collectOrAddresses(BerTlv node, List<String> out) {
        if (node == null || !node.constructed()) {
            return;
        }

        try {
            List<BerTlv> children = BerCodec.decodeAll(node.value());
            Map<String, String> attrs = new HashMap<>();

            for (BerTlv child : children) {
                String text = firstText(child);
                if (text == null || text.isBlank()) {
                    continue;
                }

                int cls = child.tagClass();
                int tag = child.tagNumber();

                // From your BER:
                // 61 -> C
                // 62 -> ADMD
                // A2 -> PRMD
                // 83 -> O
                // A6 -> OU1
                if (cls == TAG_CLASS_APPLICATION && tag == 1) {
                    attrs.put("C", text);
                } else if (cls == TAG_CLASS_APPLICATION && tag == 2) {
                    attrs.put("ADMD", text);
                } else if (cls == TAG_CLASS_CONTEXT && tag == 2) {
                    attrs.put("PRMD", text);
                } else if (cls == TAG_CLASS_CONTEXT && tag == 3) {
                    attrs.put("O", text);
                } else if (cls == TAG_CLASS_CONTEXT && tag == 6) {
                    attrs.put("OU1", text);
                }
            }

            if (attrs.containsKey("C") && attrs.containsKey("ADMD")) {
                String addr =
                    "/C=" + attrs.getOrDefault("C", "") +
                    "/ADMD=" + attrs.getOrDefault("ADMD", "") +
                    "/PRMD=" + attrs.getOrDefault("PRMD", "") +
                    "/O=" + attrs.getOrDefault("O", "") +
                    "/OU1=" + attrs.getOrDefault("OU1", "");

                if (!out.contains(addr)) {
                    out.add(addr);
                }
            }

            for (BerTlv child : children) {
                collectOrAddresses(child, out);
            }
        } catch (RuntimeException ignored) {
        }
    }

    private String firstText(BerTlv node) {
        if (node == null) {
            return null;
        }

        try {
            if (!node.constructed()) {
                int cls = node.tagClass();
                int tag = node.tagNumber();

                if (tag == 12 || tag == 19 || tag == 22 || tag == 26 || tag == 27) {
                    return new String(node.value(), java.nio.charset.StandardCharsets.UTF_8);
                }

                // Needed for O=technosky: 83 09 ...
                if (cls == TAG_CLASS_CONTEXT && node.value() != null && node.value().length > 0) {
                    return new String(node.value(), java.nio.charset.StandardCharsets.UTF_8);
                }

                return null;
            }

            for (BerTlv child : BerCodec.decodeAll(node.value())) {
                String text = firstText(child);
                if (text != null && !text.isBlank()) {
                    return text;
                }
            }
        } catch (RuntimeException ignored) {
        }

        return null;
    }

    public byte[] encodeSubmitResult(SubmitResult result) {
        String id = StringUtils.hasText(result.internalMessageId())
            ? result.internalMessageId()
            : result.submissionId();

        byte[] opCode = BerCodec.encode(
            new BerTlv(TAG_CLASS_UNIVERSAL, false, 2, 0, 1, new byte[] { 0x03 })
        );

        byte[] mtsResult = encodeMtsResult(id);

        byte[] resultValue = concat(List.of(opCode, mtsResult));

        return BerCodec.encode(
            new BerTlv(TAG_CLASS_UNIVERSAL, true, 16, 0, resultValue.length, resultValue)
        );
    }
    
    private byte[] encodeMtsResult(String id) {
        String safe = StringUtils.hasText(id) ? id : UUID.randomUUID().toString();

        byte[] localIdString = BerCodec.encode(
            new BerTlv(
                TAG_CLASS_UNIVERSAL,
                false,
                19,
                0,
                safe.length(),
                safe.getBytes(StandardCharsets.US_ASCII)
            )
        );

        byte[] localId = BerCodec.encode(
            new BerTlv(
                TAG_CLASS_APPLICATION,
                true,
                3,
                0,
                localIdString.length,
                localIdString
            )
        );

        byte[] submissionId = BerCodec.encode(
            new BerTlv(
                TAG_CLASS_CONTEXT,
                true,
                0,
                0,
                localId.length,
                localId
            )
        );

        String timestamp = X400_TIME_FORMAT.format(Instant.now());
        byte[] submissionTime = BerCodec.encode(
            new BerTlv(
                TAG_CLASS_CONTEXT,
                false,
                1,
                0,
                timestamp.length(),
                timestamp.getBytes(StandardCharsets.US_ASCII)
            )
        );

        byte[] submissionIdentifierValue = concat(List.of(submissionId, submissionTime));

        byte[] submissionIdentifier = BerCodec.encode(
            new BerTlv(
                TAG_CLASS_APPLICATION,
                true,
                4,
                0,
                submissionIdentifierValue.length,
                submissionIdentifierValue
            )
        );

        return BerCodec.encode(
            new BerTlv(
                TAG_CLASS_UNIVERSAL,
                true,
                17,
                0,
                submissionIdentifier.length,
                submissionIdentifier
            )
        );
    }

    public byte[] encodeSubmitError(P3Error error) {
        List<byte[]> fields = new ArrayList<>();
        fields.add(encodeUtf8ContextField(0, error.code()));
        fields.add(encodeUtf8ContextField(1, error.detail()));
        fields.add(encodeUtf8ContextField(2, Boolean.toString(error.retryable())));

        byte[] payload = concat(fields);
        return BerCodec.encode(new BerTlv(TAG_CLASS_CONTEXT, true, ERROR_TAG, 0, payload.length, payload));
    }

    private Map<Integer, String> decodeContextUtf8Fields(byte[] payload) {
        Map<Integer, String> values = new HashMap<>();
        for (BerTlv field : decodeContextFieldList(payload)) {
            if (field.tagClass() != TAG_CLASS_CONTEXT) {
                continue;
            }

            if (field.constructed()) {
                List<String> atoms = collectTextualAtoms(field);
                if (!atoms.isEmpty()) {
                    values.put(field.tagNumber(), atoms.get(0));
                }
            } else {
                values.put(field.tagNumber(), new String(field.value(), java.nio.charset.StandardCharsets.UTF_8));
            }
        }
        return values;
    }

    private String value(String maybeNull) {
        return maybeNull == null ? "" : maybeNull;
    }
}