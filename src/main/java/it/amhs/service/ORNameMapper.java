package it.amhs.service;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import it.amhs.asn1.BerCodec;
import it.amhs.asn1.BerTlv;

public final class ORNameMapper {

    private ORNameMapper() {
    }

    public record ORName(Optional<String> directoryName, ORAddress orAddress) {
    }

    public static ORName fromLegacyIa5(String ia5OrAddress) {
        ORAddress parsed = ORAddress.parse(ia5OrAddress);
        return new ORName(Optional.empty(), parsed);
    }

    public static ORName fromAttributes(Map<String, String> attributes, String directoryName) {
        return new ORName(Optional.ofNullable(directoryName), ORAddress.of(new LinkedHashMap<>(attributes)));
    }

    public static ORName fromBer(BerTlv originator) {
        if (!originator.constructed()) {
            return fromLegacyIa5(new String(originator.value(), StandardCharsets.US_ASCII));
        }

        List<BerTlv> fields = BerCodec.decodeAll(originator.value());
        Optional<String> directoryName = Optional.empty();
        Map<String, String> attributes = new LinkedHashMap<>();

        for (BerTlv field : fields) {
            if (field.tagClass() == 2 && field.tagNumber() == 0) {
                directoryName = Optional.of(decodeString(field));
            } else if (field.tagClass() == 2 && field.tagNumber() == 1 && field.constructed()) {
                decodeStructuredAddress(field, attributes);
            } else if (field.tagClass() == 2 && field.tagNumber() == 1) {
                attributes.putAll(ORAddress.parse(decodeString(field)).attributes());
            }
        }

        if (attributes.isEmpty()) {
            throw new IllegalArgumentException("Structured ORName missing O/R address");
        }
        return new ORName(directoryName, ORAddress.of(attributes));
    }

    private static void decodeStructuredAddress(BerTlv field, Map<String, String> attributes) {
        List<BerTlv> nodes = BerCodec.decodeAll(field.value());
        for (BerTlv node : nodes) {
            if (node.constructed()) {
                if (node.tagClass() == 2) {
                    List<BerTlv> children = BerCodec.decodeAll(node.value());
                    if (children.size() == 1 && !children.get(0).constructed()) {
                        attributes.put(mapAddressTag(node.tagClass(), node.tagNumber()), decodeString(children.get(0)));
                        continue;
                    }
                }
                decodeStructuredAddress(node, attributes);
                continue;
            }
            String value = decodeString(node);
            String key = mapAddressTag(node.tagClass(), node.tagNumber());
            attributes.put(key, value);
        }
    }

    private static String mapAddressTag(int tagClass, int tagNumber) {
        if (tagClass == 2) {
            return switch (tagNumber) {
                case 0 -> "C";
                case 1 -> "ADMD";
                case 2 -> "PRMD";
                case 3 -> "O";
                case 4 -> "OU1";
                case 5 -> "OU2";
                case 6 -> "OU3";
                case 7 -> "OU4";
                case 8 -> "CN";
                default -> "EXT-CTX-" + tagNumber;
            };
        }
        return "EXT-TAG-" + tagClass + "-" + tagNumber;
    }

    private static String decodeString(BerTlv tlv) {
        if (tlv.tagClass() == 0 && tlv.tagNumber() == 20) {
            return new String(tlv.value(), StandardCharsets.ISO_8859_1);
        }
        return new String(tlv.value(), StandardCharsets.UTF_8);
    }
}
