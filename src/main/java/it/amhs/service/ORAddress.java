package it.amhs.service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.util.StringUtils;

public final class ORAddress {

    private static final List<String> CANONICAL_ORDER = List.of("C", "ADMD", "PRMD", "O", "OU1", "OU2", "OU3", "OU4", "CN");

    private final Map<String, String> attributes;

    private ORAddress(Map<String, String> attributes) {
        this.attributes = attributes;
    }

    public static ORAddress of(Map<String, String> attrs) {
        Map<String, String> normalized = new LinkedHashMap<>();
        for (String key : CANONICAL_ORDER) {
            String value = attrs.get(key);
            if (StringUtils.hasText(value)) {
                normalized.put(key, value.trim());
            }
        }
        attrs.forEach((key, value) -> {
            if (!normalized.containsKey(key) && StringUtils.hasText(value)) {
                normalized.put(key, value.trim());
            }
        });
        return new ORAddress(normalized);
    }

    public static ORAddress parse(String address) {
        if (!StringUtils.hasText(address)) {
            throw new IllegalArgumentException("O/R address cannot be empty");
        }

        String[] tokens = address.trim().split("/");
        Map<String, String> values = new LinkedHashMap<>();
        for (String token : tokens) {
            if (!StringUtils.hasText(token) || !token.contains("=")) {
                continue;
            }

            String[] keyValue = token.split("=", 2);
            String key = normalizeKey(keyValue[0]);
            String value = keyValue[1].trim();

            if (!StringUtils.hasText(key) || !StringUtils.hasText(value)) {
                continue;
            }
            if (values.containsKey(key)) {
                throw new IllegalArgumentException("Duplicate O/R attribute: " + key);
            }
            values.put(key, value);
        }

        if (values.isEmpty()) {
            throw new IllegalArgumentException("Invalid O/R address format");
        }
        return ORAddress.of(values);
    }

    public String get(String key) {
        return attributes.get(key);
    }

    public List<String> organizationalUnits() {
        List<String> units = new ArrayList<>();
        for (int i = 1; i <= 4; i++) {
            String value = attributes.get("OU" + i);
            if (StringUtils.hasText(value)) {
                units.add(value);
            }
        }
        return units;
    }

    public String toCanonicalString() {
        StringBuilder builder = new StringBuilder();
        for (Map.Entry<String, String> entry : attributes.entrySet()) {
            builder.append('/').append(entry.getKey()).append('=').append(entry.getValue());
        }
        return builder.toString();
    }

    private static String normalizeKey(String rawKey) {
        String key = rawKey == null ? "" : rawKey.trim().toUpperCase();
        return switch (key) {
            case "A" -> "ADMD";
            case "P" -> "PRMD";
            case "OU" -> "OU1";
            default -> key;
        };
    }
}
