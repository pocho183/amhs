package it.amhs.service;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

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
}
