package it.amhs.compliance;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import it.amhs.domain.AMHSChannel;
import it.amhs.domain.AMHSProfile;

@Component
public class AMHSComplianceValidator {

    private static final Pattern ICAO_8_CHAR = Pattern.compile("^[A-Z0-9]{8}$");
    private static final Pattern COUNTRY_CODE = Pattern.compile("^[A-Z]{2}$");

    public void validate(String from, String to, String body, AMHSProfile profile) {
        if (!StringUtils.hasText(body) || body.length() > 100_000) {
            throw new IllegalArgumentException("Invalid AMHS body size");
        }

        validateAddress(from, "from");
        validateAddress(to, "to");

        if (profile == null) {
            throw new IllegalArgumentException("AMHS profile is mandatory");
        }
    }

    public void validateCertificateIdentity(AMHSChannel channel, String certificateCn, String certificateOu) {
        if (!StringUtils.hasText(certificateCn) && !StringUtils.hasText(certificateOu)) {
            return;
        }

        if (StringUtils.hasText(channel.getExpectedCn())) {
            if (!StringUtils.hasText(certificateCn) || !channel.getExpectedCn().equalsIgnoreCase(certificateCn.trim())) {
                throw new IllegalArgumentException("Certificate CN does not match channel policy");
            }
        }

        if (StringUtils.hasText(channel.getExpectedOu())) {
            if (!StringUtils.hasText(certificateOu) || !channel.getExpectedOu().equalsIgnoreCase(certificateOu.trim())) {
                throw new IllegalArgumentException("Certificate OU does not match channel policy");
            }
        }
    }

    private void validateAddress(String address, String fieldName) {
        if (!StringUtils.hasText(address)) {
            throw new IllegalArgumentException("AMHS " + fieldName + " address is mandatory");
        }

        String normalized = address.trim().toUpperCase();

        if (ICAO_8_CHAR.matcher(normalized).matches()) {
            return;
        }

        Map<String, String> orAttributes = parseOrAddress(normalized);

        String country = orAttributes.get("C");
        String admd = orAttributes.get("ADMD");
        String prmd = orAttributes.get("PRMD");
        String organization = orAttributes.get("O");
        String ou1 = orAttributes.get("OU1");

        if (!COUNTRY_CODE.matcher(defaultString(country)).matches()) {
            throw new IllegalArgumentException("AMHS " + fieldName + " O/R address must include valid C (2-letter country code)");
        }
        if (!"ICAO".equalsIgnoreCase(defaultString(admd))) {
            throw new IllegalArgumentException("AMHS " + fieldName + " O/R address must include ADMD/A=ICAO");
        }
        if (!StringUtils.hasText(prmd)) {
            throw new IllegalArgumentException("AMHS " + fieldName + " O/R address must include PRMD/P");
        }
        if (!"AFTN".equalsIgnoreCase(defaultString(organization))) {
            throw new IllegalArgumentException("AMHS " + fieldName + " O/R address must include O=AFTN");
        }
        if (!ICAO_8_CHAR.matcher(defaultString(ou1)).matches()) {
            throw new IllegalArgumentException("AMHS " + fieldName + " O/R address must include OU1 with a valid 8-character ICAO address");
        }
    }

    private Map<String, String> parseOrAddress(String address) {
        Map<String, String> values = new HashMap<>();

        String[] tokens = address.split("/");
        for (String token : tokens) {
            if (!StringUtils.hasText(token) || !token.contains("=")) {
                continue;
            }

            String[] keyValue = token.split("=", 2);
            String key = normalizeKey(keyValue[0]);
            String value = keyValue[1].trim();

            if (StringUtils.hasText(key) && StringUtils.hasText(value)) {
                values.put(key, value);
            }
        }

        return values;
    }

    private String normalizeKey(String rawKey) {
        if (!StringUtils.hasText(rawKey)) {
            return null;
        }

        String key = rawKey.trim().toUpperCase();
        return switch (key) {
            case "A" -> "ADMD";
            case "P" -> "PRMD";
            case "OU" -> "OU1";
            default -> key;
        };
    }

    private String defaultString(String value) {
        return value == null ? "" : value.trim();
    }
}
