package it.amhs.compliance;

import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import it.amhs.domain.AMHSChannel;
import it.amhs.domain.AMHSProfile;
import it.amhs.service.ORAddress;

@Component
public class AMHSComplianceValidator {

    private static final Pattern ICAO_8_CHAR = Pattern.compile("^[A-Z0-9]{8}$");
    private static final Set<String> ISO_COUNTRIES = Set.of(Locale.getISOCountries());

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

        String normalized = address.trim().toUpperCase(Locale.ROOT);

        if (ICAO_8_CHAR.matcher(normalized).matches()) {
            return;
        }

        ORAddress orAddress = ORAddress.parse(normalized);

        String country = normalized(orAddress.get("C"));
        String admd = normalized(orAddress.get("ADMD"));
        String prmd = normalized(orAddress.get("PRMD"));
        String organization = normalized(orAddress.get("O"));

        if (!ISO_COUNTRIES.contains(country)) {
            throw new IllegalArgumentException("AMHS " + fieldName + " O/R address must include a valid ISO country code");
        }
        if (!"ICAO".equals(admd)) {
            throw new IllegalArgumentException("AMHS " + fieldName + " O/R address must include ADMD/A=ICAO");
        }
        if (!StringUtils.hasText(prmd)) {
            throw new IllegalArgumentException("AMHS " + fieldName + " O/R address must include PRMD/P");
        }
        if (!StringUtils.hasText(organization)) {
            throw new IllegalArgumentException("AMHS " + fieldName + " O/R address must include O");
        }

        if (orAddress.organizationalUnits().isEmpty()) {
            throw new IllegalArgumentException("AMHS " + fieldName + " O/R address must include at least OU1");
        }

        boolean hasIcao = orAddress.organizationalUnits().stream()
            .map(this::normalized)
            .anyMatch(unit -> ICAO_8_CHAR.matcher(unit).matches());
        if (!hasIcao) {
            throw new IllegalArgumentException("AMHS " + fieldName + " O/R address must contain an 8-character ICAO unit in OU1-OU4");
        }

        ensureOrderedOu(orAddress, fieldName);
    }

    private void ensureOrderedOu(ORAddress orAddress, String fieldName) {
        Set<String> presentKeys = Set.of("OU1", "OU2", "OU3", "OU4").stream()
            .filter(key -> StringUtils.hasText(orAddress.get(key)))
            .collect(Collectors.toSet());

        for (int i = 2; i <= 4; i++) {
            if (presentKeys.contains("OU" + i) && !presentKeys.contains("OU" + (i - 1))) {
                throw new IllegalArgumentException("AMHS " + fieldName + " O/R address must not skip OU levels");
            }
        }
    }

    private String normalized(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }
}
