package it.amhs.compliance;

import java.util.regex.Pattern;

import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import it.amhs.domain.AMHSProfile;

@Component
public class AMHSComplianceValidator {

    private static final Pattern OR_ADDRESS = Pattern.compile("^[A-Z0-9]{8}$");

    public void validate(String from, String to, String body, AMHSProfile profile) {
        if (!StringUtils.hasText(body) || body.length() > 100_000) {
            throw new IllegalArgumentException("Invalid AMHS body size");
        }

        if (!isOrAddress(from) || !isOrAddress(to)) {
            throw new IllegalArgumentException("AMHS addresses must match 8-char OR-address short form");
        }

        if (profile == null) {
            throw new IllegalArgumentException("AMHS profile is mandatory");
        }
    }

    private boolean isOrAddress(String address) {
        return StringUtils.hasText(address) && OR_ADDRESS.matcher(address.trim().toUpperCase()).matches();
    }
}
