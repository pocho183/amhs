package it.amhs.compliance;

import java.util.regex.Pattern;

import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import it.amhs.domain.AMHSChannel;
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

    public void validateCertificateIdentity(AMHSChannel channel, String certificateCn, String certificateOu) {
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

    private boolean isOrAddress(String address) {
        return StringUtils.hasText(address) && OR_ADDRESS.matcher(address.trim().toUpperCase()).matches();
    }
}
