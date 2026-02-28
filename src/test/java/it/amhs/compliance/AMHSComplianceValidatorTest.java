package it.amhs.compliance;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class AMHSComplianceValidatorTest {

    private final AMHSComplianceValidator validator = new AMHSComplianceValidator();

    @Test
    void shouldAcceptWhenCertificateMatchesIcaoUnit() {
        assertDoesNotThrow(() -> validator.validateOrAddressBinding("C=IT;A=ICAO;P=ROMA;O=ENAV;OU1=LIRRZQZX", "LIRRZQZX", null));
    }

    @Test
    void shouldRejectWhenCertificateDoesNotMatchIcaoUnit() {
        assertThrows(IllegalArgumentException.class,
            () -> validator.validateOrAddressBinding("C=IT;A=ICAO;P=ROMA;O=ENAV;OU1=LIRRZQZX", "OTHERCN", "OTHEROU"));
    }
}
