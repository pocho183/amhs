package it.amhs.compliance;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class AMHSComplianceValidatorTest {

    private final AMHSComplianceValidator validator = new AMHSComplianceValidator();

    @Test
    void shouldAcceptWhenCertificateMatchesIcaoUnitInOu() {
        assertDoesNotThrow(() -> validator.validateOrAddressBinding("C=IT;A=ICAO;P=ROMA;O=ENAV;OU1=LIRRZQZX", "LIRRZQZX", null));
    }

    @Test
    void shouldAcceptWhenIcaoUnitIsInOrganization() {
        assertDoesNotThrow(() -> validator.validate("C=IT;A=ICAO;P=ROMA;O=LIRRZQZX;OU1=ENAV", "LIRRZQZX", "body", it.amhs.domain.AMHSProfile.P1));
    }

    @Test
    void shouldAcceptWhenIcaoUnitIsInCommonName() {
        assertDoesNotThrow(() -> validator.validate("C=IT;A=ICAO;P=ROMA;O=ENAV;OU1=OPS;CN=LIRRZQZX", "LIRRZQZX", "body", it.amhs.domain.AMHSProfile.P1));
    }

    @Test
    void shouldRejectWhenCertificateDoesNotMatchIcaoUnit() {
        assertThrows(IllegalArgumentException.class,
            () -> validator.validateOrAddressBinding("C=IT;A=ICAO;P=ROMA;O=ENAV;OU1=LIRRZQZX", "OTHERCN", "OTHEROU"));
    }
}
