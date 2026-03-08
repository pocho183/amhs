package it.amhs.compliance;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import it.amhs.service.protocol.p1.ExtensibilityContainers.SecurityParameters;

class SecurityLabelPolicyTest {

    private final SecurityLabelPolicy policy = new SecurityLabelPolicy();

    @Test
    void shouldAcceptDoc9880StyleLabelAndTokenOid() {
        SecurityParameters params = new SecurityParameters("SECRET|EUR|ATFM", "TOKEN-1", "1.2.840.113549.1.1.1");
        policy.validate(params);
    }

    @Test
    void shouldRejectUnknownClassification() {
        SecurityParameters params = new SecurityParameters("COSMIC TOP SECRET", "TOKEN-1", "1.2.840.113549.1.1.1");
        assertThrows(IllegalArgumentException.class, () -> policy.validate(params));
    }

    @Test
    void shouldRejectCompartmentsForUnclassified() {
        SecurityParameters params = new SecurityParameters("UNCLASSIFIED|ATFM", "TOKEN-1", "1.2.840.113549.1.1.1");
        assertThrows(IllegalArgumentException.class, () -> policy.validate(params));
    }

    @Test
    void shouldApplyDominanceSemantics() {
        assertTrue(policy.dominates("SECRET|ATFM|EUR", "CONFIDENTIAL|ATFM"));
        assertFalse(policy.dominates("CONFIDENTIAL|ATFM", "SECRET|ATFM"));
        assertFalse(policy.dominates("SECRET|ATFM", "SECRET|ATFM|EUR"));
    }


    @Test
    void shouldRejectInvalidCompartmentToken() {
        SecurityParameters params = new SecurityParameters("SECRET|A", "TOKEN-1", "1.2.840.113549.1.1.1");
        assertThrows(IllegalArgumentException.class, () -> policy.validate(params));
    }

    @Test
    void shouldNormalizeCaseAndWhitespaceForDoc9880Labels() {
        SecurityParameters params = new SecurityParameters("  secret | atfm | eur ", "TOKEN-1", "1.2.840.113549.1.1.1");
        assertTrue(policy.dominates(params.securityLabel(), "CONFIDENTIAL|ATFM"));
    }

}
