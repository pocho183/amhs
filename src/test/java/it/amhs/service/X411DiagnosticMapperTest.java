package it.amhs.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class X411DiagnosticMapperTest {

    private final X411DiagnosticMapper mapper = new X411DiagnosticMapper();

    @Test
    void prefersExplicitX411Code() {
        assertEquals("X411:16", mapper.map("X411:16", "timeout"));
    }

    @Test
    void mapsTimeoutKeywordsToTimeoutCode() {
        assertEquals("X411:16", mapper.map("transfer timed out", null));
    }

    @Test
    void mapsRoutingFailureToUnreachableCode() {
        X411Diagnostic diagnostic = mapper.mapDiagnostic("no-route", "peer unreachable", 2);
        assertEquals(X411Diagnostic.ReasonCode.ROUTING_FAILURE, diagnostic.reasonCode());
        assertEquals("X411:22", diagnostic.toPersistenceCode());
    }

    @Test
    void mapsStructuredReasonAndDiagnosticCodeFields() {
        X411Diagnostic diagnostic = mapper.mapDiagnostic("reason-code=9", "diagnostic-code=28; supplemental-info=congestion", 1);
        assertEquals(X411Diagnostic.ReasonCode.CONGESTION, diagnostic.reasonCode());
        assertTrue(diagnostic.transientFailure());
        assertEquals("X411:28", diagnostic.toPersistenceCode());
    }

    @Test
    void supportsExpandedReasonKeywords() {
        assertEquals(
            X411Diagnostic.ReasonCode.CONVERSION_NOT_PERFORMED,
            mapper.mapDiagnostic("conversion-not-performed", "cannot downgrade body part", null).reasonCode()
        );
        assertEquals(
            X411Diagnostic.ReasonCode.CONTENT_TOO_LARGE,
            mapper.mapDiagnostic("content-too-large", "size exceeded", null).reasonCode()
        );
        assertEquals(
            X411Diagnostic.ReasonCode.RECIPIENT_UNAVAILABLE,
            mapper.mapDiagnostic("recipient-unavailable", "mailbox locked", null).reasonCode()
        );
    }

    @Test
    void normalizesInvalidDiagnosticCodesToDefault() {
        assertEquals("X411:31", mapper.map("reason-code=9", "diagnostic-code=999"));
    }

    @Test
    void fallsBackToGeneralFailure() {
        assertEquals("X411:31", mapper.map("unexpected-issue", "opaque diagnostics"));
    }
}
