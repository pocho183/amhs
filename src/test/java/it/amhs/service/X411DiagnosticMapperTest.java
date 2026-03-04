package it.amhs.service;

import static org.junit.jupiter.api.Assertions.assertEquals;

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
        assertEquals("X411:22", mapper.map("no-route", "peer unreachable"));
    }

    @Test
    void mapsStructuredDiagnosticCodeField() {
        assertEquals("X411:28", mapper.map("reason-code=1", "diagnostic-code=28; supplemental-info=congestion"));
    }


    @Test
    void fallsBackToGeneralFailure() {
        assertEquals("X411:31", mapper.map("unexpected-issue", "opaque diagnostics"));
    }
}
