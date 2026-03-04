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
    void fallsBackToGeneralFailure() {
        assertEquals("X411:31", mapper.map("unexpected-issue", "opaque diagnostics"));
    }
}
