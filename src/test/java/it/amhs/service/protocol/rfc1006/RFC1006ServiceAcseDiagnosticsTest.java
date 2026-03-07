package it.amhs.service.protocol.rfc1006;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import it.amhs.service.protocol.acse.AcseModels;

class RFC1006ServiceAcseDiagnosticsTest {

    private final RFC1006Service service = new RFC1006Service(
        null,
        null,
        null,
        null,
        null,
        "LOCAL-MTA",
        "LOCAL",
        30_000,
        false,
        ""
    );

    @Test
    void shouldMapPresentationDiagnosticToProviderReason() {
        AcseModels.ResultSourceDiagnostic diagnostic = service.mapAarqDiagnostic(
            "ACSE presentation contexts do not negotiate AMHS P1 abstract syntax"
        );

        assertEquals(1, diagnostic.source());
        assertEquals(2, diagnostic.diagnostic());
    }

    @Test
    void shouldMapAuthenticationDiagnosticToRequestorReason() {
        AcseModels.ResultSourceDiagnostic diagnostic = service.mapAarqDiagnostic(
            "ACSE authentication-value verification failed"
        );

        assertEquals(2, diagnostic.source());
        assertEquals(1, diagnostic.diagnostic());
    }

    @Test
    void shouldBuildRejectedAareWithDiagnosticContainer() {
        AcseModels.AAREApdu reject = service.buildRejectedAare("ACSE authentication-value verification failed");

        assertFalse(reject.accepted());
        assertTrue(reject.diagnostic().isPresent());
        assertTrue(reject.resultSourceDiagnostic().isPresent());
        assertEquals(RFC1006Service.ICAO_AMHS_P1_OID, reject.presentationContextOids().get(0));
        assertEquals(2, reject.resultSourceDiagnostic().orElseThrow().source());
        assertEquals(1, reject.resultSourceDiagnostic().orElseThrow().diagnostic());
    }
}
