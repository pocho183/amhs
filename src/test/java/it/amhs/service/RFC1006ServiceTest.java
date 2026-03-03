package it.amhs.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;

class RFC1006ServiceTest {

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
    void shouldAppendLocalTraceHopToExistingTrace() {
        Instant arrival = Instant.parse("2026-02-28T12:30:45Z");

        String trace = RFC1006Service.appendTraceHop("MTA1>MTA2", arrival, "LIMMZQZX", "ICAO");

        assertEquals("MTA1>MTA2>LIMMZQZX@ICAO[2026-02-28T12:30:45Z]", trace);
    }

    @Test
    void shouldCreateTraceWhenIncomingTraceMissing() {
        Instant arrival = Instant.parse("2026-02-28T13:00:00Z");

        String trace = RFC1006Service.appendTraceHop(null, arrival, "", "");

        assertTrue(trace.startsWith("LOCAL-MTA@LOCAL[2026-02-28T13:00:00Z]"));
    }

    @Test
    void shouldAcceptLegacyClass0OptionsValue() {
        service.validateClassNegotiation(0x0A);
    }

    @Test
    void shouldRejectNonClass0Negotiation() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> service.validateClassNegotiation(4));
        assertTrue(ex.getMessage().contains("only class 0"));
    }

    @Test
    void shouldRejectAarqWithoutPresentationContext() {
        AcseModels.AARQApdu aarq = new AcseModels.AARQApdu(
            RFC1006Service.ICAO_AMHS_P1_OID,
            Optional.of("LIMMZQZX"),
            Optional.of("DEST"),
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            List.of()
        );

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
            () -> service.validateAarqForAmhsP1(aarq, "LIMMZQZX", null));
        assertTrue(ex.getMessage().contains("presentation"));
    }

    @Test
    void shouldValidateAarqContextPresentationAndCertificateBinding() {
        AcseModels.AARQApdu aarq = new AcseModels.AARQApdu(
            RFC1006Service.ICAO_AMHS_P1_OID,
            Optional.of("LIMMZQZX"),
            Optional.of("DEST"),
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            List.of(RFC1006Service.ICAO_AMHS_P1_OID)
        );

        service.validateAarqForAmhsP1(aarq, "LIMMZQZX", null);
    }
}
