package it.amhs.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;

import org.junit.jupiter.api.Test;

class RFC1006ServiceTest {

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
}
