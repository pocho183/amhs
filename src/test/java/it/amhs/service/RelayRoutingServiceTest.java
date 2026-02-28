package it.amhs.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class RelayRoutingServiceTest {

    @Test
    void selectsNextHopAndAlternatesWithAttempts() {
        RelayRoutingService service = new RelayRoutingService("/C=IT/ADMD=ICAO/PRMD=ENAV->mta1:102|mta2:102");
        RelayRoutingService.AMHSMessageEnvelope envelope = new RelayRoutingService.AMHSMessageEnvelope(
            ORAddress.parse("/C=IT/ADMD=ICAO/PRMD=ENAV/O=ATS/CN=AFTN"),
            null
        );

        String first = service.findNextHop(envelope, 0).orElseThrow().endpoint();
        String second = service.findNextHop(envelope, 1).orElseThrow().endpoint();

        assertEquals("mta1:102", first);
        assertEquals("mta2:102", second);
    }

    @Test
    void noMatchingRouteReturnsEmpty() {
        RelayRoutingService service = new RelayRoutingService("/C=IT/ADMD=ICAO/PRMD=ENAV->mta1:102");
        RelayRoutingService.AMHSMessageEnvelope envelope = new RelayRoutingService.AMHSMessageEnvelope(
            ORAddress.parse("/C=FR/ADMD=ICAO/PRMD=DSNA/O=ATC/CN=OPS"),
            null
        );

        assertTrue(service.findNextHop(envelope, 0).isEmpty());
    }
}
