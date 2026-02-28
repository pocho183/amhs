package it.amhs.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.Test;

import it.amhs.domain.AMHSMessage;
import it.amhs.domain.AMHSMessageState;
import it.amhs.repository.AMHSMessageRepository;

class OutboundRelayEngineTest {

    @Test
    void detectsLoopFromTrace() {
        assertTrue(OutboundRelayEngine.hasLoop("HUB@ICAO[2026-01-01T00:00:00Z]>X", "HUB", "ICAO"));
    }

    @Test
    void putsMessageInDeadLetterWhenNoRoute() {
        AMHSMessageRepository repo = mock(AMHSMessageRepository.class);
        OutboundP1Client client = mock(OutboundP1Client.class);
        RelayRoutingService routes = new RelayRoutingService("/C=IT/ADMD=ICAO/PRMD=ENAV->mta1:102");
        OutboundRelayEngine engine = new OutboundRelayEngine(repo, routes, client, "LOCAL-MTA", "LOCAL", true, 3);

        AMHSMessage msg = message("/C=FR/ADMD=ICAO/PRMD=DGAC/O=ATC/CN=OPS");
        engine.relaySingle(msg);

        assertEquals(AMHSMessageState.FAILED, msg.getLifecycleState());
        assertEquals("no-route", msg.getDeadLetterReason());
        verify(repo).save(msg);
    }

    @Test
    void defersAndBacksOffOnFailure() {
        AMHSMessageRepository repo = mock(AMHSMessageRepository.class);
        OutboundP1Client client = mock(OutboundP1Client.class);
        doThrow(new IllegalStateException("network")).when(client).relay(any(), any());

        RelayRoutingService routes = new RelayRoutingService("/C=IT/ADMD=ICAO/PRMD=ENAV->mta1:102|mta2:102");
        OutboundRelayEngine engine = new OutboundRelayEngine(repo, routes, client, "LOCAL-MTA", "LOCAL", true, 3);

        AMHSMessage msg = message("/C=IT/ADMD=ICAO/PRMD=ENAV/O=ATC/CN=OPS");
        engine.relaySingle(msg);

        assertEquals(AMHSMessageState.DEFERRED, msg.getLifecycleState());
        assertEquals(1, msg.getRelayAttemptCount());
        verify(repo).save(msg);
    }

    private AMHSMessage message(String recipientOrAddress) {
        AMHSMessage msg = new AMHSMessage();
        msg.setMessageId("MSG-1");
        msg.setSender("/C=IT/ADMD=ICAO/PRMD=ENAV/O=ATC/CN=SRC");
        msg.setRecipient(recipientOrAddress);
        msg.setRecipientOrAddress(recipientOrAddress);
        msg.setBody("TEST");
        msg.setLifecycleState(AMHSMessageState.SUBMITTED);
        return msg;
    }
}
