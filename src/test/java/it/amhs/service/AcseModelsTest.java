package it.amhs.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Optional;

import org.junit.jupiter.api.Test;

import it.amhs.service.protocol.acse.AcseModels;

class AcseModelsTest {

    @Test
    void shouldDriveAssociationStateMachine() {
        AcseModels.AssociationStateMachine sm = new AcseModels.AssociationStateMachine();
        sm.onOutbound(new AcseModels.AARQApdu("2.6.0.1.6.1", Optional.of("CALLING"), Optional.of("CALLED")));
        assertEquals(AcseModels.AssociationState.AWAITING_AARE, sm.state());
        sm.onInbound(new AcseModels.AAREApdu(true, Optional.empty()));
        assertEquals(AcseModels.AssociationState.ESTABLISHED, sm.state());
        sm.onOutbound(new AcseModels.RLRQApdu(Optional.of("normal")));
        sm.onInbound(new AcseModels.RLREApdu(true));
        assertEquals(AcseModels.AssociationState.CLOSED, sm.state());
    }

    @Test
    void shouldHandleInboundAssociationHandshakeBeforeEstablished() {
        AcseModels.AssociationStateMachine sm = new AcseModels.AssociationStateMachine();

        sm.onInbound(new AcseModels.AARQApdu("2.6.0.1.6.1", Optional.of("CALLING"), Optional.of("CALLED")));
        assertEquals(AcseModels.AssociationState.AWAITING_AARE_RESPONSE, sm.state());

        sm.onOutbound(new AcseModels.AAREApdu(true, Optional.empty()));
        assertEquals(AcseModels.AssociationState.ESTABLISHED, sm.state());
    }

    @Test
    void shouldHandleInboundReleaseHandshake() {
        AcseModels.AssociationStateMachine sm = new AcseModels.AssociationStateMachine();

        sm.onOutbound(new AcseModels.AARQApdu("2.6.0.1.6.1", Optional.of("CALLING"), Optional.of("CALLED")));
        sm.onInbound(new AcseModels.AAREApdu(true, Optional.empty()));

        sm.onInbound(new AcseModels.RLRQApdu(Optional.of("normal")));
        assertEquals(AcseModels.AssociationState.AWAITING_RLRE_RESPONSE, sm.state());

        sm.onOutbound(new AcseModels.RLREApdu(true));
        assertEquals(AcseModels.AssociationState.CLOSED, sm.state());
    }

    @Test
    void shouldRejectInvalidTransition() {
        AcseModels.AssociationStateMachine sm = new AcseModels.AssociationStateMachine();
        assertThrows(IllegalStateException.class, () -> sm.onOutbound(new AcseModels.RLRQApdu(Optional.empty())));
    }
}
