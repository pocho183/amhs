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

    @Test
    void shouldRejectAarqWithBothAeTitleAndAeQualifierOnSameSide() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> new AcseModels.AARQApdu(
            "2.6.0.1.6.1",
            Optional.of("CALLING"),
            Optional.empty(),
            Optional.of(new AcseModels.ApTitle("1.3.27.1")),
            Optional.of(new AcseModels.AeQualifier(7)),
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            Optional.of("bind-info".getBytes()),
            java.util.List.of("2.6.0.1.6.1")
        ));

        assertEquals("ACSE calling identity cannot include both AE-title and AE-qualifier", ex.getMessage());
    }

    @Test
    void shouldRejectNegativeAeQualifier() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
            () -> new AcseModels.AeQualifier(-1));
        assertEquals("ACSE AE-qualifier must be non-negative", ex.getMessage());
    }
}
