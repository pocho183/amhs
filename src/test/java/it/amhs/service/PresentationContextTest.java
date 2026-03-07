package it.amhs.service;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

import it.amhs.service.protocol.acse.PresentationContext;

class PresentationContextTest {

    @Test
    void shouldAcceptValidNegotiation() {
        List<PresentationContext> proposed = List.of(
            new PresentationContext(1, "2.6.0.1.6.1", List.of("2.1.1")),
            new PresentationContext(3, "2.6.0.1.6.2", List.of("2.1.1"))
        );

        assertDoesNotThrow(() -> PresentationContext.validateNegotiation(proposed, Set.of(1)));
    }

    @Test
    void shouldRejectAcceptedContextNotInProposal() {
        List<PresentationContext> proposed = List.of(new PresentationContext(1, "2.6.0.1.6.1", List.of("2.1.1")));
        assertThrows(IllegalArgumentException.class, () -> PresentationContext.validateNegotiation(proposed, Set.of(3)));
    }

    @Test
    void shouldRejectWhenNoContextAccepted() {
        List<PresentationContext> proposed = List.of(new PresentationContext(1, "2.6.0.1.6.1", List.of("2.1.1")));

        assertThrows(IllegalArgumentException.class, () -> PresentationContext.validateNegotiation(proposed, Set.of()));
    }

    @Test
    void shouldRejectDuplicateProposedIdentifiers() {
        List<PresentationContext> proposed = List.of(
            new PresentationContext(1, "2.6.0.1.6.1", List.of("2.1.1")),
            new PresentationContext(1, "2.6.0.1.6.2", List.of("2.1.1"))
        );

        assertThrows(IllegalArgumentException.class, () -> PresentationContext.validateNegotiation(proposed, Set.of(1)));
    }

    @Test
    void shouldRejectInvalidAcceptedIdentifier() {
        List<PresentationContext> proposed = List.of(new PresentationContext(1, "2.6.0.1.6.1", List.of("2.1.1")));

        assertThrows(IllegalArgumentException.class, () -> PresentationContext.validateNegotiation(proposed, Set.of(2)));
    }
}
