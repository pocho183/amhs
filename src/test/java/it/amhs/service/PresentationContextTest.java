package it.amhs.service;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

class PresentationContextTest {

    @Test
    void shouldRejectAcceptedContextNotInProposal() {
        List<PresentationContext> proposed = List.of(new PresentationContext(1, "2.6.0.1.6.1", List.of("2.1.1")));
        assertThrows(IllegalArgumentException.class, () -> PresentationContext.validateNegotiation(proposed, Set.of(3)));
    }
}
