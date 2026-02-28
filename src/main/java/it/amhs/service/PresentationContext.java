package it.amhs.service;

import java.util.List;
import java.util.Set;

public record PresentationContext(int identifier, String abstractSyntaxOid, List<String> transferSyntaxOids) {

    public void validate() {
        if (identifier <= 0 || identifier % 2 == 0) {
            throw new IllegalArgumentException("Presentation-context identifier must be an odd positive integer");
        }
        if (abstractSyntaxOid == null || abstractSyntaxOid.isBlank()) {
            throw new IllegalArgumentException("Presentation-context abstract syntax OID is required");
        }
        if (transferSyntaxOids == null || transferSyntaxOids.isEmpty()) {
            throw new IllegalArgumentException("At least one transfer syntax must be provided");
        }
    }

    public static void validateNegotiation(List<PresentationContext> proposed, Set<Integer> acceptedIdentifiers) {
        if (proposed == null || proposed.isEmpty()) {
            throw new IllegalArgumentException("At least one presentation-context proposal is required");
        }
        for (PresentationContext context : proposed) {
            context.validate();
        }
        for (Integer id : acceptedIdentifiers) {
            boolean known = proposed.stream().anyMatch(candidate -> candidate.identifier == id);
            if (!known) {
                throw new IllegalArgumentException("Accepted presentation-context id not proposed: " + id);
            }
        }
    }
}
