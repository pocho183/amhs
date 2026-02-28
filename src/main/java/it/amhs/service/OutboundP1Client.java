package it.amhs.service;

import it.amhs.domain.AMHSMessage;

public interface OutboundP1Client {

    RelayTransferOutcome relay(String endpoint, AMHSMessage message);

    record RelayTransferOutcome(
        boolean accepted,
        String mtsIdentifier,
        String diagnostic,
        java.util.Map<String, RecipientOutcome> recipientOutcomes
    ) {
        public static RelayTransferOutcome accepted(String mtsIdentifier) {
            return new RelayTransferOutcome(true, mtsIdentifier, "accepted", java.util.Map.of());
        }

        public record RecipientOutcome(int status, String diagnostic) {
        }
    }
}
