package it.amhs.service.relay;

import it.amhs.domain.AMHSMessage;

public interface OutboundP1Client {

    RelayTransferOutcome relay(String endpoint, AMHSMessage message);

    record RelayTransferOutcome(
        boolean accepted,
        String mtsIdentifier,
        String diagnostic,
        java.util.Map<String, RecipientOutcome> recipientOutcomes
    ) {
        private static final int RECIPIENT_STATUS_ACCEPTED = 0;
        private static final int RECIPIENT_STATUS_DEFERRED = 1;

        public static RelayTransferOutcome accepted(String mtsIdentifier) {
            return new RelayTransferOutcome(true, mtsIdentifier, "accepted", java.util.Map.of());
        }

        public boolean hasRecipientFailures() {
            return recipientOutcomes.values().stream().anyMatch(outcome -> outcome.status() > RECIPIENT_STATUS_DEFERRED);
        }

        public boolean hasDeferredRecipients() {
            return recipientOutcomes.values().stream().anyMatch(outcome -> outcome.status() == RECIPIENT_STATUS_DEFERRED);
        }

        public boolean allRecipientsDeferred() {
            return !recipientOutcomes.isEmpty()
                && recipientOutcomes.values().stream().allMatch(outcome -> outcome.status() == RECIPIENT_STATUS_DEFERRED);
        }

        public record RecipientOutcome(int status, String diagnostic) {
        }
    }
}
