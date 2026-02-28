package it.amhs.service;

import java.util.Optional;

public final class AcseModels {

    private AcseModels() {
    }

    public sealed interface AcseApdu permits AARQApdu, AAREApdu, ABRTApdu, RLRQApdu, RLREApdu {
    }

    public record AARQApdu(String applicationContextName, Optional<String> callingAeTitle, Optional<String> calledAeTitle) implements AcseApdu {
    }

    public record AAREApdu(boolean accepted, Optional<String> diagnostic) implements AcseApdu {
    }

    public record ABRTApdu(String source, Optional<String> diagnostic) implements AcseApdu {
    }

    public record RLRQApdu(Optional<String> reason) implements AcseApdu {
    }

    public record RLREApdu(boolean normal) implements AcseApdu {
    }

    public enum AssociationState {
        IDLE,
        AWAITING_AARE,
        ESTABLISHED,
        AWAITING_RLRE,
        ABORTED,
        CLOSED
    }

    public static final class AssociationStateMachine {
        private AssociationState state = AssociationState.IDLE;

        public AssociationState state() {
            return state;
        }

        public void onOutbound(AcseApdu apdu) {
            transition(apdu, true);
        }

        public void onInbound(AcseApdu apdu) {
            transition(apdu, false);
        }

        private void transition(AcseApdu apdu, boolean outbound) {
            if (apdu instanceof AARQApdu) {
                require(state == AssociationState.IDLE, "AARQ only allowed in IDLE state");
                state = outbound ? AssociationState.AWAITING_AARE : AssociationState.ESTABLISHED;
                return;
            }
            if (apdu instanceof AAREApdu aare) {
                require(state == AssociationState.AWAITING_AARE || state == AssociationState.ESTABLISHED,
                    "AARE only allowed during association setup");
                state = aare.accepted() ? AssociationState.ESTABLISHED : AssociationState.CLOSED;
                return;
            }
            if (apdu instanceof RLRQApdu) {
                require(state == AssociationState.ESTABLISHED, "RLRQ only allowed in ESTABLISHED state");
                state = AssociationState.AWAITING_RLRE;
                return;
            }
            if (apdu instanceof RLREApdu) {
                require(state == AssociationState.AWAITING_RLRE, "RLRE only allowed after RLRQ");
                state = AssociationState.CLOSED;
                return;
            }
            if (apdu instanceof ABRTApdu) {
                state = AssociationState.ABORTED;
                return;
            }
            throw new IllegalArgumentException("Unsupported ACSE APDU type: " + apdu.getClass().getSimpleName());
        }

        private void require(boolean condition, String message) {
            if (!condition) {
                throw new IllegalStateException(message + ", current=" + state);
            }
        }
    }
}
