package it.amhs.service.protocol.acse;

import java.util.List;
import java.util.Optional;

public final class AcseModels {

    private AcseModels() {
    }

    public sealed interface AcseApdu permits AARQApdu, AAREApdu, ABRTApdu, RLRQApdu, RLREApdu {
    }

    public record ApTitle(String objectIdentifier) {
    }

    public record AeQualifier(int value) {
    }

    public record ResultSourceDiagnostic(int source, int diagnostic) {
    }

    public record AARQApdu(
        String applicationContextName,
        Optional<String> callingAeTitle,
        Optional<String> calledAeTitle,
        Optional<ApTitle> callingApTitle,
        Optional<AeQualifier> callingAeQualifier,
        Optional<ApTitle> calledApTitle,
        Optional<AeQualifier> calledAeQualifier,
        Optional<byte[]> authenticationValue,
        Optional<byte[]> userInformation,
        List<String> presentationContextOids
    ) implements AcseApdu {
        public AARQApdu(String applicationContextName, Optional<String> callingAeTitle, Optional<String> calledAeTitle) {
            this(applicationContextName, callingAeTitle, calledAeTitle,
                Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(),
                Optional.empty(), Optional.empty(), List.of());
        }

        public AARQApdu {
            presentationContextOids = List.copyOf(presentationContextOids);
        }
    }

    public record AAREApdu(
        boolean accepted,
        Optional<String> diagnostic,
        Optional<ResultSourceDiagnostic> resultSourceDiagnostic,
        Optional<byte[]> userInformation,
        List<String> presentationContextOids
    ) implements AcseApdu {
        public AAREApdu(boolean accepted, Optional<String> diagnostic) {
            this(accepted, diagnostic, Optional.empty(), Optional.empty(), List.of());
        }

        public AAREApdu {
            presentationContextOids = List.copyOf(presentationContextOids);
        }
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
        AWAITING_AARE_RESPONSE,
        ESTABLISHED,
        AWAITING_RLRE,
        AWAITING_RLRE_RESPONSE,
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
                state = outbound ? AssociationState.AWAITING_AARE : AssociationState.AWAITING_AARE_RESPONSE;
                return;
            }
            if (apdu instanceof AAREApdu aare) {
                if (outbound) {
                    require(state == AssociationState.AWAITING_AARE_RESPONSE,
                        "Outbound AARE only allowed after inbound AARQ");
                } else {
                    require(state == AssociationState.AWAITING_AARE,
                        "Inbound AARE only allowed after outbound AARQ");
                }
                state = aare.accepted() ? AssociationState.ESTABLISHED : AssociationState.CLOSED;
                return;
            }
            if (apdu instanceof RLRQApdu) {
                require(state == AssociationState.ESTABLISHED, "RLRQ only allowed in ESTABLISHED state");
                state = outbound ? AssociationState.AWAITING_RLRE : AssociationState.AWAITING_RLRE_RESPONSE;
                return;
            }
            if (apdu instanceof RLREApdu) {
                if (outbound) {
                    require(state == AssociationState.AWAITING_RLRE_RESPONSE,
                        "Outbound RLRE only allowed after inbound RLRQ");
                } else {
                    require(state == AssociationState.AWAITING_RLRE,
                        "Inbound RLRE only allowed after outbound RLRQ");
                }
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
