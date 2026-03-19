package it.amhs.service.protocol.acse;

import java.util.List;
import java.util.Optional;
import java.util.Set;

public final class AcseModels {

    private AcseModels() {
    }

    public sealed interface AcseApdu permits AARQApdu, AAREApdu, ABRTApdu, RLRQApdu, RLREApdu {
    }

    public record ApTitle(String objectIdentifier) {
    }

    public record AeQualifier(int value) {
        public AeQualifier {
            if (value < 0) {
                throw new IllegalArgumentException("ACSE AE-qualifier must be non-negative");
            }
        }
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
        List<String> presentationContextOids,
        List<PresentationContext> presentationContexts
    ) implements AcseApdu {
        public AARQApdu(String applicationContextName, Optional<String> callingAeTitle, Optional<String> calledAeTitle) {
            this(applicationContextName, callingAeTitle, calledAeTitle,
                Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(),
                Optional.empty(), Optional.empty(), List.of(), List.of());
        }

        public AARQApdu(
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
        ) {
            this(applicationContextName, callingAeTitle, calledAeTitle, callingApTitle, callingAeQualifier,
                calledApTitle, calledAeQualifier, authenticationValue, userInformation, presentationContextOids, List.of());
        }

        public AARQApdu {
            presentationContextOids = List.copyOf(presentationContextOids);
            validateAeIdentity("calling", callingAeTitle, callingAeQualifier);
            validateAeIdentity("called", calledAeTitle, calledAeQualifier);
        }

        private static void validateAeIdentity(
            String side,
            Optional<String> aeTitle,
            Optional<AeQualifier> aeQualifier
        ) {
            if (aeTitle.isPresent() && aeQualifier.isPresent()) {
                throw new IllegalArgumentException("ACSE " + side + " identity cannot include both AE-title and AE-qualifier");
            }
        }
    }

    public record AAREApdu(
    	    Optional<String> applicationContextName,
    	    boolean accepted,
    	    Optional<String> diagnostic,
    	    Optional<ResultSourceDiagnostic> resultSourceDiagnostic,
    	    Optional<byte[]> userInformation,
    	    List<String> presentationContextOids,
    	    Set<Integer> acceptedPresentationContextIds
    	) implements AcseApdu {
    	    public AAREApdu(boolean accepted, Optional<String> diagnostic) {
    	        this(Optional.empty(), accepted, diagnostic, Optional.empty(), Optional.empty(), List.of(), Set.of());
    	    }

    	    public AAREApdu(
    	        Optional<String> applicationContextName,
    	        boolean accepted,
    	        Optional<String> diagnostic,
    	        Optional<ResultSourceDiagnostic> resultSourceDiagnostic,
    	        Optional<byte[]> userInformation,
    	        List<String> presentationContextOids
    	    ) {
    	        this(applicationContextName, accepted, diagnostic, resultSourceDiagnostic, userInformation, presentationContextOids, Set.of());
    	    }

    	    public AAREApdu {
    	        applicationContextName = applicationContextName == null ? Optional.empty() : applicationContextName;
    	        presentationContextOids = List.copyOf(presentationContextOids);
    	        acceptedPresentationContextIds = Set.copyOf(acceptedPresentationContextIds);
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
