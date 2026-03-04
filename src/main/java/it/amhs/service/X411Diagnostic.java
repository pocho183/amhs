package it.amhs.service;

import java.util.Arrays;

public record X411Diagnostic(ReasonCode reasonCode, int diagnosticCode) {

    public static X411Diagnostic of(ReasonCode reasonCode, int diagnosticCode) {
        ReasonCode resolvedReason = reasonCode == null ? ReasonCode.UNABLE_TO_TRANSFER : reasonCode;
        int resolvedDiagnostic = Math.max(0, diagnosticCode);
        return new X411Diagnostic(resolvedReason, resolvedDiagnostic);
    }

    public boolean transientFailure() {
        return reasonCode.transientFailure;
    }

    public String toPersistenceCode() {
        return "X411:" + diagnosticCode;
    }

    public enum ReasonCode {
        UNABLE_TO_TRANSFER(0, false),
        ROUTING_FAILURE(1, false),
        CONGESTION(2, true),
        LOOP_DETECTED(3, false),
        SECURITY_FAILURE(4, false),
        CONTENT_SYNTAX_ERROR(5, false);

        private final int code;
        private final boolean transientFailure;

        ReasonCode(int code, boolean transientFailure) {
            this.code = code;
            this.transientFailure = transientFailure;
        }

        public int code() {
            return code;
        }

        public static ReasonCode fromCode(int code) {
            return Arrays.stream(values())
                .filter(value -> value.code == code)
                .findFirst()
                .orElse(UNABLE_TO_TRANSFER);
        }
    }
}
