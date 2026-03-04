package it.amhs.service;

import java.util.Arrays;

public record X411Diagnostic(ReasonCode reasonCode, int diagnosticCode) {

    public static final int MIN_DIAGNOSTIC_CODE = 0;
    public static final int MAX_DIAGNOSTIC_CODE = 127;
    public static final int DEFAULT_DIAGNOSTIC_CODE = 31;

    public static X411Diagnostic of(ReasonCode reasonCode, int diagnosticCode) {
        ReasonCode resolvedReason = reasonCode == null ? ReasonCode.UNABLE_TO_TRANSFER : reasonCode;
        int resolvedDiagnostic = isValidDiagnosticCode(diagnosticCode) ? diagnosticCode : DEFAULT_DIAGNOSTIC_CODE;
        return new X411Diagnostic(resolvedReason, resolvedDiagnostic);
    }

    public static boolean isValidDiagnosticCode(int diagnosticCode) {
        return diagnosticCode >= MIN_DIAGNOSTIC_CODE && diagnosticCode <= MAX_DIAGNOSTIC_CODE;
    }

    public boolean transientFailure() {
        return reasonCode.transientFailure;
    }

    public String toPersistenceCode() {
        return "X411:" + diagnosticCode;
    }

    public enum ReasonCode {
        UNABLE_TO_TRANSFER(0, false),
        TRANSFER_IMPOSSIBLE(1, false),
        CONVERSION_NOT_PERFORMED(2, false),
        CONTENT_TOO_LARGE(3, false),
        RECIPIENT_UNAVAILABLE(4, true),
        LOOP_DETECTED(5, false),
        SECURITY_FAILURE(6, false),
        CONTENT_SYNTAX_ERROR(7, false),
        ROUTING_FAILURE(8, false),
        CONGESTION(9, true),
        DISTRIBUTION_LIST_EXPANSION_PROHIBITED(10, false),
        REDIRECTION_LOOP_DETECTED(11, false),
        ALTERNATE_RECIPIENT_NOT_ALLOWED(12, false);

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
