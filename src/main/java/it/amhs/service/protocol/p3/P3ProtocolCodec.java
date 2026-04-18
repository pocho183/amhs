package it.amhs.service.protocol.p3;

import it.amhs.service.protocol.p3.P3OperationModels.BindRequest;
import it.amhs.service.protocol.p3.P3OperationModels.BindResult;
import it.amhs.service.protocol.p3.P3OperationModels.P3Error;
import it.amhs.service.protocol.p3.P3OperationModels.ReleaseResult;
import it.amhs.service.protocol.p3.P3OperationModels.SubmitRequest;
import it.amhs.service.protocol.p3.P3OperationModels.SubmitResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class P3ProtocolCodec {

    private static final Logger logger = LoggerFactory.getLogger(P3ProtocolCodec.class);

    private final P3BindCodec bindCodec;
    private final P3SubmitCodec submitCodec;
    private final P3ReleaseCodec releaseCodec;
    private final P3GatewaySessionService sessionService;

    public P3ProtocolCodec(
        P3BindCodec bindCodec,
        P3SubmitCodec submitCodec,
        P3ReleaseCodec releaseCodec,
        P3GatewaySessionService sessionService
    ) {
        this.bindCodec = bindCodec;
        this.submitCodec = submitCodec;
        this.releaseCodec = releaseCodec;
        this.sessionService = sessionService;
    }

    public boolean isSupportedApplicationApdu(byte[] encodedPdu) {
        return bindCodec.isLikelyNativeBind(encodedPdu)
            || submitCodec.isLikelySubmitRequest(encodedPdu)
            || releaseCodec.isLikelyReleaseRequest(encodedPdu);
    }

    public byte[] handle(P3GatewaySessionService.SessionState session, byte[] encodedApdu) {
        try {
            if (bindCodec.isLikelyNativeBind(encodedApdu)) {
                return handleBind(session, encodedApdu);
            }

            if (submitCodec.isLikelySubmitRequest(encodedApdu)) {
                return handleSubmit(session, encodedApdu);
            }

            if (releaseCodec.isLikelyReleaseRequest(encodedApdu)) {
                return handleRelease(session, encodedApdu);
            }

            logger.warn("Unsupported P3 APDU");
            return bindCodec.encodeBindError(
                null,
                new P3Error(
                    "unsupported-operation",
                    "Unsupported P3 operation",
                    false
                )
            );
        } catch (IllegalArgumentException ex) {
            logger.warn("Malformed P3 APDU: {}", ex.getMessage());
            return bindCodec.encodeBindError(
                null,
                new P3Error(
                    "malformed-apdu",
                    ex.getMessage(),
                    false
                )
            );
        }
    }

    private byte[] handleBind(P3GatewaySessionService.SessionState session, byte[] encodedApdu) {
        BindRequest request = bindCodec.decodeBindRequest(encodedApdu);

        String command = "BIND"
            + " username=" + value(request.authenticatedIdentity())
            + ";password=" + value(request.password())
            + ";sender=" + value(request.senderOrAddress())
            + ";channel=" + request.requestedChannel().orElse("");

        String response = sessionService.handleCommand(session, command);

        if (response.startsWith("OK")) {
            String sender = parseField(response, "sender", request.senderOrAddress());
            String channel = parseField(response, "channel", request.requestedChannel().orElse(""));

            return bindCodec.encodeBindResult(
                request.originalApdu(),
                new BindResult(sender, channel)
            );
        }

        return bindCodec.encodeBindError(
            request.originalApdu(),
            toError(response)
        );
    }

    private byte[] handleSubmit(P3GatewaySessionService.SessionState session, byte[] encodedApdu) {
        SubmitRequest request = submitCodec.decodeSubmitRequest(encodedApdu);

        String command = "SUBMIT"
            + " recipient=" + value(request.recipientOrAddress())
            + ";subject=" + value(request.subject())
            + ";body=" + value(request.body());

        String response = sessionService.handleCommand(session, command);

        if (response.startsWith("OK")) {
            String submissionId = parseField(response, "submission-id", "");
            String messageId = parseField(response, "message-id", "");
            return submitCodec.encodeSubmitResult(new SubmitResult(submissionId, messageId));
        }

        return submitCodec.encodeSubmitError(toError(response));
    }

    private byte[] handleRelease(P3GatewaySessionService.SessionState session, byte[] encodedApdu) {
        releaseCodec.decodeReleaseRequest(encodedApdu);

        String response = sessionService.handleCommand(session, "UNBIND");
        if (response.startsWith("OK")) {
            return releaseCodec.encodeReleaseResult(new ReleaseResult());
        }

        return releaseCodec.encodeReleaseError(toError(response));
    }

    private P3Error toError(String response) {
        String code = parseField(response, "code", "gateway");
        String detail = parseField(response, "detail", response);
        boolean retryable =
            "interrupted".equals(code)
                || "routing-policy".equals(code)
                || "resource-exhausted".equals(code)
                || "temporarily-unavailable".equals(code)
                || "transient-failure".equals(code)
                || "timeout".equals(code);

        return new P3Error(code, detail, retryable);
    }

    private String parseField(String response, String key, String fallback) {
        if (response == null || response.isBlank()) {
            return fallback;
        }

        String[] tokens = response.split("\\s+");
        for (String token : tokens) {
            int idx = token.indexOf('=');
            if (idx > 0 && idx < token.length() - 1 && key.equals(token.substring(0, idx))) {
                return token.substring(idx + 1);
            }
        }

        return fallback;
    }

    private String value(String maybeNull) {
        return maybeNull == null ? "" : maybeNull;
    }
}