package it.amhs.service;

import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import it.amhs.domain.AMHSDeliveryReport;
import it.amhs.domain.AMHSDeliveryStatus;
import it.amhs.domain.AMHSMessage;
import it.amhs.domain.AMHSMessageState;
import it.amhs.domain.AMHSReportType;
import it.amhs.repository.AMHSDeliveryReportRepository;
import it.amhs.repository.AMHSMessageRepository;

@Service
public class AMHSDeliveryReportService {

    private final AMHSDeliveryReportRepository deliveryReportRepository;
    private final AMHSMessageRepository messageRepository;
    private final AMHSMessageStateMachine stateMachine;
    private final X411DiagnosticMapper diagnosticMapper;

    public AMHSDeliveryReportService(
        AMHSDeliveryReportRepository deliveryReportRepository,
        AMHSMessageRepository messageRepository,
        AMHSMessageStateMachine stateMachine,
        X411DiagnosticMapper diagnosticMapper
    ) {
        this.deliveryReportRepository = deliveryReportRepository;
        this.messageRepository = messageRepository;
        this.stateMachine = stateMachine;
        this.diagnosticMapper = diagnosticMapper;
    }

    public void setReportExpiration(AMHSMessage message) {
        if (message.getTimeoutDr() != null && message.getTimeoutDr() > 0) {
            message.setDrExpirationAt(Date.from(Instant.now().plusSeconds(message.getTimeoutDr())));
        }
    }

    public void createDeliveryReport(AMHSMessage message) {
        AMHSDeliveryReport report = buildReport(
            message,
            message.getRecipient(),
            AMHSReportType.DR,
            AMHSDeliveryStatus.DELIVERED,
            "X411:0",
            null
        );
        deliveryReportRepository.save(report);
    }


    public void handleTransferOutcome(AMHSMessage message, OutboundP1Client.RelayTransferOutcome outcome) {
        if (outcome.accepted() && !outcome.hasRecipientFailures() && !outcome.hasDeferredRecipients()) {
            return;
        }

        if (!outcome.recipientOutcomes().isEmpty()) {
            createRecipientReports(message, outcome);
            return;
        }

        String reason = outcome.diagnostic() == null || outcome.diagnostic().isBlank()
            ? (outcome.hasDeferredRecipients() ? "transfer-deferred" : "transfer-rejected")
            : outcome.diagnostic();
        X411Diagnostic diagnostic = diagnosticMapper.mapDiagnostic(reason, outcome.diagnostic(), null);
        AMHSDeliveryStatus status = diagnostic.transientFailure() || outcome.hasDeferredRecipients()
            ? AMHSDeliveryStatus.DEFERRED
            : AMHSDeliveryStatus.FAILED;
        createNonDeliveryReport(message, reason, diagnostic.toPersistenceCode(), status);
    }

    private void createRecipientReports(AMHSMessage message, OutboundP1Client.RelayTransferOutcome outcome) {
        Map<Integer, String> deferredDiagnostics = new LinkedHashMap<>();

        for (Map.Entry<String, OutboundP1Client.RelayTransferOutcome.RecipientOutcome> entry : outcome.recipientOutcomes().entrySet()) {
            OutboundP1Client.RelayTransferOutcome.RecipientOutcome recipientOutcome = entry.getValue();
            if (recipientOutcome.status() <= 0) {
                continue;
            }

            String reason = resolveRecipientReason(recipientOutcome);
            X411Diagnostic diagnostic = diagnosticMapper.mapDiagnostic(reason, recipientOutcome.diagnostic(), recipientOutcome.status());
            AMHSDeliveryStatus status = diagnostic.transientFailure() || recipientOutcome.status() == 1
                ? AMHSDeliveryStatus.DEFERRED
                : AMHSDeliveryStatus.FAILED;
            createNonDeliveryReportForRecipient(message, entry.getKey(), reason, diagnostic.toPersistenceCode(), status);

            if (status == AMHSDeliveryStatus.DEFERRED) {
                deferredDiagnostics.put(recipientOutcome.status(), reason);
            }
        }

        if (!deferredDiagnostics.isEmpty() && !outcome.hasRecipientFailures()) {
            message.setLastRelayError(deferredDiagnostics.values().iterator().next());
        }
    }

    public Optional<AMHSMessage> resolveByMtsIdentifier(String mtsIdentifier) {
        if (mtsIdentifier == null || mtsIdentifier.isBlank()) {
            return Optional.empty();
        }
        return messageRepository.findByMtsIdentifier(mtsIdentifier.trim());
    }

    public void createNonDeliveryReport(AMHSMessage message, String reason, String diagnosticCode, AMHSDeliveryStatus status) {
        createNonDeliveryReportForRecipient(message, message.getRecipient(), reason, diagnosticCode, status);
    }

    private void createNonDeliveryReportForRecipient(
        AMHSMessage message,
        String recipient,
        String reason,
        String diagnosticCode,
        AMHSDeliveryStatus status
    ) {
        AMHSDeliveryReport report = buildReport(
            message,
            recipient,
            AMHSReportType.NDR,
            status,
            diagnosticCode,
            reason
        );
        deliveryReportRepository.save(report);
    }

    @Scheduled(fixedDelayString = "${amhs.dr.expiration-check-ms:30000}")
    public void expirePendingMessages() {
        Date now = new Date();
        List<AMHSMessage> pending = messageRepository.findByLifecycleStateIn(List.of(
            AMHSMessageState.SUBMITTED,
            AMHSMessageState.TRANSFERRED,
            AMHSMessageState.DEFERRED
        ));

        for (AMHSMessage message : pending) {
            if (message.getDrExpirationAt() == null || !message.getDrExpirationAt().before(now)) {
                continue;
            }
            stateMachine.transition(message, AMHSMessageState.EXPIRED);
            createNonDeliveryReport(message, "transfer-timeout", "X411:16", AMHSDeliveryStatus.EXPIRED);
            stateMachine.transition(message, AMHSMessageState.REPORTED);
            messageRepository.save(message);
        }
    }

    private AMHSDeliveryReport buildReport(
        AMHSMessage message,
        String recipient,
        AMHSReportType reportType,
        AMHSDeliveryStatus status,
        String diagnosticCode,
        String reason
    ) {
        AMHSDeliveryReport report = new AMHSDeliveryReport();
        report.setMessage(message);
        report.setRecipient(recipient == null || recipient.isBlank() ? message.getRecipient() : recipient);
        report.setReportType(reportType);
        report.setDeliveryStatus(status);
        report.setX411DiagnosticCode(diagnosticCode);
        report.setNonDeliveryReason(reason);
        report.setReturnOfContent(shouldReturnContent(message));
        report.setExpiresAt(message.getDrExpirationAt());
        report.setRelatedMtsIdentifier(message.getMtsIdentifier());
        report.setCorrelationToken(buildCorrelationToken(message));
        return report;
    }

    private boolean shouldReturnContent(AMHSMessage message) {
        if (message.getDeliveryReport() != null && message.getDeliveryReport().equalsIgnoreCase("headers")) {
            return false;
        }
        if (message.getDeliveryReport() != null && message.getDeliveryReport().equalsIgnoreCase("full")) {
            return true;
        }
        return message.getIpnRequest() != null && message.getIpnRequest() > 0;
    }

    private String resolveRecipientReason(OutboundP1Client.RelayTransferOutcome.RecipientOutcome outcome) {
        if (outcome.diagnostic() != null && !outcome.diagnostic().isBlank()) {
            return outcome.diagnostic();
        }
        return outcome.status() == 1 ? "recipient-deferred" : "recipient-failed";
    }

    private String buildCorrelationToken(AMHSMessage message) {
        String msgId = message.getMessageId() == null ? "" : message.getMessageId().trim();
        String mts = message.getMtsIdentifier() == null ? "" : message.getMtsIdentifier().trim();
        if (!msgId.isEmpty() && !mts.isEmpty()) {
            return msgId + "::" + mts;
        }
        if (!msgId.isEmpty()) {
            return "MSG::" + msgId;
        }
        if (!mts.isEmpty()) {
            return "MTS::" + mts;
        }
        return null;
    }
}
