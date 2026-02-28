package it.amhs.service;

import java.time.Instant;
import java.util.Date;
import java.util.List;

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

    public AMHSDeliveryReportService(
        AMHSDeliveryReportRepository deliveryReportRepository,
        AMHSMessageRepository messageRepository,
        AMHSMessageStateMachine stateMachine
    ) {
        this.deliveryReportRepository = deliveryReportRepository;
        this.messageRepository = messageRepository;
        this.stateMachine = stateMachine;
    }

    public void setReportExpiration(AMHSMessage message) {
        if (message.getTimeoutDr() != null && message.getTimeoutDr() > 0) {
            message.setDrExpirationAt(Date.from(Instant.now().plusSeconds(message.getTimeoutDr())));
        }
    }

    public void createDeliveryReport(AMHSMessage message) {
        AMHSDeliveryReport report = buildReport(
            message,
            AMHSReportType.DR,
            AMHSDeliveryStatus.DELIVERED,
            "X411:0",
            null
        );
        deliveryReportRepository.save(report);
    }

    public void createNonDeliveryReport(AMHSMessage message, String reason, String diagnosticCode, AMHSDeliveryStatus status) {
        AMHSDeliveryReport report = buildReport(
            message,
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
        AMHSReportType reportType,
        AMHSDeliveryStatus status,
        String diagnosticCode,
        String reason
    ) {
        AMHSDeliveryReport report = new AMHSDeliveryReport();
        report.setMessage(message);
        report.setRecipient(message.getRecipient());
        report.setReportType(reportType);
        report.setDeliveryStatus(status);
        report.setX411DiagnosticCode(diagnosticCode);
        report.setNonDeliveryReason(reason);
        report.setReturnOfContent(shouldReturnContent(message));
        report.setExpiresAt(message.getDrExpirationAt());
        return report;
    }

    private boolean shouldReturnContent(AMHSMessage message) {
        return message.getIpnRequest() != null && message.getIpnRequest() > 0;
    }
}
