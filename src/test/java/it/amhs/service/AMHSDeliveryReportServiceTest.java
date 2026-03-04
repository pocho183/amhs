package it.amhs.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import it.amhs.domain.AMHSDeliveryReport;
import it.amhs.domain.AMHSDeliveryStatus;
import it.amhs.domain.AMHSMessage;
import it.amhs.domain.AMHSMessageState;
import it.amhs.repository.AMHSDeliveryReportRepository;
import it.amhs.repository.AMHSMessageRepository;

class AMHSDeliveryReportServiceTest {

    @Test
    void createsCorrelatedDeliveryReport() {
        AMHSDeliveryReportRepository reportRepo = mock(AMHSDeliveryReportRepository.class);
        AMHSMessageRepository messageRepo = mock(AMHSMessageRepository.class);
        AMHSMessageStateMachine stateMachine = mock(AMHSMessageStateMachine.class);
        X411DiagnosticMapper mapper = new X411DiagnosticMapper();
        AMHSDeliveryReportService service = new AMHSDeliveryReportService(reportRepo, messageRepo, stateMachine, mapper);

        AMHSMessage message = message("MSG-1", "MTS-1");
        service.createDeliveryReport(message);

        ArgumentCaptor<AMHSDeliveryReport> captor = ArgumentCaptor.forClass(AMHSDeliveryReport.class);
        verify(reportRepo).save(captor.capture());
        assertEquals("MTS-1", captor.getValue().getRelatedMtsIdentifier());
        assertEquals("MSG-1::MTS-1", captor.getValue().getCorrelationToken());
    }

    @Test
    void mapsTransferFailureDiagnosticsForNdr() {
        AMHSDeliveryReportRepository reportRepo = mock(AMHSDeliveryReportRepository.class);
        AMHSMessageRepository messageRepo = mock(AMHSMessageRepository.class);
        AMHSMessageStateMachine stateMachine = mock(AMHSMessageStateMachine.class);
        X411DiagnosticMapper mapper = new X411DiagnosticMapper();
        AMHSDeliveryReportService service = new AMHSDeliveryReportService(reportRepo, messageRepo, stateMachine, mapper);

        AMHSMessage message = message("MSG-2", null);
        OutboundP1Client.RelayTransferOutcome outcome = new OutboundP1Client.RelayTransferOutcome(
            false,
            null,
            "peer unreachable",
            java.util.Map.of()
        );

        service.handleTransferOutcome(message, outcome);

        ArgumentCaptor<AMHSDeliveryReport> captor = ArgumentCaptor.forClass(AMHSDeliveryReport.class);
        verify(reportRepo).save(captor.capture());
        assertEquals("X411:22", captor.getValue().getX411DiagnosticCode());
        assertEquals(AMHSDeliveryStatus.FAILED, captor.getValue().getDeliveryStatus());
        assertEquals("MSG::MSG-2", captor.getValue().getCorrelationToken());
    }

    @Test
    void resolvesMessageByMtsIdentifier() {
        AMHSDeliveryReportRepository reportRepo = mock(AMHSDeliveryReportRepository.class);
        AMHSMessageRepository messageRepo = mock(AMHSMessageRepository.class);
        AMHSMessageStateMachine stateMachine = mock(AMHSMessageStateMachine.class);
        X411DiagnosticMapper mapper = new X411DiagnosticMapper();
        AMHSDeliveryReportService service = new AMHSDeliveryReportService(reportRepo, messageRepo, stateMachine, mapper);

        AMHSMessage expected = message("MSG-3", "MTS-3");
        when(messageRepo.findByMtsIdentifier("MTS-3")).thenReturn(java.util.Optional.of(expected));

        assertEquals(expected, service.resolveByMtsIdentifier(" MTS-3 ").orElseThrow());
        assertNull(service.resolveByMtsIdentifier(" ").orElse(null));
        verify(messageRepo).findByMtsIdentifier("MTS-3");
    }

    private AMHSMessage message(String messageId, String mtsId) {
        AMHSMessage message = new AMHSMessage();
        message.setMessageId(messageId);
        message.setMtsIdentifier(mtsId);
        message.setRecipient("/C=IT/ADMD=ICAO/PRMD=ENAV/O=ATC/CN=OPS");
        message.setLifecycleState(AMHSMessageState.SUBMITTED);
        return message;
    }
}
