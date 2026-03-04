package it.amhs.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import it.amhs.domain.AMHSDeliveryReport;
import it.amhs.domain.AMHSDeliveryStatus;
import it.amhs.domain.AMHSMessage;
import it.amhs.domain.AMHSMessageState;
import it.amhs.domain.AMHSProfile;
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
            Map.of()
        );

        service.handleTransferOutcome(message, outcome);

        ArgumentCaptor<AMHSDeliveryReport> captor = ArgumentCaptor.forClass(AMHSDeliveryReport.class);
        verify(reportRepo).save(captor.capture());
        assertEquals("X411:22", captor.getValue().getX411DiagnosticCode());
        assertEquals(AMHSDeliveryStatus.FAILED, captor.getValue().getDeliveryStatus());
        assertEquals("MSG::MSG-2", captor.getValue().getCorrelationToken());
        assertNotNull(captor.getValue().getNdrApduRawBerHex());
        assertEquals(X411TagMap.TAG_CLASS_CONTEXT, captor.getValue().getNdrApduTagClass());
        assertEquals(X411TagMap.APDU_NON_DELIVERY_REPORT, captor.getValue().getNdrApduTagNumber());
    }

    @Test
    void createsPerRecipientReportsForMixedOutcome() {
        AMHSDeliveryReportRepository reportRepo = mock(AMHSDeliveryReportRepository.class);
        AMHSMessageRepository messageRepo = mock(AMHSMessageRepository.class);
        AMHSMessageStateMachine stateMachine = mock(AMHSMessageStateMachine.class);
        X411DiagnosticMapper mapper = new X411DiagnosticMapper();
        AMHSDeliveryReportService service = new AMHSDeliveryReportService(reportRepo, messageRepo, stateMachine, mapper);

        AMHSMessage message = message("MSG-4", "MTS-4");
        OutboundP1Client.RelayTransferOutcome outcome = new OutboundP1Client.RelayTransferOutcome(
            false,
            "MTS-4",
            "recipient issues",
            Map.of(
                "/C=IT/ADMD=ICAO/PRMD=ENAV/O=ATC/CN=OPS-1", new OutboundP1Client.RelayTransferOutcome.RecipientOutcome(2, "peer unreachable"),
                "/C=IT/ADMD=ICAO/PRMD=ENAV/O=ATC/CN=OPS-2", new OutboundP1Client.RelayTransferOutcome.RecipientOutcome(1, "temporary congestion"),
                "/C=IT/ADMD=ICAO/PRMD=ENAV/O=ATC/CN=OPS-3", new OutboundP1Client.RelayTransferOutcome.RecipientOutcome(0, "delivered")
            )
        );

        service.handleTransferOutcome(message, outcome);

        ArgumentCaptor<AMHSDeliveryReport> captor = ArgumentCaptor.forClass(AMHSDeliveryReport.class);
        verify(reportRepo, times(2)).save(captor.capture());
        List<AMHSDeliveryReport> reports = captor.getAllValues();
        assertEquals(AMHSDeliveryStatus.FAILED, reports.get(0).getDeliveryStatus());
        assertEquals("/C=IT/ADMD=ICAO/PRMD=ENAV/O=ATC/CN=OPS-1", reports.get(0).getRecipient());
        assertEquals("X411:22", reports.get(0).getX411DiagnosticCode());
        assertNotNull(reports.get(0).getNdrApduRawBerHex());

        assertEquals(AMHSDeliveryStatus.DEFERRED, reports.get(1).getDeliveryStatus());
        assertEquals("/C=IT/ADMD=ICAO/PRMD=ENAV/O=ATC/CN=OPS-2", reports.get(1).getRecipient());
        assertEquals("X411:28", reports.get(1).getX411DiagnosticCode());
    }

    @Test
    void returnOfContentHonorsDeliveryReportPreference() {
        AMHSDeliveryReportRepository reportRepo = mock(AMHSDeliveryReportRepository.class);
        AMHSMessageRepository messageRepo = mock(AMHSMessageRepository.class);
        AMHSMessageStateMachine stateMachine = mock(AMHSMessageStateMachine.class);
        X411DiagnosticMapper mapper = new X411DiagnosticMapper();
        AMHSDeliveryReportService service = new AMHSDeliveryReportService(reportRepo, messageRepo, stateMachine, mapper);

        AMHSMessage full = message("MSG-FULL", null);
        full.setDeliveryReport("full");
        full.setIpnRequest(0);
        service.createNonDeliveryReport(full, "failure", "X411:31", AMHSDeliveryStatus.FAILED);

        AMHSMessage headers = message("MSG-H", null);
        headers.setDeliveryReport("headers");
        headers.setIpnRequest(1);
        service.createNonDeliveryReport(headers, "failure", "X411:31", AMHSDeliveryStatus.FAILED);

        ArgumentCaptor<AMHSDeliveryReport> captor = ArgumentCaptor.forClass(AMHSDeliveryReport.class);
        verify(reportRepo, times(2)).save(captor.capture());
        assertEquals(true, captor.getAllValues().get(0).isReturnOfContent());
        assertEquals(false, captor.getAllValues().get(1).isReturnOfContent());
    }

    @Test
    void returnOfContentForIpnDependsOnProfileAndSizeLimit() {
        AMHSDeliveryReportRepository reportRepo = mock(AMHSDeliveryReportRepository.class);
        AMHSMessageRepository messageRepo = mock(AMHSMessageRepository.class);
        AMHSMessageStateMachine stateMachine = mock(AMHSMessageStateMachine.class);
        X411DiagnosticMapper mapper = new X411DiagnosticMapper();
        AMHSDeliveryReportService service = new AMHSDeliveryReportService(reportRepo, messageRepo, stateMachine, mapper);

        AMHSMessage basicProfile = message("MSG-B", null);
        basicProfile.setProfile(AMHSProfile.P3);
        basicProfile.setBody("short-body");
        basicProfile.setIpnRequest(1);
        service.createNonDeliveryReport(basicProfile, "failure", "X411:31", AMHSDeliveryStatus.FAILED);

        AMHSMessage extendedProfile = message("MSG-E", null);
        extendedProfile.setProfile(AMHSProfile.P1);
        extendedProfile.setBody("short-body");
        extendedProfile.setIpnRequest(1);
        service.createNonDeliveryReport(extendedProfile, "failure", "X411:31", AMHSDeliveryStatus.FAILED);

        AMHSMessage tooLarge = message("MSG-L", null);
        tooLarge.setProfile(AMHSProfile.P1);
        tooLarge.setBody("A".repeat(9000));
        tooLarge.setDeliveryReport("full");
        service.createNonDeliveryReport(tooLarge, "failure", "X411:31", AMHSDeliveryStatus.FAILED);

        ArgumentCaptor<AMHSDeliveryReport> captor = ArgumentCaptor.forClass(AMHSDeliveryReport.class);
        verify(reportRepo, times(3)).save(captor.capture());
        assertEquals(false, captor.getAllValues().get(0).isReturnOfContent());
        assertEquals(true, captor.getAllValues().get(1).isReturnOfContent());
        assertEquals(false, captor.getAllValues().get(2).isReturnOfContent());
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
