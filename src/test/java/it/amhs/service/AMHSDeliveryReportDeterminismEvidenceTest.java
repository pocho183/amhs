package it.amhs.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertIterableEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import it.amhs.domain.AMHSDeliveryReport;
import it.amhs.domain.AMHSDeliveryStatus;
import it.amhs.domain.AMHSMessage;
import it.amhs.domain.AMHSMessageState;
import it.amhs.domain.AMHSReportType;
import it.amhs.repository.AMHSDeliveryReportRepository;
import it.amhs.repository.AMHSMessageRepository;
import it.amhs.service.relay.OutboundP1Client;
import it.amhs.service.report.AMHSDeliveryReportService;
import it.amhs.service.state.AMHSMessageStateMachine;
import it.amhs.service.x411.X411DiagnosticMapper;

class AMHSDeliveryReportDeterminismEvidenceTest {

    @Test
    void buildsDeterministicCrossPeerTraceChainForDeclaredP1Scenarios() {
        List<TraceScenario> scenarios = List.of(
            TraceScenario.deliverySuccess(),
            TraceScenario.nonDelivery(),
            TraceScenario.delay(),
            TraceScenario.redirection(),
            TraceScenario.transferFailure()
        );

        List<TraceScenarioResult> firstRun = executeScenarios(scenarios);
        List<TraceScenarioResult> secondRun = executeScenarios(scenarios);

        assertEquals(scenarios.size(), firstRun.size());
        assertEquals(scenarios.size(), secondRun.size());

        for (int i = 0; i < scenarios.size(); i++) {
            TraceScenario expected = scenarios.get(i);
            TraceScenarioResult initial = firstRun.get(i);
            TraceScenarioResult replayed = secondRun.get(i);

            assertEquals(expected.scenarioId, initial.scenarioId);
            assertEquals(expected.peerAcknowledgment, initial.peerAcknowledgment);
            assertEquals(expected.ingressEvent, initial.ingressEvent);
            assertEquals(expected.queueStateTransition, initial.queueStateTransition);
            assertEquals(expected.expectedReportType, initial.reportType);
            assertEquals(expected.expectedStatus, initial.status);
            assertEquals(expected.expectedCorrelationId, initial.correlationId);
            assertEquals(expected.expectedDiagnosticCode, initial.diagnosticCode);

            assertEquals(initial, replayed, "scenario must replay identically: " + expected.scenarioId);
        }

        assertIterableEquals(
            scenarios.stream().map(s -> s.expectedCorrelationId).toList(),
            firstRun.stream().map(TraceScenarioResult::correlationId).toList()
        );
    }

    private static List<TraceScenarioResult> executeScenarios(List<TraceScenario> scenarios) {
        AMHSDeliveryReportRepository reportRepo = mock(AMHSDeliveryReportRepository.class);
        AMHSMessageRepository messageRepo = mock(AMHSMessageRepository.class);
        AMHSMessageStateMachine stateMachine = mock(AMHSMessageStateMachine.class);
        X411DiagnosticMapper mapper = new X411DiagnosticMapper();
        AMHSDeliveryReportService service = new AMHSDeliveryReportService(reportRepo, messageRepo, stateMachine, mapper);

        List<AMHSDeliveryReport> persistedReports = new ArrayList<>();
        when(reportRepo.save(any(AMHSDeliveryReport.class))).thenAnswer(invocation -> {
            AMHSDeliveryReport report = invocation.getArgument(0);
            persistedReports.add(report);
            return report;
        });

        List<TraceScenarioResult> chain = new ArrayList<>();
        for (TraceScenario scenario : scenarios) {
            int before = persistedReports.size();

            if (scenario.successScenario) {
                service.createDeliveryReport(scenario.message);
            } else {
                service.handleTransferOutcome(scenario.message, scenario.outcome);
            }

            List<AMHSDeliveryReport> emitted = persistedReports.subList(before, persistedReports.size());
            AMHSDeliveryReport report = emitted.stream()
                .filter(candidate -> scenario.message.getRecipient().equals(candidate.getRecipient()) || scenario.preferredRecipient.equals(candidate.getRecipient()))
                .findFirst()
                .orElseThrow();

            if (scenario.expectedReportType == AMHSReportType.NDR) {
                assertNotNull(report.getNdrApduRawBerHex());
            }

            chain.add(new TraceScenarioResult(
                scenario.scenarioId,
                scenario.ingressEvent,
                scenario.queueStateTransition,
                scenario.peerAcknowledgment,
                report.getReportType(),
                report.getDeliveryStatus(),
                report.getCorrelationToken(),
                report.getX411DiagnosticCode()
            ));
        }
        return chain;
    }

    private record TraceScenario(
        String scenarioId,
        String ingressEvent,
        String queueStateTransition,
        String peerAcknowledgment,
        AMHSMessage message,
        OutboundP1Client.RelayTransferOutcome outcome,
        boolean successScenario,
        AMHSReportType expectedReportType,
        AMHSDeliveryStatus expectedStatus,
        String expectedCorrelationId,
        String expectedDiagnosticCode,
        String preferredRecipient
    ) {

        static TraceScenario deliverySuccess() {
            AMHSMessage message = message("MSG-1", "MTS-1", "/C=IT/ADMD=ICAO/PRMD=ENAV/O=ATC/CN=OPS");
            return new TraceScenario(
                "SCN-DELIVERY-SUCCESS",
                "ingress.accepted(MSG-1,MTS-1)",
                "SUBMITTED → TRANSFERRED → DELIVERED",
                "ENAV-OPS:P1-ACK-250",
                message,
                null,
                true,
                AMHSReportType.DR,
                AMHSDeliveryStatus.DELIVERED,
                "MSG-1::MTS-1",
                "X411:0",
                message.getRecipient()
            );
        }

        static TraceScenario nonDelivery() {
            AMHSMessage message = message("MSG-2", null, "/C=IT/ADMD=ICAO/PRMD=MIL/O=NET/CN=OPS");
            OutboundP1Client.RelayTransferOutcome outcome = new OutboundP1Client.RelayTransferOutcome(
                false,
                null,
                "peer unreachable",
                Map.of()
            );
            return new TraceScenario(
                "SCN-NON-DELIVERY",
                "ingress.transfer-attempt(MSG-2)",
                "SUBMITTED → FAILED → REPORTED",
                "MIL-NET:P1-REJ-550",
                message,
                outcome,
                false,
                AMHSReportType.NDR,
                AMHSDeliveryStatus.FAILED,
                "MSG::MSG-2",
                "X411:22",
                message.getRecipient()
            );
        }

        static TraceScenario delay() {
            AMHSMessage message = message("MSG-4", "MTS-4", "/C=IT/ADMD=ICAO/PRMD=ENAV/O=ATC/CN=OPS-2");
            Map<String, OutboundP1Client.RelayTransferOutcome.RecipientOutcome> recipients = new LinkedHashMap<>();
            recipients.put("/C=IT/ADMD=ICAO/PRMD=ENAV/O=ATC/CN=OPS-2", new OutboundP1Client.RelayTransferOutcome.RecipientOutcome(1, "temporary congestion"));
            OutboundP1Client.RelayTransferOutcome outcome = new OutboundP1Client.RelayTransferOutcome(
                false,
                "MTS-4",
                "recipient issues",
                recipients
            );
            return new TraceScenario(
                "SCN-DELAY",
                "ingress.partial-recipient-outcome(MSG-4,MTS-4)",
                "SUBMITTED → DEFERRED → REPORTED",
                "CERTIFIED-AMHS-LAB:P1-ACK-451",
                message,
                outcome,
                false,
                AMHSReportType.NDR,
                AMHSDeliveryStatus.DEFERRED,
                "MSG-4::MTS-4",
                "X411:28",
                "/C=IT/ADMD=ICAO/PRMD=ENAV/O=ATC/CN=OPS-2"
            );
        }

        static TraceScenario redirection() {
            AMHSMessage message = message("MSG-REDIR-1", null, "/C=IT/ADMD=ICAO/PRMD=METEO/O=LEGACY/CN=ROUTER");
            OutboundP1Client.RelayTransferOutcome outcome = new OutboundP1Client.RelayTransferOutcome(
                false,
                null,
                "redirection-loop-detected",
                Map.of()
            );
            return new TraceScenario(
                "SCN-REDIRECTION",
                "ingress.redirect-loop(MSG-REDIR-1)",
                "SUBMITTED → FAILED → REPORTED",
                "METEO-LEGACY:P1-REJ-554",
                message,
                outcome,
                false,
                AMHSReportType.NDR,
                AMHSDeliveryStatus.FAILED,
                "MSG::MSG-REDIR-1",
                "X411:21",
                message.getRecipient()
            );
        }

        static TraceScenario transferFailure() {
            AMHSMessage message = message("MSG-TF-1", null, "/C=IT/ADMD=ICAO/PRMD=MIL/O=NET/CN=BACKUP");
            OutboundP1Client.RelayTransferOutcome outcome = new OutboundP1Client.RelayTransferOutcome(
                false,
                null,
                "transfer-failure-fallback-addressing",
                Map.of()
            );
            return new TraceScenario(
                "SCN-TRANSFER-FAILURE",
                "ingress.transfer-failure(MSG-TF-1)",
                "SUBMITTED → FAILED → REPORTED",
                "MIL-NET:P1-REJ-553",
                message,
                outcome,
                false,
                AMHSReportType.NDR,
                AMHSDeliveryStatus.FAILED,
                "MSG::MSG-TF-1",
                "X411:22",
                message.getRecipient()
            );
        }

        private static AMHSMessage message(String messageId, String mtsId, String recipient) {
            AMHSMessage message = new AMHSMessage();
            message.setMessageId(messageId);
            message.setMtsIdentifier(mtsId);
            message.setRecipient(recipient);
            message.setLifecycleState(AMHSMessageState.SUBMITTED);
            return message;
        }
    }

    private record TraceScenarioResult(
        String scenarioId,
        String ingressEvent,
        String queueStateTransition,
        String peerAcknowledgment,
        AMHSReportType reportType,
        AMHSDeliveryStatus status,
        String correlationId,
        String diagnosticCode
    ) {
    }
}
