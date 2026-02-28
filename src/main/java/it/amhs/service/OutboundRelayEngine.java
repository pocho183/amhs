package it.amhs.service;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import it.amhs.domain.AMHSMessage;
import it.amhs.domain.AMHSMessageState;
import it.amhs.repository.AMHSMessageRepository;

@Service
public class OutboundRelayEngine {

    private static final Logger logger = LoggerFactory.getLogger(OutboundRelayEngine.class);

    private final AMHSMessageRepository messageRepository;
    private final RelayRoutingService routingService;
    private final OutboundP1Client outboundP1Client;
    private final AMHSDeliveryReportService deliveryReportService;
    private final String localMtaName;
    private final String localRoutingDomain;
    private final boolean relayEnabled;
    private final int maxAttempts;

    public OutboundRelayEngine(
        AMHSMessageRepository messageRepository,
        RelayRoutingService routingService,
        OutboundP1Client outboundP1Client,
        AMHSDeliveryReportService deliveryReportService,
        @Value("${amhs.mta.local-name:LOCAL-MTA}") String localMtaName,
        @Value("${amhs.mta.routing-domain:LOCAL}") String localRoutingDomain,
        @Value("${amhs.relay.enabled:false}") boolean relayEnabled,
        @Value("${amhs.relay.max-attempts:5}") int maxAttempts
    ) {
        this.messageRepository = messageRepository;
        this.routingService = routingService;
        this.outboundP1Client = outboundP1Client;
        this.deliveryReportService = deliveryReportService;
        this.localMtaName = localMtaName;
        this.localRoutingDomain = localRoutingDomain;
        this.relayEnabled = relayEnabled;
        this.maxAttempts = maxAttempts;
    }

    @Scheduled(fixedDelayString = "${amhs.relay.scan-delay-ms:5000}")
    public void relayPendingMessages() {
        if (!relayEnabled) {
            return;
        }

        List<AMHSMessageState> states = List.of(AMHSMessageState.SUBMITTED, AMHSMessageState.DEFERRED);
        for (AMHSMessage message : messageRepository.findByLifecycleStateIn(states)) {
            if (message.getNextRetryAt() != null && message.getNextRetryAt().after(new Date())) {
                continue;
            }
            relaySingle(message);
        }
    }

    void relaySingle(AMHSMessage message) {
        String existingTrace = message.getTransferTrace();
        if (hasLoop(existingTrace, localMtaName, localRoutingDomain)) {
            deadLetter(message, "loop-detected");
            return;
        }

        ORAddress recipient = ORAddress.parse(StringUtils.hasText(message.getRecipientOrAddress()) ? message.getRecipientOrAddress() : message.getRecipient());
        RelayRoutingService.AMHSMessageEnvelope envelope = new RelayRoutingService.AMHSMessageEnvelope(recipient, existingTrace);
        RelayRoutingService.RelayNextHop nextHop = routingService.findNextHop(envelope, message.getRelayAttemptCount())
            .orElse(null);

        if (nextHop == null) {
            deadLetter(message, "no-route");
            return;
        }

        try {
            OutboundP1Client.RelayTransferOutcome transferOutcome = outboundP1Client.relay(nextHop.endpoint(), message);
            message.setMtsIdentifier(transferOutcome.mtsIdentifier());
            message.setPerRecipientFields(transferOutcome.recipientOutcomes().isEmpty()
                ? null
                : transferOutcome.recipientOutcomes().entrySet().stream()
                    .map(entry -> entry.getKey() + "(" + entry.getValue().status() + ")")
                    .collect(java.util.stream.Collectors.joining(","))
            );
            message.setTransferTrace(RFC1006Service.appendTraceHop(existingTrace, Instant.now(), localMtaName, localRoutingDomain));
            message.setLastRelayError(transferOutcome.accepted() ? null : transferOutcome.diagnostic());
            message.setNextRetryAt(null);
            if (transferOutcome.accepted()) {
                message.setLifecycleState(AMHSMessageState.TRANSFERRED);
            } else {
                message.setLifecycleState(AMHSMessageState.FAILED);
                message.setDeadLetterReason("transfer-rejected");
                deliveryReportService.handleTransferOutcome(message, transferOutcome);
            }
            messageRepository.save(message);
        } catch (RuntimeException ex) {
            int attempt = message.getRelayAttemptCount() + 1;
            message.setRelayAttemptCount(attempt);
            message.setLastRelayError(ex.getMessage());
            if (attempt >= maxAttempts) {
                deadLetter(message, "max-attempts-exceeded");
                return;
            }
            Duration delay = Duration.ofSeconds((long) Math.pow(2, Math.min(attempt, 8)));
            message.setLifecycleState(AMHSMessageState.DEFERRED);
            message.setNextRetryAt(Date.from(Instant.now().plus(delay)));
            messageRepository.save(message);
            logger.warn("Deferred AMHS relay message {} on attempt {} via {}", message.getMessageId(), attempt, nextHop.endpoint());
        }
    }

    static boolean hasLoop(String trace, String localMtaName, String routingDomain) {
        if (!StringUtils.hasText(trace)) {
            return false;
        }
        String marker = (StringUtils.hasText(localMtaName) ? localMtaName.trim() : "LOCAL-MTA")
            + "@" + (StringUtils.hasText(routingDomain) ? routingDomain.trim() : "LOCAL") + "[";
        return trace.contains(marker);
    }

    private void deadLetter(AMHSMessage message, String reason) {
        message.setLifecycleState(AMHSMessageState.FAILED);
        message.setDeadLetterReason(reason);
        message.setNextRetryAt(null);
        messageRepository.save(message);
    }
}
