package it.amhs.api;

import java.util.List;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import it.amhs.domain.AMHSMessage;
import it.amhs.domain.AMHSPriority;
import it.amhs.domain.AMHSProfile;
import it.amhs.service.MTAService;
import it.amhs.service.X400MessageService;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/amhs/messages")
public class AMHSController {

    private final MTAService mtaService;
    private final X400MessageService x400MessageService;

    public AMHSController(MTAService mtaService, X400MessageService x400MessageService) {
        this.mtaService = mtaService;
        this.x400MessageService = x400MessageService;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public MessageResponse send(@Valid @RequestBody MessageRequest request) {
        AMHSMessage saved = mtaService.storeMessage(
            request.from(),
            request.to(),
            request.body(),
            request.messageId(),
            request.profile(),
            request.priority(),
            request.subject(),
            request.channel(),
            null,
            null
        );
        return toResponse(saved);
    }

    @PostMapping("/x400")
    @ResponseStatus(HttpStatus.CREATED)
    public MessageResponse sendX400(@Valid @RequestBody X400MessageRequest request) {
        AMHSMessage saved = x400MessageService.storeFromP3(request);
        return toResponse(saved);
    }

    @GetMapping
    public List<MessageResponse> listAll(
        @RequestParam(required = false) String channel,
        @RequestParam(required = false) AMHSProfile profile
    ) {
        return mtaService.findByFilters(channel, profile).stream().map(this::toResponse).toList();
    }

    @GetMapping("/health")
    public String health() {
        return "AMHS server running";
    }

    @GetMapping("/capabilities")
    public Map<String, Object> capabilities() {
        return Map.of(
            "profiles", AMHSProfile.values(),
            "priorities", AMHSPriority.values(),
            "management", "Use /api/amhs/channels to manage channel/CN/OU policies",
            "x400Submit", "Use POST /api/amhs/messages/x400 for P3/X.400 metadata capture and traceability",
            "note", "Operational ICAO certification requires conformance testing, PKI governance, and regulatory acceptance."
        );
    }

    private MessageResponse toResponse(AMHSMessage message) {
        return new MessageResponse(
            message.getMessageId(),
            message.getSender(),
            message.getRecipient(),
            message.getBody(),
            message.getChannelName(),
            message.getProfile(),
            message.getPriority(),
            message.getSubject(),
            message.getCertificateCn(),
            message.getCertificateOu(),
            message.getSenderOrAddress(),
            message.getRecipientOrAddress(),
            message.getPresentationAddress(),
            message.getIpnRequest(),
            message.getDeliveryReport(),
            message.getTimeoutDr(),
            message.getReceivedAt()
        );
    }
}
