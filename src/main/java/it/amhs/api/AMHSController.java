package it.amhs.api;

import java.util.List;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import it.amhs.domain.AMHSMessage;
import it.amhs.domain.AMHSPriority;
import it.amhs.domain.AMHSProfile;
import it.amhs.service.MTAService;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/amhs/messages")
public class AMHSController {

    private final MTAService mtaService;

    public AMHSController(MTAService mtaService) {
        this.mtaService = mtaService;
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
            request.subject()
        );
        return toResponse(saved);
    }

    @GetMapping
    public List<MessageResponse> listAll() {
        return mtaService.findAll().stream().map(this::toResponse).toList();
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
            "note", "Baseline implementation. Formal ICAO certification requires conformance testing and operational controls."
        );
    }

    private MessageResponse toResponse(AMHSMessage message) {
        return new MessageResponse(
            message.getMessageId(),
            message.getSender(),
            message.getRecipient(),
            message.getBody(),
            message.getProfile(),
            message.getPriority(),
            message.getSubject(),
            message.getReceivedAt()
        );
    }
}

