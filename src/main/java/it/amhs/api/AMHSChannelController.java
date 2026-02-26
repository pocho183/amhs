package it.amhs.api;



import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import it.amhs.domain.AMHSChannel;
import it.amhs.service.AMHSChannelService;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/amhs/channels")
public class AMHSChannelController {

    private final AMHSChannelService channelService;

    public AMHSChannelController(AMHSChannelService channelService) {
        this.channelService = channelService;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public ChannelResponse createOrUpdate(@Valid @RequestBody ChannelRequest request) {
        return toResponse(channelService.createOrUpdate(request));
    }

    @GetMapping
    public List<ChannelResponse> list() {
        return channelService.findAll().stream().map(this::toResponse).toList();
    }

    private ChannelResponse toResponse(AMHSChannel channel) {
        return new ChannelResponse(
            channel.getId(),
            channel.getName(),
            channel.getExpectedCn(),
            channel.getExpectedOu(),
            channel.isEnabled()
        );
    }
}
