package it.amhs.service;


import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import it.amhs.api.ChannelRequest;
import it.amhs.domain.AMHSChannel;
import it.amhs.repository.AMHSChannelRepository;

@Service
public class AMHSChannelService {

    public static final String DEFAULT_CHANNEL_NAME = "ATFM";

    private final AMHSChannelRepository channelRepository;

    public AMHSChannelService(AMHSChannelRepository channelRepository) {
        this.channelRepository = channelRepository;
    }

    public AMHSChannel createOrUpdate(ChannelRequest request) {
        AMHSChannel channel = channelRepository.findByNameIgnoreCase(request.name().trim())
            .orElseGet(AMHSChannel::new);

        channel.setName(request.name().trim().toUpperCase());
        channel.setExpectedCn(normalize(request.expectedCn()));
        channel.setExpectedOu(normalize(request.expectedOu()));
        channel.setEnabled(request.enabled() == null || request.enabled());
        return channelRepository.save(channel);
    }

    public List<AMHSChannel> findAll() {
        return channelRepository.findAll();
    }

    public AMHSChannel requireEnabledChannel(String channelName) {
        String normalized = StringUtils.hasText(channelName) ? channelName.trim().toUpperCase() : DEFAULT_CHANNEL_NAME;
        AMHSChannel channel = channelRepository.findByNameIgnoreCase(normalized)
            .orElseThrow(() -> new IllegalArgumentException("Unknown AMHS channel: " + normalized));
        if (!channel.isEnabled()) {
            throw new IllegalArgumentException("AMHS channel is disabled: " + normalized);
        }
        return channel;
    }

    private String normalize(String value) {
        return StringUtils.hasText(value) ? value.trim() : null;
    }
}
