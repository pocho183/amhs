package it.amhs.service;

import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import it.amhs.api.ChannelRequest;

@Component
public class AMHSBootstrapService implements CommandLineRunner {

    private final AMHSChannelService channelService;

    public AMHSBootstrapService(AMHSChannelService channelService) {
        this.channelService = channelService;
    }

    @Override
    public void run(String... args) {
        channelService.createOrUpdate(new ChannelRequest(AMHSChannelService.DEFAULT_CHANNEL_NAME, "amhs-client-01", "ATM", true));
        channelService.createOrUpdate(new ChannelRequest("AFTN", "amhs-aftn-gateway", "AFTN", true));
    }
}
