package it.amhs.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import it.amhs.api.ChannelRequest;

@Component
public class AMHSBootstrapService implements CommandLineRunner {

    private final AMHSChannelService channelService;
    private final boolean needClientAuth;

    public AMHSBootstrapService(AMHSChannelService channelService, @Value("${rfc1006.tls.need-client-auth:false}") boolean needClientAuth) {
        this.channelService = channelService;
        this.needClientAuth = needClientAuth;
    }

    @Override
    public void run(String... args) {
        String atfmExpectedCn = needClientAuth ? "amhs-client-01" : null;
        String atfmExpectedOu = needClientAuth ? "ATM" : null;
        String aftnExpectedCn = needClientAuth ? "amhs-aftn-gateway" : null;
        String aftnExpectedOu = needClientAuth ? "AFTN" : null;

        channelService.createOrUpdate(new ChannelRequest(AMHSChannelService.DEFAULT_CHANNEL_NAME, atfmExpectedCn, atfmExpectedOu, true));
        channelService.createOrUpdate(new ChannelRequest("AFTN", aftnExpectedCn, aftnExpectedOu, true));
    }
}
