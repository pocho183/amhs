package it.amhs.service.protocol.p3;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;

import it.amhs.api.X400MessageRequest;
import it.amhs.compliance.AMHSComplianceValidator;
import it.amhs.domain.AMHSChannel;
import it.amhs.domain.AMHSMessage;
import it.amhs.service.channel.AMHSChannelService;
import it.amhs.service.message.X400MessageService;
import it.amhs.service.relay.RelayRoutingService;

class P3GatewaySessionServiceTest {

    @Test
    void bindSubmitAndUnbindFlowReturnsDeterministicSubmissionId() {
        CapturingX400MessageService messageService = new CapturingX400MessageService();
        P3GatewaySessionService sessionService = new P3GatewaySessionService(
            messageService,
            new AMHSComplianceValidator(),
            enabledChannelService(),
            new RelayRoutingService(""),
            true,
            "LIMCZZZX",
            "secret",
            "RFC1006",
            "127.0.0.1:102",
            "AMHS-P3-GATEWAY"
        );

        P3GatewaySessionService.SessionState session = sessionService.newSession();

        String bindResponse = sessionService.handleCommand(session,
            "BIND username=LIMCZZZX;password=secret;sender=/C=IT/ADMD=ICAO/PRMD=ENAV/O=ORG/OU1=LIMCZZZX/CN=Alice Test");
        assertTrue(bindResponse.startsWith("OK code=bind-accepted"));

        String submitResponse = sessionService.handleCommand(session,
            "SUBMIT recipient=/C=IT/ADMD=ICAO/PRMD=ENAV/O=ORG/OU1=LIRRZZZX/CN=Bob Test;subject=METAR;body=METAR-LINE");
        assertTrue(submitResponse.startsWith("OK code=submitted submission-id="));

        String firstSubmissionId = tokenValue(submitResponse, "submission-id");
        String secondSubmissionId = tokenValue(
            sessionService.handleCommand(session,
                "SUBMIT recipient=/C=IT/ADMD=ICAO/PRMD=ENAV/O=ORG/OU1=LIRRZZZX/CN=Bob Test;subject=METAR;body=METAR-LINE"),
            "submission-id");
        assertEquals(firstSubmissionId, secondSubmissionId);
        assertEquals(firstSubmissionId, messageService.lastRequest.messageId());

        assertEquals("OK code=release", sessionService.handleCommand(session, "UNBIND"));
    }

    @Test
    void submitBeforeBindIsRejected() {
        P3GatewaySessionService sessionService = new P3GatewaySessionService(
            new CapturingX400MessageService(),
            new AMHSComplianceValidator(),
            enabledChannelService(),
            new RelayRoutingService(""),
            false,
            "",
            "",
            "RFC1006",
            "127.0.0.1:102",
            "AMHS-P3-GATEWAY"
        );

        String submitResponse = sessionService.handleCommand(
            sessionService.newSession(),
            "SUBMIT recipient=/C=ITA/ADMD=ICAO/PRMD=ENAV/O=ORG/OU1=ATC/CN=Bob Test;body=DATA"
        );

        assertEquals("ERR code=association detail=Submit received before bind", submitResponse);
    }

    @Test
    void bindRejectsIdentityNotBoundToSenderAddress() {
        P3GatewaySessionService sessionService = new P3GatewaySessionService(
            new CapturingX400MessageService(),
            new AMHSComplianceValidator(),
            enabledChannelService(),
            new RelayRoutingService(""),
            true,
            "alice",
            "secret",
            "RFC1006",
            "127.0.0.1:102",
            "AMHS-P3-GATEWAY"
        );

        String bindResponse = sessionService.handleCommand(
            sessionService.newSession(),
            "BIND username=alice;password=secret;sender=/C=IT/ADMD=ICAO/PRMD=ENAV/O=ORG/OU1=LIMCZZZX/CN=Bob Test"
        );

        assertTrue(bindResponse.startsWith("ERR code=authz-failed"));
    }

    @Test
    void submitRejectsWhenRoutingTableHasNoMatchingRoute() {
        P3GatewaySessionService sessionService = new P3GatewaySessionService(
            new CapturingX400MessageService(),
            new AMHSComplianceValidator(),
            enabledChannelService(),
            new RelayRoutingService("/C=FR/ADMD=ICAO/PRMD=DSNA/O=ORG/OU1=LFPGZZZX->peer.fr:102"),
            true,
            "LIMCZZZX",
            "secret",
            "RFC1006",
            "127.0.0.1:102",
            "AMHS-P3-GATEWAY"
        );

        P3GatewaySessionService.SessionState session = sessionService.newSession();
        assertTrue(sessionService.handleCommand(session,
            "BIND username=LIMCZZZX;password=secret;sender=/C=IT/ADMD=ICAO/PRMD=ENAV/O=ORG/OU1=LIMCZZZX/CN=Alice Test")
            .startsWith("OK code=bind-accepted"));

        String submitResponse = sessionService.handleCommand(
            session,
            "SUBMIT recipient=/C=IT/ADMD=ICAO/PRMD=ENAV/O=ORG/OU1=LIRRZZZX/CN=Bob Test;body=DATA"
        );

        assertEquals("ERR code=routing-policy detail=No route found for recipient", submitResponse);
    }

    private static AMHSChannelService enabledChannelService() {
        AMHSChannel channel = new AMHSChannel();
        channel.setName("ATFM");
        channel.setEnabled(true);

        AMHSChannelService channelService = mock(AMHSChannelService.class);
        when(channelService.requireEnabledChannel(anyString())).thenReturn(channel);
        return channelService;
    }

    private static String tokenValue(String response, String key) {
        for (String token : response.split("\\s+")) {
            if (token.startsWith(key + "=")) {
                return token.substring((key + "=").length());
            }
        }
        throw new IllegalStateException("Missing key " + key + " in response: " + response);
    }

    private static class CapturingX400MessageService extends X400MessageService {
        private X400MessageRequest lastRequest;
        private long sequence = 0;

        CapturingX400MessageService() {
            super(null, null);
        }

        @Override
        public AMHSMessage storeFromP3(X400MessageRequest request) {
            this.lastRequest = request;
            AMHSMessage message = new AMHSMessage();
            message.setId(++sequence);
            return message;
        }
    }
}
