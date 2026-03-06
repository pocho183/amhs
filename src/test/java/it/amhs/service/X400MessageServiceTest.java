package it.amhs.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Date;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import it.amhs.api.X400MessageRequest;
import it.amhs.domain.AMHSMessage;
import it.amhs.domain.AMHSPriority;
import it.amhs.domain.AMHSProfile;
import it.amhs.service.address.X400AddressBuilder;
import it.amhs.service.message.X400MessageService;
import it.amhs.service.protocol.p1.MTAService;

class X400MessageServiceTest {

    @Test
    void storeFromP3UsesP3ProfileAndBuildsCanonicalOrMappings() {
        MTAService mtaService = mock(MTAService.class);
        X400AddressBuilder addressBuilder = new X400AddressBuilder();

        AMHSMessage persisted = new AMHSMessage();
        persisted.setId(42L);
        when(mtaService.storeX400Message(
            anyString(), anyString(), anyString(), anyString(), any(), any(), any(), anyString(), any(), any(), any(Date.class),
            anyString(), anyString(), anyString(), any(), any(), any(), any(), any(), any(), any()
        )).thenReturn(persisted);

        X400MessageService service = new X400MessageService(mtaService, addressBuilder);

        X400MessageRequest request = new X400MessageRequest(
            "sub-1", "METAR-LINE", "METAR", AMHSPriority.GG, 1, "BASIC", 15,
            "RFC1006", "127.0.0.1:102", "AMHS-P3-GATEWAY",
            "Alice Test", "LIMCZZZX", null, null, null, "ORG", "ENAV", "ICAO", "IT",
            "Bob Test", "LIRRZZZX", null, null, null, "ORG", "ENAV", "ICAO", "IT",
            "ATFM", "LIMCZZZX", "AMHS"
        );

        AMHSMessage stored = service.storeFromP3(request);
        assertEquals(42L, stored.getId());

        ArgumentCaptor<String> from = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> to = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<AMHSProfile> profile = ArgumentCaptor.forClass(AMHSProfile.class);
        ArgumentCaptor<String> senderOr = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> recipientOr = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> presentation = ArgumentCaptor.forClass(String.class);

        verify(mtaService).storeX400Message(
            from.capture(),
            to.capture(),
            anyString(),
            anyString(),
            profile.capture(),
            any(),
            any(),
            anyString(),
            any(),
            any(),
            any(Date.class),
            senderOr.capture(),
            recipientOr.capture(),
            presentation.capture(),
            any(),
            any(),
            any(),
            any(),
            any(),
            any(),
            any()
        );

        assertEquals("/C=IT/ADMD=ICAO/PRMD=ENAV/O=ORG/OU1=LIMCZZZX/CN=Alice Test", from.getValue());
        assertEquals("/C=IT/ADMD=ICAO/PRMD=ENAV/O=ORG/OU1=LIRRZZZX/CN=Bob Test", to.getValue());
        assertEquals(AMHSProfile.P3, profile.getValue());
        assertEquals(from.getValue(), senderOr.getValue());
        assertEquals(to.getValue(), recipientOr.getValue());
        assertEquals("RFC1006$127.0.0.1:102$AMHS-P3-GATEWAY", presentation.getValue());
    }
}
