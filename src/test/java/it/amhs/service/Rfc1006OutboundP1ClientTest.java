package it.amhs.service;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.reflect.Method;

import org.junit.jupiter.api.Test;

class Rfc1006OutboundP1ClientTest {

    @Test
    void shouldBuildIcaoCompliantConnectionRequestTpdu() throws Exception {
        Rfc1006OutboundP1Client client = new Rfc1006OutboundP1Client(new P1AssociationProtocol(), new AcseAssociationProtocol());
        Method builder = Rfc1006OutboundP1Client.class.getDeclaredMethod("buildConnectionRequestTpdu");
        builder.setAccessible(true);

        byte[] tpdu = (byte[]) builder.invoke(client);
        CotpConnectionTpdu parsed = CotpConnectionTpdu.parse(tpdu);

        assertEquals(CotpConnectionTpdu.PDU_CR, parsed.type());
        assertEquals(0, parsed.tpduClass());
        assertEquals(16_384, parsed.negotiatedMaxUserData());
    }
}
