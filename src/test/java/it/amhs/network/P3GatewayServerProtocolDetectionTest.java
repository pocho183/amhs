package it.amhs.network;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.reflect.Method;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class P3GatewayServerProtocolDetectionTest {

    private P3GatewayServer server;
    private Method detectProtocol;
    private Method classifyRfc1006Payload;

    @BeforeEach
    void setUp() throws Exception {
        server = new P3GatewayServer("0.0.0.0", 1988, 1, false, false, false, null, null, null);
        detectProtocol = P3GatewayServer.class.getDeclaredMethod("detectProtocol", byte[].class);
        detectProtocol.setAccessible(true);
        classifyRfc1006Payload = P3GatewayServer.class.getDeclaredMethod("classifyRfc1006Payload", byte[].class);
        classifyRfc1006Payload.setAccessible(true);
    }

    @Test
    void detectsRfc1006OnlyForFullTpktHeader() throws Exception {
        Object protocol = detectProtocol.invoke(server, (Object) new byte[] { 0x03, 0x00, 0x00, 0x13, 0x0E });

        assertEquals("RFC1006_TPKT", protocol.toString());
    }

    @Test
    void doesNotTreatBerTag3AsRfc1006() throws Exception {
        Object protocol = detectProtocol.invoke(server, (Object) new byte[] { 0x03, 0x00 });

        assertEquals("BER_APDU", protocol.toString());
    }

    @Test
    void classifiesSessionSpduByLeadingOctet() throws Exception {
        Object kind = classifyRfc1006Payload.invoke(server, (Object) new byte[] { 0x0D, 0x10, 0x00 });

        assertEquals("OSI_SESSION_SPDU", kind.toString());
    }

    @Test
    void classifiesAcseApduByLeadingOctet() throws Exception {
        Object kind = classifyRfc1006Payload.invoke(server, (Object) new byte[] { 0x60, 0x1A, 0x01, 0x00 });

        assertEquals("ACSE_APDU", kind.toString());
    }
}
