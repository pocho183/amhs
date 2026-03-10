package it.amhs.network;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.reflect.Method;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class P3GatewayServerProtocolDetectionTest {

    private P3GatewayServer server;
    private Method detectProtocol;
    private Method classifyRfc1006Payload;
    private Method isRfc1006PayloadSupportedByAsn1;
    private Method extractApplicationPduFromRfc1006Payload;

    @BeforeEach
    void setUp() throws Exception {
        server = new P3GatewayServer("0.0.0.0", 1988, 1, false, false, false, "GATEWAY_MULTI_PROTOCOL", null, null, null);
        detectProtocol = P3GatewayServer.class.getDeclaredMethod("detectProtocol", byte[].class);
        detectProtocol.setAccessible(true);
        classifyRfc1006Payload = P3GatewayServer.class.getDeclaredMethod("classifyRfc1006Payload", byte[].class);
        classifyRfc1006Payload.setAccessible(true);
        isRfc1006PayloadSupportedByAsn1 = P3GatewayServer.class.getDeclaredMethod("isRfc1006PayloadSupportedByAsn1", String.class);
        isRfc1006PayloadSupportedByAsn1.setAccessible(true);
        extractApplicationPduFromRfc1006Payload = P3GatewayServer.class.getDeclaredMethod("extractApplicationPduFromRfc1006Payload", byte[].class, String.class);
        extractApplicationPduFromRfc1006Payload.setAccessible(true);
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
    void prioritizesBerDetectionForPrintableAcseTags() throws Exception {
        Object aarq = detectProtocol.invoke(server, (Object) new byte[] { 0x60, 0x03, 0x01, 0x01, 0x00 });
        Object aareOrPpdu = detectProtocol.invoke(server, (Object) new byte[] { 0x61, 0x03, 0x01, 0x01, 0x00 });
        Object tag62 = detectProtocol.invoke(server, (Object) new byte[] { 0x62, 0x03, 0x01, 0x01, 0x00 });
        Object tag64 = detectProtocol.invoke(server, (Object) new byte[] { 0x64, 0x03, 0x01, 0x01, 0x00 });

        assertEquals("BER_APDU", aarq.toString());
        assertEquals("BER_APDU", aareOrPpdu.toString());
        assertEquals("BER_APDU", tag62.toString());
        assertEquals("BER_APDU", tag64.toString());
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

    @Test
    void onlyBerPayloadsArePassedToAsn1Handler() throws Exception {
        Object berSupported = isRfc1006PayloadSupportedByAsn1.invoke(server, "BER_APDU");
        Object sessionSupported = isRfc1006PayloadSupportedByAsn1.invoke(server, "OSI_SESSION_SPDU");
        Object presentationSupported = isRfc1006PayloadSupportedByAsn1.invoke(server, "OSI_PRESENTATION_PPDU");
        Object acseSupported = isRfc1006PayloadSupportedByAsn1.invoke(server, "ACSE_APDU");

        assertEquals(true, berSupported);
        assertEquals(true, sessionSupported);
        assertEquals(true, presentationSupported);
        assertEquals(true, acseSupported);
    }

    @Test
    void extractsGatewayApduFromAcsePayload() throws Exception {
        byte[] gatewayApdu = new byte[] {(byte) 0xA0, 0x03, 0x0C, 0x01, 0x41};
        byte[] acse = new byte[] {0x60, 0x09, (byte) 0xBE, 0x07, (byte) 0xA0, 0x05, (byte) 0xA0, 0x03, 0x0C, 0x01, 0x41};

        byte[] extracted = (byte[]) extractApplicationPduFromRfc1006Payload.invoke(server, acse, "ACSE_APDU");

        assertArrayEquals(gatewayApdu, extracted);
    }

    @Test
    void extractsGatewayApduFromSessionEnvelope() throws Exception {
        byte[] gatewayApdu = new byte[] {(byte) 0xA0, 0x03, 0x0C, 0x01, 0x41};
        byte[] acse = new byte[] {0x60, 0x09, (byte) 0xBE, 0x07, (byte) 0xA0, 0x05, (byte) 0xA0, 0x03, 0x0C, 0x01, 0x41};
        byte[] sessionWrapped = new byte[3 + acse.length];
        sessionWrapped[0] = 0x0D;
        sessionWrapped[1] = 0x01;
        sessionWrapped[2] = 0x00;
        System.arraycopy(acse, 0, sessionWrapped, 3, acse.length);

        byte[] extracted = (byte[]) extractApplicationPduFromRfc1006Payload.invoke(server, sessionWrapped, "OSI_SESSION_SPDU");

        assertArrayEquals(gatewayApdu, extracted);
    }

    @Test
    void extractsGatewayApduFromSessionEnvelopeAfterNonEnvelopeBerTlv() throws Exception {
        byte[] gatewayApdu = new byte[] {(byte) 0xA0, 0x03, 0x0C, 0x01, 0x41};
        byte[] acse = new byte[] {0x60, 0x09, (byte) 0xBE, 0x07, (byte) 0xA0, 0x05, (byte) 0xA0, 0x03, 0x0C, 0x01, 0x41};
        byte[] sessionWrapped = new byte[3 + 12 + acse.length];
        sessionWrapped[0] = 0x0D;
        sessionWrapped[1] = (byte) 0xFF;
        sessionWrapped[2] = 0x01;
        sessionWrapped[3] = 0x28;
        sessionWrapped[4] = 0x0A;
        for (int i = 0; i < 10; i++) {
            sessionWrapped[5 + i] = (byte) (i + 1);
        }
        System.arraycopy(acse, 0, sessionWrapped, 15, acse.length);

        byte[] extracted = (byte[]) extractApplicationPduFromRfc1006Payload.invoke(server, sessionWrapped, "OSI_SESSION_SPDU");

        assertArrayEquals(gatewayApdu, extracted);
    }


    @Test
    void rewrapsAcsePayloadForRfc1006Response() throws Exception {
        Method rewrap = P3GatewayServer.class.getDeclaredMethod("rewrapApplicationPduForRfc1006Response", byte[].class, String.class, byte[].class);
        rewrap.setAccessible(true);
        byte[] gatewayResponse = new byte[] {(byte) 0xA1, 0x03, 0x0C, 0x01, 0x42};
        byte[] inboundAcse = new byte[] {0x60, 0x09, (byte) 0xBE, 0x07, (byte) 0xA0, 0x05, (byte) 0xA0, 0x03, 0x0C, 0x01, 0x41};

        byte[] wrapped = (byte[]) rewrap.invoke(server, gatewayResponse, "ACSE_APDU", inboundAcse);

        assertEquals(0x61, wrapped[0] & 0xFF);
        assertEquals((byte) 0xBE, wrapped[2]);
    }

    @Test
    void rewrapsSessionEnvelopeForRfc1006Response() throws Exception {
        Method rewrap = P3GatewayServer.class.getDeclaredMethod("rewrapApplicationPduForRfc1006Response", byte[].class, String.class, byte[].class);
        rewrap.setAccessible(true);
        byte[] gatewayResponse = new byte[] {(byte) 0xA1, 0x03, 0x0C, 0x01, 0x42};
        byte[] acse = new byte[] {0x60, 0x09, (byte) 0xBE, 0x07, (byte) 0xA0, 0x05, (byte) 0xA0, 0x03, 0x0C, 0x01, 0x41};
        byte[] sessionWrapped = new byte[3 + acse.length];
        sessionWrapped[0] = 0x0D;
        sessionWrapped[1] = 0x01;
        sessionWrapped[2] = 0x00;
        System.arraycopy(acse, 0, sessionWrapped, 3, acse.length);

        byte[] wrapped = (byte[]) rewrap.invoke(server, gatewayResponse, "OSI_SESSION_SPDU", sessionWrapped);

        assertEquals(0x0D, wrapped[0] & 0xFF);
        assertEquals(0x61, wrapped[3] & 0xFF);
    }


    @Test
    void rewrapPreservesSessionPresentationAndAcseEnvelope() throws Exception {
        Method rewrap = P3GatewayServer.class.getDeclaredMethod("rewrapApplicationPduForRfc1006Response", byte[].class, String.class, byte[].class);
        rewrap.setAccessible(true);
        byte[] gatewayResponse = new byte[] {(byte) 0xA1, 0x03, 0x0C, 0x01, 0x42};
        byte[] presentation = new byte[] {0x61, 0x0D, (byte) 0xBE, 0x0B, 0x60, 0x09, (byte) 0xBE, 0x07, (byte) 0xA0, 0x05, (byte) 0xA0, 0x03, 0x0C, 0x01, 0x41};
        byte[] sessionWrapped = new byte[3 + presentation.length];
        sessionWrapped[0] = 0x0D;
        sessionWrapped[1] = 0x01;
        sessionWrapped[2] = 0x00;
        System.arraycopy(presentation, 0, sessionWrapped, 3, presentation.length);

        byte[] wrapped = (byte[]) rewrap.invoke(server, gatewayResponse, "OSI_SESSION_SPDU", sessionWrapped);

        assertEquals(0x0D, wrapped[0] & 0xFF);
        assertEquals(0x61, wrapped[3] & 0xFF);
        assertEquals((byte) 0xBE, wrapped[5]);
        assertEquals(0x61, wrapped[7] & 0xFF);
        assertEquals((byte) 0xA1, wrapped[11]);
    }

    @Test
    void extractsGatewayApduFromPresentationEnvelope() throws Exception {
        byte[] gatewayApdu = new byte[] {(byte) 0xA0, 0x03, 0x0C, 0x01, 0x41};
        byte[] acse = new byte[] {0x60, 0x09, (byte) 0xBE, 0x07, (byte) 0xA0, 0x05, (byte) 0xA0, 0x03, 0x0C, 0x01, 0x41};
        byte[] presentation = new byte[] {0x61, 0x0D, (byte) 0xBE, 0x0B, 0x60, 0x09, (byte) 0xBE, 0x07, (byte) 0xA0, 0x05, (byte) 0xA0, 0x03, 0x0C, 0x01, 0x41};

        byte[] extracted = (byte[]) extractApplicationPduFromRfc1006Payload.invoke(server, presentation, "OSI_PRESENTATION_PPDU");

        assertArrayEquals(gatewayApdu, extracted);
    }

    @Test
    void rewrapPreservesPresentationAndAcseEnvelope() throws Exception {
        Method rewrap = P3GatewayServer.class.getDeclaredMethod("rewrapApplicationPduForRfc1006Response", byte[].class, String.class, byte[].class);
        rewrap.setAccessible(true);
        byte[] gatewayResponse = new byte[] {(byte) 0xA1, 0x03, 0x0C, 0x01, 0x42};
        byte[] presentation = new byte[] {0x61, 0x0D, (byte) 0xBE, 0x0B, 0x60, 0x09, (byte) 0xBE, 0x07, (byte) 0xA0, 0x05, (byte) 0xA0, 0x03, 0x0C, 0x01, 0x41};

        byte[] wrapped = (byte[]) rewrap.invoke(server, gatewayResponse, "OSI_PRESENTATION_PPDU", presentation);

        assertEquals(0x61, wrapped[0] & 0xFF);
        assertEquals((byte) 0xBE, wrapped[2]);
        assertEquals(0x61, wrapped[4] & 0xFF);
        assertEquals((byte) 0xA1, wrapped[8]);
    }

    @Test
    void extractsReportRequestApduFromPresentationEnvelope() throws Exception {
        byte[] gatewayApdu = new byte[] {(byte) 0xA9, 0x03, 0x0C, 0x01, 0x41};
        byte[] acse = new byte[] {0x60, 0x09, (byte) 0xBE, 0x07, (byte) 0xA0, 0x05, (byte) 0xA9, 0x03, 0x0C, 0x01, 0x41};
        byte[] presentation = new byte[] {0x61, 0x0D, (byte) 0xBE, 0x0B, 0x60, 0x09, (byte) 0xBE, 0x07, (byte) 0xA0, 0x05, (byte) 0xA9, 0x03, 0x0C, 0x01, 0x41};

        byte[] extracted = (byte[]) extractApplicationPduFromRfc1006Payload.invoke(server, presentation, "OSI_PRESENTATION_PPDU");

        assertArrayEquals(gatewayApdu, extracted);
    }

    @Test
    void rewrapPreservesEnvelopeForReportRequestAndInjectsReportResponse() throws Exception {
        Method rewrap = P3GatewayServer.class.getDeclaredMethod("rewrapApplicationPduForRfc1006Response", byte[].class, String.class, byte[].class);
        rewrap.setAccessible(true);

        byte[] gatewayResponse = new byte[] {(byte) 0xAA, 0x03, 0x0C, 0x01, 0x42};
        byte[] presentation = new byte[] {0x61, 0x0D, (byte) 0xBE, 0x0B, 0x60, 0x09, (byte) 0xBE, 0x07, (byte) 0xA0, 0x05, (byte) 0xA9, 0x03, 0x0C, 0x01, 0x41};

        byte[] wrapped = (byte[]) rewrap.invoke(server, gatewayResponse, "OSI_PRESENTATION_PPDU", presentation);
        byte[] extracted = (byte[]) extractApplicationPduFromRfc1006Payload.invoke(server, wrapped, "OSI_PRESENTATION_PPDU");

        assertArrayEquals(gatewayResponse, extracted);
    }


    @Test
    void extractsReadRequestApduFromPresentationEnvelope() throws Exception {
        byte[] gatewayApdu = new byte[] {(byte) 0xAB, 0x03, 0x0C, 0x01, 0x41};
        byte[] acse = new byte[] {0x60, 0x09, (byte) 0xBE, 0x07, (byte) 0xA0, 0x05, (byte) 0xAB, 0x03, 0x0C, 0x01, 0x41};
        byte[] presentation = new byte[] {0x61, 0x0D, (byte) 0xBE, 0x0B, 0x60, 0x09, (byte) 0xBE, 0x07, (byte) 0xA0, 0x05, (byte) 0xAB, 0x03, 0x0C, 0x01, 0x41};

        byte[] extracted = (byte[]) extractApplicationPduFromRfc1006Payload.invoke(server, presentation, "OSI_PRESENTATION_PPDU");

        assertArrayEquals(gatewayApdu, extracted);
    }

    @Test
    void rewrapPreservesEnvelopeForReadRequestAndInjectsReadResponse() throws Exception {
        Method rewrap = P3GatewayServer.class.getDeclaredMethod("rewrapApplicationPduForRfc1006Response", byte[].class, String.class, byte[].class);
        rewrap.setAccessible(true);

        byte[] gatewayResponse = new byte[] {(byte) 0xAC, 0x03, 0x0C, 0x01, 0x42};
        byte[] presentation = new byte[] {0x61, 0x0D, (byte) 0xBE, 0x0B, 0x60, 0x09, (byte) 0xBE, 0x07, (byte) 0xA0, 0x05, (byte) 0xAB, 0x03, 0x0C, 0x01, 0x41};

        byte[] wrapped = (byte[]) rewrap.invoke(server, gatewayResponse, "OSI_PRESENTATION_PPDU", presentation);
        byte[] extracted = (byte[]) extractApplicationPduFromRfc1006Payload.invoke(server, wrapped, "OSI_PRESENTATION_PPDU");

        assertArrayEquals(gatewayResponse, extracted);
    }

    @Test
    void standardProfileRejectsTextAndBer() throws Exception {
        P3GatewayServer strictServer = new P3GatewayServer("0.0.0.0", 1988, 1, false, false, false, "STANDARD_P3", null, null, null);
        Method isProtocolAllowed = P3GatewayServer.class.getDeclaredMethod("isProtocolAllowed", Class.forName("it.amhs.network.P3GatewayServer$ProtocolKind"));
        isProtocolAllowed.setAccessible(true);

        Object text = detectProtocol.invoke(strictServer, (Object) new byte[] { 'B', 'I', 'N', 'D' });
        Object ber = detectProtocol.invoke(strictServer, (Object) new byte[] { (byte) 0xA0, 0x03, 0x0C, 0x01, 0x41 });
        Object rfc1006 = detectProtocol.invoke(strictServer, (Object) new byte[] { 0x03, 0x00, 0x00, 0x13, 0x0E });

        assertEquals(false, isProtocolAllowed.invoke(strictServer, text));
        assertEquals(false, isProtocolAllowed.invoke(strictServer, ber));
        assertEquals(true, isProtocolAllowed.invoke(strictServer, rfc1006));
    }

    @Test
    void multiProtocolProfileRejectsTextButAllowsBerAndRfc1006() throws Exception {
        P3GatewayServer gatewayServer = new P3GatewayServer("0.0.0.0", 1988, 1, false, false, false, "GATEWAY_MULTI_PROTOCOL", null, null, null);
        Method isProtocolAllowed = P3GatewayServer.class.getDeclaredMethod("isProtocolAllowed", Class.forName("it.amhs.network.P3GatewayServer$ProtocolKind"));
        isProtocolAllowed.setAccessible(true);

        Object text = detectProtocol.invoke(gatewayServer, (Object) new byte[] { 'B', 'I', 'N', 'D' });
        Object ber = detectProtocol.invoke(gatewayServer, (Object) new byte[] { (byte) 0xA0, 0x03, 0x0C, 0x01, 0x41 });
        Object rfc1006 = detectProtocol.invoke(gatewayServer, (Object) new byte[] { 0x03, 0x00, 0x00, 0x13, 0x0E });

        assertEquals(false, isProtocolAllowed.invoke(gatewayServer, text));
        assertEquals(true, isProtocolAllowed.invoke(gatewayServer, ber));
        assertEquals(true, isProtocolAllowed.invoke(gatewayServer, rfc1006));
    }

    @Test
    void rejectsInvalidListenerProfile() {
        try {
            new P3GatewayServer("0.0.0.0", 1988, 1, false, false, false, "bad-profile", null, null, null);
        } catch (IllegalArgumentException ex) {
            assertEquals(true, ex.getMessage().contains("listener-profile"));
            return;
        }
        throw new AssertionError("Expected IllegalArgumentException");
    }

}
