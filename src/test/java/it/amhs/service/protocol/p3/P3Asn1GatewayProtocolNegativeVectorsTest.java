package it.amhs.service.protocol.p3;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import it.amhs.asn1.BerCodec;
import it.amhs.asn1.BerTlv;

class P3Asn1GatewayProtocolNegativeVectorsTest {

    @Test
    void returnsInvalidApduWhenIncomingApduIsNotContextConstructed() {
        P3Asn1GatewayProtocol protocol = new P3Asn1GatewayProtocol(new StubSessionService());

        byte[] primitiveContext = BerCodec.encode(new BerTlv(2, false, P3Asn1GatewayProtocol.APDU_BIND_REQUEST, 0, 0, new byte[0]));
        byte[] response = protocol.handle(new StubSessionService().newSession(), primitiveContext);

        BerTlv error = BerCodec.decodeSingle(response);
        assertEquals(P3Asn1GatewayProtocol.APDU_ERROR, error.tagNumber());
        assertEquals("invalid-apdu", decodeErrorField(error, 0));
    }

    @Test
    void returnsUnsupportedOperationForUnknownContextApdu() {
        StubSessionService service = new StubSessionService();
        P3Asn1GatewayProtocol protocol = new P3Asn1GatewayProtocol(service);

        byte[] unknown = BerCodec.encode(new BerTlv(2, true, 30, 0, 0, new byte[0]));
        byte[] response = protocol.handle(service.newSession(), unknown);

        BerTlv error = BerCodec.decodeSingle(response);
        assertEquals(P3Asn1GatewayProtocol.APDU_ERROR, error.tagNumber());
        assertEquals("unsupported-operation", decodeErrorField(error, 0));
    }

    @Test
    void returnsRoseRejectForMalformedRoseInvokeWithoutOperationCode() {
        StubSessionService service = new StubSessionService();
        P3Asn1GatewayProtocol protocol = new P3Asn1GatewayProtocol(service);

        byte[] malformedInvokeBody = BerCodec.encode(new BerTlv(0, true, 16, 0,
            BerCodec.encode(new BerTlv(0, false, 2, 0, 1, new byte[] { 0x01 })).length,
            BerCodec.encode(new BerTlv(0, false, 2, 0, 1, new byte[] { 0x01 }))));
        byte[] malformedInvoke = BerCodec.encode(new BerTlv(1, true, 1, 0, malformedInvokeBody.length, malformedInvokeBody));

        byte[] response = protocol.handle(service.newSession(), malformedInvoke);
        BerTlv roseReject = BerCodec.decodeSingle(response);

        assertEquals(1, roseReject.tagClass());
        assertEquals(4, roseReject.tagNumber());
    }

    @Test
    void rtseNestedScanSkipsContextZeroThatIsNotGatewayApdu() {
        RecordingSessionService service = new RecordingSessionService();
        P3Asn1GatewayProtocol protocol = new P3Asn1GatewayProtocol(service);

        byte[] fakeInnerContextZero = BerCodec.encode(new BerTlv(2, true, 0, 0,
            BerCodec.encode(new BerTlv(0, false, 2, 0, 1, new byte[] { 0x05 })).length,
            BerCodec.encode(new BerTlv(0, false, 2, 0, 1, new byte[] { 0x05 }))));

        byte[] bindPayload = concat(
            contextUtf8(0, "amhsuser"),
            contextUtf8(1, "changeit"),
            contextUtf8(2, "/C=IT/ADMD=ICAO/PRMD=ENAV/O=ENAV/OU1=LIRR/CN=alice"),
            contextUtf8(3, "ATFM")
        );
        byte[] realBindApdu = BerCodec.encode(new BerTlv(2, true, P3Asn1GatewayProtocol.APDU_BIND_REQUEST, 0, bindPayload.length, bindPayload));

        byte[] rtsePayload = concat(fakeInnerContextZero, realBindApdu);
        byte[] rtse = BerCodec.encode(new BerTlv(1, true, 16, 0, rtsePayload.length, rtsePayload));

        protocol.handle(service.newSession(), rtse);

        assertTrue(service.lastCommand.contains("username=amhsuser"));
        assertTrue(service.lastCommand.contains("channel=ATFM"));
    }



    @Test
    void rtseNestedScanRejectsContextApduWithUnexpectedFieldTags() {
        RecordingSessionService service = new RecordingSessionService();
        P3Asn1GatewayProtocol protocol = new P3Asn1GatewayProtocol(service);

        byte[] fakeBindPayload = contextUtf8(7, "noise");
        byte[] fakeBindApdu = BerCodec.encode(new BerTlv(2, true, P3Asn1GatewayProtocol.APDU_BIND_REQUEST, 0, fakeBindPayload.length, fakeBindPayload));

        byte[] submitPayload = concat(
            contextUtf8(0, "/C=IT/ADMD=ICAO/PRMD=ENAV/O=ENAV/OU1=LIRR/CN=bob"),
            contextUtf8(1, "subject"),
            contextUtf8(2, "body")
        );
        byte[] submitApdu = BerCodec.encode(new BerTlv(2, true, P3Asn1GatewayProtocol.APDU_SUBMIT_REQUEST, 0, submitPayload.length, submitPayload));

        byte[] rtsePayload = concat(fakeBindApdu, submitApdu);
        byte[] rtse = BerCodec.encode(new BerTlv(1, true, 16, 0, rtsePayload.length, rtsePayload));

        protocol.handle(service.newSession(), rtse);

        assertTrue(service.lastCommand.startsWith("SUBMIT"));
        assertTrue(service.lastCommand.contains("subject=subject"));
    }

    @Test
    void rtseNestedScanRejectsContextApduWithNonScalarFieldWrappers() {
        RecordingSessionService service = new RecordingSessionService();
        P3Asn1GatewayProtocol protocol = new P3Asn1GatewayProtocol(service);

        byte[] nestedSequence = BerCodec.encode(new BerTlv(0, true, 16, 0,
            BerCodec.encode(new BerTlv(0, false, 12, 0, 5, "inner".getBytes(StandardCharsets.UTF_8))).length,
            BerCodec.encode(new BerTlv(0, false, 12, 0, 5, "inner".getBytes(StandardCharsets.UTF_8)))));
        byte[] wrappedField = BerCodec.encode(new BerTlv(2, true, 0, 0, nestedSequence.length, nestedSequence));
        byte[] fakeBindApdu = BerCodec.encode(new BerTlv(2, true, P3Asn1GatewayProtocol.APDU_BIND_REQUEST, 0, wrappedField.length, wrappedField));

        byte[] bindPayload = concat(
            contextUtf8(0, "amhsuser"),
            contextUtf8(1, "changeit"),
            contextUtf8(2, "/C=IT/ADMD=ICAO/PRMD=ENAV/O=ENAV/OU1=LIRR/CN=alice"),
            contextUtf8(3, "ATFM")
        );
        byte[] realBindApdu = BerCodec.encode(new BerTlv(2, true, P3Asn1GatewayProtocol.APDU_BIND_REQUEST, 0, bindPayload.length, bindPayload));

        byte[] rtsePayload = concat(fakeBindApdu, realBindApdu);
        byte[] rtse = BerCodec.encode(new BerTlv(1, true, 16, 0, rtsePayload.length, rtsePayload));

        protocol.handle(service.newSession(), rtse);

        assertTrue(service.lastCommand.contains("username=amhsuser"));
        assertTrue(service.lastCommand.contains("channel=ATFM"));
    }

    @Test
    void returnsMalformedApduErrorForInvalidBerPayload() {
        P3Asn1GatewayProtocol protocol = new P3Asn1GatewayProtocol(new StubSessionService());

        byte[] response = protocol.handle(new StubSessionService().newSession(), new byte[] { (byte) 0xA0, 0x02, 0x01 });

        BerTlv error = BerCodec.decodeSingle(response);
        assertEquals(P3Asn1GatewayProtocol.APDU_ERROR, error.tagNumber());
        assertEquals("malformed-apdu", decodeErrorField(error, 0));
    }

    @Test
    void readPduRejectsIndefiniteLength() {
        P3Asn1GatewayProtocol protocol = new P3Asn1GatewayProtocol(new StubSessionService());

        assertThrows(IllegalArgumentException.class, () ->
            protocol.readPdu(new ByteArrayInputStream(new byte[] { (byte) 0xA0, (byte) 0x80 }))
        );
    }

    @Test
    void readPduRejectsTruncatedLongFormLength() {
        P3Asn1GatewayProtocol protocol = new P3Asn1GatewayProtocol(new StubSessionService());

        assertThrows(EOFException.class, () ->
            protocol.readPdu(new ByteArrayInputStream(new byte[] { (byte) 0xA0, (byte) 0x82, 0x01 }))
        );
    }

    @Test
    void readPduRejectsTruncatedValue() {
        P3Asn1GatewayProtocol protocol = new P3Asn1GatewayProtocol(new StubSessionService());

        assertThrows(EOFException.class, () ->
            protocol.readPdu(new ByteArrayInputStream(new byte[] { (byte) 0xA0, 0x02, 0x01 }))
        );
    }

    private static String decodeErrorField(BerTlv errorApdu, int fieldTag) {
        for (BerTlv field : BerCodec.decodeAll(errorApdu.value())) {
            if (field.tagClass() == 2 && field.tagNumber() == fieldTag) {
                BerTlv utf8 = BerCodec.decodeSingle(field.value());
                return new String(utf8.value(), StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    private static byte[] contextUtf8(int tagNumber, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        byte[] utf8 = BerCodec.encode(new BerTlv(0, false, 12, 0, bytes.length, bytes));
        return BerCodec.encode(new BerTlv(2, true, tagNumber, 0, utf8.length, utf8));
    }

    private static byte[] concat(byte[]... chunks) {
        int total = 0;
        for (byte[] chunk : chunks) {
            total += chunk.length;
        }
        byte[] merged = new byte[total];
        int offset = 0;
        for (byte[] chunk : chunks) {
            System.arraycopy(chunk, 0, merged, offset, chunk.length);
            offset += chunk.length;
        }
        return merged;
    }

    private static final class RecordingSessionService extends StubSessionService {
        private String lastCommand = "";

        @Override
        public String handleCommand(SessionState state, String rawCommand) {
            lastCommand = rawCommand;
            return super.handleCommand(state, rawCommand);
        }
    }
}
