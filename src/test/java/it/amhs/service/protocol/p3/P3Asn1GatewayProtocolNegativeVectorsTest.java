package it.amhs.service.protocol.p3;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.EOFException;

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
                return new String(utf8.value());
            }
        }
        return null;
    }
}
