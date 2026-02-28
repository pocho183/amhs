package it.amhs.service;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import it.amhs.asn1.BerCodec;
import it.amhs.asn1.BerTlv;

class P1AssociationProtocolTest {

    private final P1AssociationProtocol protocol = new P1AssociationProtocol();

    @Test
    void shouldDecodeBindWithIcaoP1AbstractSyntax() {
        byte[] bindPayload = concat(
            contextPrimitive(0, "CALLING-MTA"),
            contextPrimitive(1, "CALLED-MTA"),
            contextConstructed(2, BerCodec.encode(new BerTlv(0, false, 6, 0, 5, new byte[] {
                0x56, 0x00, 0x01, 0x06, 0x01
            })))
        );

        byte[] pdu = BerCodec.encode(new BerTlv(2, true, 0, 0, bindPayload.length, bindPayload));

        P1AssociationProtocol.Pdu decoded = protocol.decode(pdu);
        P1AssociationProtocol.BindPdu bind = assertInstanceOf(P1AssociationProtocol.BindPdu.class, decoded);

        assertEquals("2.6.0.1.6.1", bind.abstractSyntaxOid());
        assertEquals("CALLING-MTA", bind.callingMta().orElseThrow());
        assertEquals("CALLED-MTA", bind.calledMta().orElseThrow());
    }

    @Test
    void shouldDecodeTransferPdu() {
        byte[] messageBytes = "payload".getBytes(StandardCharsets.UTF_8);
        byte[] pdu = BerCodec.encode(new BerTlv(2, true, 1, 0, messageBytes.length, messageBytes));

        P1AssociationProtocol.Pdu decoded = protocol.decode(pdu);
        P1AssociationProtocol.TransferPdu transfer = assertInstanceOf(P1AssociationProtocol.TransferPdu.class, decoded);

        assertArrayEquals(messageBytes, transfer.messagePayload());
    }

    @Test
    void shouldRejectBindWithUnsupportedSyntax() {
        byte[] bindPayload = concat(
            contextConstructed(2, BerCodec.encode(new BerTlv(0, false, 6, 0, 5, new byte[] {
                0x56, 0x00, 0x01, 0x06, 0x02
            })))
        );

        byte[] pdu = BerCodec.encode(new BerTlv(2, true, 0, 0, bindPayload.length, bindPayload));

        assertThrows(IllegalArgumentException.class, () -> protocol.decode(pdu));
    }

    @Test
    void shouldEncodeErrorPdu() {
        byte[] error = protocol.encodeError("association", "bind required");
        P1AssociationProtocol.ErrorPdu decoded = assertInstanceOf(P1AssociationProtocol.ErrorPdu.class, protocol.decode(error));
        assertEquals("association", decoded.code());
        assertEquals("bind required", decoded.diagnostic());
    }

    @Test
    void shouldEncodeReleaseResultAsContext11() {
        byte[] release = protocol.encodeReleaseResult();
        BerTlv tlv = BerCodec.decodeSingle(release);
        assertEquals(2, tlv.tagClass());
        assertTrue(tlv.constructed());
        assertEquals(11, tlv.tagNumber());
    }

    private static byte[] contextPrimitive(int tag, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
        return BerCodec.encode(new BerTlv(2, false, tag, 0, bytes.length, bytes));
    }

    private static byte[] contextConstructed(int tag, byte[] value) {
        return BerCodec.encode(new BerTlv(2, true, tag, 0, value.length, value));
    }

    private static byte[] concat(byte[]... chunks) {
        int len = 0;
        for (byte[] chunk : chunks) {
            len += chunk.length;
        }
        byte[] out = new byte[len];
        int offset = 0;
        for (byte[] chunk : chunks) {
            System.arraycopy(chunk, 0, out, offset, chunk.length);
            offset += chunk.length;
        }
        return out;
    }
}
