package it.amhs.asn1;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class BerCodecTest {

    @Test
    void shouldEncodeAndDecodeSequence() {
        byte[] encoded = new byte[] {0x30, 0x07, (byte) 0x80, 0x02, 'A', 'A', (byte) 0x81, 0x01, 'B'};

        BerTlv decoded = BerCodec.decodeSingle(encoded);
        assertEquals(0, decoded.tagClass());
        assertEquals(16, decoded.tagNumber());
        assertEquals(7, decoded.length());
        assertArrayEquals(encoded, BerCodec.encode(decoded));
    }

    @Test
    void shouldRejectIndefiniteLength() {
        byte[] invalid = new byte[] {0x30, (byte) 0x80, 0x00, 0x00};
        assertThrows(IllegalArgumentException.class, () -> BerCodec.decodeSingle(invalid));
    }
}
