package it.amhs.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import it.amhs.asn1.BerCodec;
import it.amhs.asn1.BerTlv;

class ORNameMapperTest {

    @Test
    void shouldDecodeDirectoryNameWithTeletexAndBmpStrings() {
        byte[] t61Cn = BerCodec.encode(new BerTlv(0, false, 20, 0, "LÍRRAFTN".getBytes(StandardCharsets.ISO_8859_1).length,
            "LÍRRAFTN".getBytes(StandardCharsets.ISO_8859_1)));
        byte[] bmpOu = BerCodec.encode(new BerTlv(0, false, 30, 0, "ATÇ".getBytes(StandardCharsets.UTF_16BE).length,
            "ATÇ".getBytes(StandardCharsets.UTF_16BE)));

        byte[] directoryName = sequence(
            sequence(t61Cn),
            sequence(bmpOu)
        );

        byte[] orAddress = sequence(
            contextPrimitive(0, "IT"),
            contextPrimitive(1, "ICAO"),
            contextPrimitive(2, "ROMA"),
            contextPrimitive(3, "ENAV"),
            contextT61(4, "LIRRZQZX")
        );

        byte[] orNameContent = concat(
            contextConstructed(0, directoryName),
            contextConstructed(1, orAddress)
        );

        ORNameMapper.ORName decoded = ORNameMapper.fromBer(new BerTlv(2, true, 4, 0, orNameContent.length, orNameContent));

        assertTrue(decoded.directoryName().isPresent());
        assertTrue(decoded.directoryName().orElseThrow().contains("LÍRRAFTN"));
        assertTrue(decoded.directoryName().orElseThrow().contains("ATÇ"));
        assertEquals("/C=IT/ADMD=ICAO/PRMD=ROMA/O=ENAV/OU1=LIRRZQZX", decoded.orAddress().toCanonicalString());
    }

    private static byte[] contextPrimitive(int tag, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
        return BerCodec.encode(new BerTlv(2, false, tag, 0, bytes.length, bytes));
    }

    private static byte[] contextT61(int tag, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.ISO_8859_1);
        byte[] t61 = BerCodec.encode(new BerTlv(0, false, 20, 0, bytes.length, bytes));
        return BerCodec.encode(new BerTlv(2, true, tag, 0, t61.length, t61));
    }

    private static byte[] contextConstructed(int tag, byte[] value) {
        return BerCodec.encode(new BerTlv(2, true, tag, 0, value.length, value));
    }

    private static byte[] sequence(byte[]... chunks) {
        byte[] out = concat(chunks);
        return BerCodec.encode(new BerTlv(0, true, 16, 0, out.length, out));
    }

    private static byte[] concat(byte[]... chunks) {
        int len = 0;
        for (byte[] c : chunks) {
            len += c.length;
        }
        byte[] out = new byte[len];
        int offset = 0;
        for (byte[] c : chunks) {
            System.arraycopy(c, 0, out, offset, c.length);
            offset += c.length;
        }
        return out;
    }
}
