package it.amhs.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import it.amhs.asn1.BerCodec;
import it.amhs.asn1.BerTlv;
import it.amhs.service.address.ORNameMapper;

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

    @Test
    void shouldDecodeDirectoryNameChoiceWithRdnAttributes() {
        byte[] cnAtv = sequence(
            oid("2.5.4.3"),
            printable("LIRRATCX")
        );
        byte[] ouAtv = sequence(
            oid("2.5.4.11"),
            universal("AMHS")
        );

        byte[] name = sequence(
            set(cnAtv),
            set(ouAtv)
        );

        BerTlv directoryNameChoice = new BerTlv(2, true, 0, 0, name.length, name);
        ORNameMapper.ORName decoded = ORNameMapper.fromBer(directoryNameChoice);

        assertEquals("CN=LIRRATCX,OU=AMHS", decoded.directoryName().orElseThrow());
        assertEquals("/CN=CN=LIRRATCX,OU=AMHS", decoded.orAddress().toCanonicalString());
    }

    private static byte[] printable(String value) {
        byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
        return BerCodec.encode(new BerTlv(0, false, 19, 0, bytes.length, bytes));
    }

    private static byte[] universal(String value) {
        int[] cps = value.codePoints().toArray();
        byte[] bytes = new byte[cps.length * 4];
        for (int i = 0; i < cps.length; i++) {
            int cp = cps[i];
            bytes[i * 4] = (byte) ((cp >>> 24) & 0xFF);
            bytes[i * 4 + 1] = (byte) ((cp >>> 16) & 0xFF);
            bytes[i * 4 + 2] = (byte) ((cp >>> 8) & 0xFF);
            bytes[i * 4 + 3] = (byte) (cp & 0xFF);
        }
        return BerCodec.encode(new BerTlv(0, false, 28, 0, bytes.length, bytes));
    }

    private static byte[] oid(String dotted) {
        String[] parts = dotted.split("\\.");
        byte[] out = new byte[16];
        int cursor = 0;
        int first = Integer.parseInt(parts[0]);
        int second = Integer.parseInt(parts[1]);
        out[cursor++] = (byte) (first * 40 + second);
        for (int i = 2; i < parts.length; i++) {
            long v = Long.parseLong(parts[i]);
            int start = cursor;
            do {
                out[cursor++] = (byte) (v & 0x7F);
                v >>>= 7;
            } while (v > 0);
            for (int l = start, r = cursor - 1; l < r; l++, r--) {
                byte t = out[l];
                out[l] = out[r];
                out[r] = t;
            }
            for (int j = start; j < cursor - 1; j++) {
                out[j] |= (byte) 0x80;
            }
        }
        byte[] encoded = new byte[cursor];
        System.arraycopy(out, 0, encoded, 0, cursor);
        return BerCodec.encode(new BerTlv(0, false, 6, 0, encoded.length, encoded));
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

    private static byte[] set(byte[]... chunks) {
        byte[] out = concat(chunks);
        return BerCodec.encode(new BerTlv(0, true, 17, 0, out.length, out));
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
