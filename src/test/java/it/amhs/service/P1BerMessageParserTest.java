package it.amhs.service;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import it.amhs.asn1.BerCodec;
import it.amhs.asn1.BerTlv;
import it.amhs.domain.AMHSPriority;
import it.amhs.domain.AMHSProfile;

class P1BerMessageParserTest {

    private final P1BerMessageParser parser = new P1BerMessageParser();

    @Test
    void shouldParseP1BerSequenceWithOptionalAndChoice() {
        byte[] content = concat(
            BerCodec.encode(new BerTlv(2, false, 0, 0, 8, "LIRRZQZX".getBytes(StandardCharsets.US_ASCII))),
            BerCodec.encode(new BerTlv(2, false, 1, 0, 8, "LIIRYAYX".getBytes(StandardCharsets.US_ASCII))),
            BerCodec.encode(new BerTlv(2, false, 2, 0, 5, "HELLO".getBytes(StandardCharsets.UTF_8))),
            BerCodec.encode(new BerTlv(2, false, 3, 0, 1, new byte[] {0x01})),
            BerCodec.encode(new BerTlv(2, false, 4, 0, 1, new byte[] {0x00})),
            BerCodec.encode(new BerTlv(2, false, 5, 0, 7, "SUBJECT".getBytes(StandardCharsets.UTF_8))),
            BerCodec.encode(new BerTlv(2, false, 8, 0, 15, "20260228120000Z".getBytes(StandardCharsets.US_ASCII)))
        );

        byte[] payload = BerCodec.encode(new BerTlv(0, true, 16, 0, content.length, content));
        P1BerMessageParser.ParsedP1Message parsed = parser.parse(payload);

        assertEquals("LIRRZQZX", parsed.from());
        assertEquals("LIIRYAYX", parsed.to());
        assertEquals("HELLO", parsed.body());
        assertEquals(AMHSProfile.P7, parsed.profile());
        assertEquals(AMHSPriority.SS, parsed.priority());
        assertEquals("SUBJECT", parsed.subject());
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
