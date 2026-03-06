package it.amhs.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import it.amhs.asn1.BerCodec;
import it.amhs.asn1.BerTlv;
import it.amhs.service.protocol.p1.IncomingMessageParser;
import it.amhs.service.protocol.p1.P1BerMessageParser;
import it.amhs.service.protocol.rfc1006.RFC1006Service;

class IncomingMessageParserTest {

    private final IncomingMessageParser parser = new IncomingMessageParser(new P1BerMessageParser(), "LOCAL-MTA", "LOCAL");

    @Test
    void shouldParseBerPayloadEvenWhenPrefixedByGarbageBytes() {
        byte[] ber = sampleBerPayload("LIRRZQZX", "LIIRYAYX", "HELLO-BER");
        byte[] prefixed = new byte[ber.length + 3];
        prefixed[0] = 0x01;
        prefixed[1] = 0x02;
        prefixed[2] = 0x03;
        System.arraycopy(ber, 0, prefixed, 3, ber.length);

        RFC1006Service.IncomingMessage parsed = parser.parse(prefixed, new String(prefixed, StandardCharsets.UTF_8), null, null);

        assertEquals("LIRRZQZX", parsed.from());
        assertEquals("LIIRYAYX", parsed.to());
        assertEquals("HELLO-BER", parsed.body());
    }

    @Test
    void shouldPreferHexBodyForBinaryPayloadWhenHeadersAreMissing() {
        byte[] binary = new byte[] {(byte) 0xEF, (byte) 0xBB, (byte) 0xA2, 0x00, 0x11, (byte) 0xFF};
        String decoded = new String(binary, StandardCharsets.UTF_8);

        RFC1006Service.IncomingMessage parsed = parser.parse(binary, decoded, null, null);

        assertEquals("UNKNOWN_FROM", parsed.from());
        assertEquals("UNKNOWN_TO", parsed.to());
        assertEquals("EFBBA20011FF", parsed.body());
        assertNotEquals(decoded, parsed.body());
    }

    private static byte[] sampleBerPayload(String from, String to, String body) {
        byte[] content = concat(
            contextPrimitive(0, from),
            contextPrimitive(1, to),
            contextUtf8(2, body)
        );
        return BerCodec.encode(new BerTlv(0, true, 16, 0, content.length, content));
    }

    private static byte[] contextPrimitive(int tag, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
        return BerCodec.encode(new BerTlv(2, false, tag, 0, bytes.length, bytes));
    }

    private static byte[] contextUtf8(int tag, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        return BerCodec.encode(new BerTlv(2, false, tag, 0, bytes.length, bytes));
    }

    private static byte[] concat(byte[]... chunks) {
        int len = 0;
        for (byte[] chunk : chunks) {
            len += chunk.length;
        }

        byte[] combined = new byte[len];
        int offset = 0;
        for (byte[] chunk : chunks) {
            System.arraycopy(chunk, 0, combined, offset, chunk.length);
            offset += chunk.length;
        }
        return combined;
    }
}
