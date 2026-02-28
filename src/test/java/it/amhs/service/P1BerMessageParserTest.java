package it.amhs.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
        assertEquals(AMHSProfile.P3, parsed.profile());
        assertEquals(AMHSPriority.SS, parsed.priority());
        assertEquals("SUBJECT", parsed.subject());
    }


    @Test
    void shouldParseP1ProfileValue() {
        byte[] content = concat(
            BerCodec.encode(new BerTlv(2, false, 0, 0, 8, "LIRRZQZX".getBytes(StandardCharsets.US_ASCII))),
            BerCodec.encode(new BerTlv(2, false, 1, 0, 8, "LIIRYAYX".getBytes(StandardCharsets.US_ASCII))),
            BerCodec.encode(new BerTlv(2, false, 2, 0, 5, "HELLO".getBytes(StandardCharsets.UTF_8))),
            BerCodec.encode(new BerTlv(2, false, 3, 0, 1, new byte[] {0x00}))
        );

        byte[] payload = BerCodec.encode(new BerTlv(0, true, 16, 0, content.length, content));
        P1BerMessageParser.ParsedP1Message parsed = parser.parse(payload);

        assertEquals(AMHSProfile.P1, parsed.profile());
    }

    @Test
    void shouldParseTransferEnvelopeWithMtsIdentifierPerRecipientTraceAndContentType() {
        byte[] mtsIdentifier = sequence(
            contextPrimitive(0, "MTS-ABC-123"),
            contextPrimitive(8, "20260228123045Z")
        );

        byte[] perRecipient = sequence(
            sequence(
                contextPrimitive(0, "LIIRYAYX"),
                contextEnumerated(1, 2)
            ),
            sequence(
                contextPrimitive(0, "LIRRZQZX")
            )
        );

        byte[] traceInformation = sequence(
            sequence(contextPrimitive(0, "MTA1")),
            sequence(contextPrimitive(0, "MTA2"))
        );

        byte[] envelope = sequence(
            contextConstructed(0, mtsIdentifier),
            contextConstructed(1, perRecipient),
            contextConstructed(2, traceInformation),
            contextConstructed(3, BerCodec.encode(new BerTlv(0, false, 6, 0, 9, new byte[] {
                0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x07, 0x01
            }))),
            contextPrimitive(4, "LIRRZQZX")
        );

        byte[] payloadContent = concat(
            contextPrimitive(2, "Hello envelope"),
            contextConstructed(9, envelope)
        );

        byte[] payload = BerCodec.encode(new BerTlv(0, true, 16, 0, payloadContent.length, payloadContent));
        P1BerMessageParser.ParsedP1Message parsed = parser.parse(payload);

        assertEquals("LIRRZQZX", parsed.from());
        assertEquals("LIIRYAYX", parsed.to());
        assertEquals("MTS-ABC-123", parsed.messageId());
        assertTrue(parsed.transferEnvelope().mtsIdentifier().isPresent());
        assertEquals("1.2.840.113549.1.7.1", parsed.transferEnvelope().contentTypeOid().orElseThrow());
        assertEquals(2, parsed.transferEnvelope().perRecipientFields().size());
        assertTrue(parsed.transferEnvelope().traceInformation().isPresent());
        assertEquals("MTA1", parsed.transferEnvelope().traceInformation().orElseThrow().hops().get(0));
    }


    private static byte[] contextUtf8(int tag, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        return BerCodec.encode(new BerTlv(2, false, tag, 0, bytes.length, bytes));
    }



    @Test
    void shouldParseEnvelopeSecurityParametersAndUnknownExtensions() {
        byte[] security = sequence(
            contextUtf8(0, "SECRET"),
            contextPrimitive(1, "TOKEN-1"),
            contextPrimitive(2, "1.2.3.4")
        );

        byte[] envelope = sequence(
            contextConstructed(5, security),
            contextPrimitive(10, "opaque")
        );

        byte[] payloadContent = concat(
            contextPrimitive(0, "LIRRZQZX"),
            contextPrimitive(1, "LIIRYAYX"),
            contextUtf8(2, "Hello"),
            contextConstructed(9, envelope)
        );
        byte[] payload = BerCodec.encode(new BerTlv(0, true, 16, 0, payloadContent.length, payloadContent));

        P1BerMessageParser.ParsedP1Message parsed = parser.parse(payload);
        assertEquals("SECRET", parsed.transferEnvelope().securityParameters().orElseThrow().securityLabel());
        assertEquals(1, parsed.transferEnvelope().unknownExtensions().size());
    }
    private static byte[] contextPrimitive(int tag, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
        return BerCodec.encode(new BerTlv(2, false, tag, 0, bytes.length, bytes));
    }

    private static byte[] contextEnumerated(int tag, int value) {
        return BerCodec.encode(new BerTlv(2, false, tag, 0, 1, new byte[] {(byte) value}));
    }

    private static byte[] contextConstructed(int tag, byte[] value) {
        return BerCodec.encode(new BerTlv(2, true, tag, 0, value.length, value));
    }

    private static byte[] sequence(byte[]... chunks) {
        byte[] content = concat(chunks);
        return BerCodec.encode(new BerTlv(0, true, 16, 0, content.length, content));
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
