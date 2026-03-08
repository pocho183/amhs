package it.amhs.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import it.amhs.asn1.BerCodec;
import it.amhs.asn1.BerTlv;
import it.amhs.domain.AMHSPriority;
import it.amhs.domain.AMHSProfile;
import it.amhs.compliance.SecurityLabelPolicy;
import it.amhs.service.protocol.p1.P1BerMessageParser;

class P1BerMessageParserTest {

    private final P1BerMessageParser parser = new P1BerMessageParser(new SecurityLabelPolicy());

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

    @Test
    void shouldParseConstructedUtf8FieldsFromContextTags() {
        byte[] from = contextConstructed(0, utf8Universal("LIRRZQZX"));
        byte[] to = contextConstructed(1, utf8Universal("LIIRYAYX"));
        byte[] body = contextConstructed(2, utf8Universal("HELLO"));
        byte[] subject = contextConstructed(5, utf8Universal("SUBJECT"));

        byte[] content = concat(from, to, body, subject);
        byte[] payload = BerCodec.encode(new BerTlv(0, true, 16, 0, content.length, content));

        P1BerMessageParser.ParsedP1Message parsed = parser.parse(payload);

        assertEquals("LIRRZQZX", parsed.from());
        assertEquals("LIIRYAYX", parsed.to());
        assertEquals("HELLO", parsed.body());
        assertEquals("SUBJECT", parsed.subject());
    }

    private static byte[] contextUtf8(int tag, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        return BerCodec.encode(new BerTlv(2, false, tag, 0, bytes.length, bytes));
    }


    @Test
    void shouldDecodeLegacyConstructedPrintableAddressingVector() {
        byte[] payloadContent = concat(
            contextConstructed(0, printableUniversal("LIRRZQZX")),
            contextConstructed(1, ia5Universal("LIIRYAYX")),
            contextConstructed(2, printableUniversal("LEGACY BODY")),
            contextConstructed(5, printableUniversal("OPS NOTICE"))
        );

        byte[] payload = BerCodec.encode(new BerTlv(0, true, 16, 0, payloadContent.length, payloadContent));
        P1BerMessageParser.ParsedP1Message parsed = parser.parse(payload);

        assertEquals("LIRRZQZX", parsed.from());
        assertEquals("LIIRYAYX", parsed.to());
        assertEquals("LEGACY BODY", parsed.body());
        assertEquals("OPS NOTICE", parsed.subject());
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


    @Test
    void shouldKeepBackwardCompatibilityWhenLegacyEnvelopeContainsExtensionAnchorOnly() {
        byte[] envelope = sequence(
            contextPrimitive(6, "legacy-anchor"),
            contextPrimitive(10, "opaque-extension")
        );

        byte[] payloadContent = concat(
            contextPrimitive(0, "LIRRZQZX"),
            contextPrimitive(1, "LIIRYAYX"),
            contextUtf8(2, "Hello"),
            contextConstructed(9, envelope)
        );
        byte[] payload = BerCodec.encode(new BerTlv(0, true, 16, 0, payloadContent.length, payloadContent));

        P1BerMessageParser.ParsedP1Message parsed = parser.parse(payload);
        assertEquals(1, parsed.transferEnvelope().unknownExtensions().size());
        assertEquals(10, parsed.transferEnvelope().unknownExtensions().get(0).tagNumber());
    }

    @Test
    void shouldIgnoreLegacyNonContextEnvelopeElementForBackwardCompatibility() {
        byte[] envelope = sequence(
            contextPrimitive(10, "opaque-extension"),
            BerCodec.encode(new BerTlv(0, false, 19, 0, 7, "LEGACY1".getBytes(StandardCharsets.US_ASCII)))
        );

        byte[] payloadContent = concat(
            contextPrimitive(0, "LIRRZQZX"),
            contextPrimitive(1, "LIIRYAYX"),
            contextUtf8(2, "Hello"),
            contextConstructed(9, envelope)
        );
        byte[] payload = BerCodec.encode(new BerTlv(0, true, 16, 0, payloadContent.length, payloadContent));

        P1BerMessageParser.ParsedP1Message parsed = parser.parse(payload);
        assertEquals(1, parsed.transferEnvelope().unknownExtensions().size());
        assertEquals(10, parsed.transferEnvelope().unknownExtensions().get(0).tagNumber());
    }


    @Test
    void shouldPreserveMultipleOperationalUnknownEnvelopeExtensions() {
        byte[] legacySetPayload = printableUniversal("IGNORED");
        byte[] envelope = sequence(
            contextPrimitive(10, "opaque-extension"),
            contextConstructed(11, sequence(contextPrimitive(0, "legacy-opaque"))),
            BerCodec.encode(new BerTlv(0, true, 17, 0, legacySetPayload.length, legacySetPayload))
        );

        byte[] payloadContent = concat(
            contextPrimitive(0, "LIRRZQZX"),
            contextPrimitive(1, "LIIRYAYX"),
            contextUtf8(2, "Hello"),
            contextConstructed(9, envelope)
        );
        byte[] payload = BerCodec.encode(new BerTlv(0, true, 16, 0, payloadContent.length, payloadContent));

        P1BerMessageParser.ParsedP1Message parsed = parser.parse(payload);
        assertEquals(2, parsed.transferEnvelope().unknownExtensions().size());
        assertEquals(10, parsed.transferEnvelope().unknownExtensions().get(0).tagNumber());
        assertEquals(11, parsed.transferEnvelope().unknownExtensions().get(1).tagNumber());
    }

    @Test
    void shouldPreserveHighTagOperationalUnknownEnvelopeExtensionOctets() {
        byte[] opaqueHighTagExtension = new byte[] {(byte) 0x81, 0x10, 0x42, 0x00};
        byte[] envelope = sequence(
            contextPrimitive(31, opaqueHighTagExtension)
        );

        byte[] payloadContent = concat(
            contextPrimitive(0, "LIRRZQZX"),
            contextPrimitive(1, "LIIRYAYX"),
            contextUtf8(2, "Hello"),
            contextConstructed(9, envelope)
        );
        byte[] payload = BerCodec.encode(new BerTlv(0, true, 16, 0, payloadContent.length, payloadContent));

        P1BerMessageParser.ParsedP1Message parsed = parser.parse(payload);
        assertEquals(1, parsed.transferEnvelope().unknownExtensions().size());
        assertEquals(31, parsed.transferEnvelope().unknownExtensions().get(0).tagNumber());
        assertArrayEquals(opaqueHighTagExtension, parsed.transferEnvelope().unknownExtensions().get(0).value());
    }

    @Test
    void shouldTreatLegacyCriticalityLikeOpaqueUnknownExtensionPayload() {
        byte[] legacyCriticalityPayload = sequence(
            contextPrimitive(0, "criticality=critical"),
            contextPrimitive(1, "peer-defined")
        );
        byte[] envelope = sequence(
            contextConstructed(12, legacyCriticalityPayload)
        );

        byte[] payloadContent = concat(
            contextPrimitive(0, "LIRRZQZX"),
            contextPrimitive(1, "LIIRYAYX"),
            contextUtf8(2, "Hello"),
            contextConstructed(9, envelope)
        );
        byte[] payload = BerCodec.encode(new BerTlv(0, true, 16, 0, payloadContent.length, payloadContent));

        P1BerMessageParser.ParsedP1Message parsed = parser.parse(payload);
        assertEquals(1, parsed.transferEnvelope().unknownExtensions().size());
        assertEquals(12, parsed.transferEnvelope().unknownExtensions().get(0).tagNumber());
        assertArrayEquals(legacyCriticalityPayload, parsed.transferEnvelope().unknownExtensions().get(0).value());
    }

    @Test
    void shouldRejectUnsupportedSecurityClassification() {
        byte[] security = sequence(
            contextUtf8(0, "COSMIC"),
            contextPrimitive(1, "TOKEN-1"),
            contextPrimitive(2, "1.2.3.4")
        );

        byte[] envelope = sequence(contextConstructed(5, security));

        byte[] payloadContent = concat(
            contextPrimitive(0, "LIRRZQZX"),
            contextPrimitive(1, "LIIRYAYX"),
            contextUtf8(2, "Hello"),
            contextConstructed(9, envelope)
        );
        byte[] payload = BerCodec.encode(new BerTlv(0, true, 16, 0, payloadContent.length, payloadContent));

        assertThrows(IllegalArgumentException.class, () -> parser.parse(payload));
    }

    @Test
    void shouldParseStructuredOrNameWithT61AndExtensionAttributes() {
        byte[] orAddress = sequence(
            contextPrimitive(0, "380"),
            contextPrimitive(1, " "),
            contextPrimitive(2, "ROMA"),
            contextPrimitive(3, "ENAV"),
            contextT61(4, "LIRRZQZX"),
            contextPrimitive(22, "OPS-EXT")
        );
        byte[] originatorOrName = sequence(
            contextPrimitive(0, "CN=OPS,OU=ATC,O=ENAV,C=IT"),
            contextConstructed(1, orAddress)
        );

        byte[] envelope = sequence(
            contextConstructed(4, originatorOrName),
            contextConstructed(1, sequence(sequence(contextPrimitive(0, "LIIRYAYX"))))
        );
        byte[] payloadContent = concat(
            contextUtf8(2, "Hello"),
            contextConstructed(9, envelope)
        );

        byte[] payload = BerCodec.encode(new BerTlv(0, true, 16, 0, payloadContent.length, payloadContent));
        P1BerMessageParser.ParsedP1Message parsed = parser.parse(payload);

        assertEquals("/C=380/ADMD= /PRMD=ROMA/O=ENAV/OU1=LIRRZQZX/EXT-CTX-22=OPS-EXT", parsed.from());
    }


    private static byte[] ia5Universal(String value) {
        byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
        return BerCodec.encode(new BerTlv(0, false, 22, 0, bytes.length, bytes));
    }

    private static byte[] printableUniversal(String value) {
        byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
        return BerCodec.encode(new BerTlv(0, false, 19, 0, bytes.length, bytes));
    }

    private static byte[] utf8Universal(String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        return BerCodec.encode(new BerTlv(0, false, 12, 0, bytes.length, bytes));
    }

    private static byte[] contextPrimitive(int tag, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
        return BerCodec.encode(new BerTlv(2, false, tag, 0, bytes.length, bytes));
    }

    private static byte[] contextPrimitive(int tag, byte[] value) {
        return BerCodec.encode(new BerTlv(2, false, tag, 0, value.length, value));
    }

    private static byte[] contextT61(int tag, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.ISO_8859_1);
        byte[] t61 = BerCodec.encode(new BerTlv(0, false, 20, 0, bytes.length, bytes));
        return BerCodec.encode(new BerTlv(2, true, tag, 0, t61.length, t61));
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
