package it.amhs.service;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import it.amhs.asn1.BerCodec;
import it.amhs.asn1.BerTlv;

import org.junit.jupiter.api.Test;

import it.amhs.service.protocol.acse.AcseAssociationProtocol;
import it.amhs.service.protocol.acse.AcseModels;
import it.amhs.service.protocol.acse.PresentationContext;

class AcseAssociationProtocolTest {

    private final AcseAssociationProtocol protocol = new AcseAssociationProtocol();

    @Test
    void shouldEncodeAndDecodeAarqApdu() {
        AcseModels.AARQApdu aarq = new AcseModels.AARQApdu("2.6.0.1.6.1", Optional.of("CALLING"), Optional.of("CALLED"));

        byte[] encoded = protocol.encode(aarq);
        AcseModels.AcseApdu decoded = protocol.decode(encoded);

        assertEquals(0x60, encoded[0] & 0xFF, "AARQ must use [APPLICATION 0]");
        assertEquals(aarq, decoded);
    }

    @Test
    void shouldEncodeAndDecodeExtendedAarqFields() {
        byte[] auth = "secret".getBytes(StandardCharsets.US_ASCII);
        byte[] assocInfo = "p-context".getBytes(StandardCharsets.US_ASCII);
        AcseModels.AARQApdu aarq = new AcseModels.AARQApdu(
            "2.6.0.1.6.1",
            Optional.empty(),
            Optional.empty(),
            Optional.of(new AcseModels.ApTitle("1.2.840.113549")),
            Optional.of(new AcseModels.AeQualifier(4)),
            Optional.of(new AcseModels.ApTitle("1.3.6.1.4.1")),
            Optional.of(new AcseModels.AeQualifier(2)),
            Optional.of(auth),
            Optional.of(assocInfo),
            List.of("2.1.1", "2.1.2")
        );

        AcseModels.AARQApdu decoded = assertInstanceOf(AcseModels.AARQApdu.class, protocol.decode(protocol.encode(aarq)));

        assertEquals(aarq.applicationContextName(), decoded.applicationContextName());
        assertEquals(aarq.callingApTitle(), decoded.callingApTitle());
        assertEquals(aarq.calledApTitle(), decoded.calledApTitle());
        assertEquals(aarq.callingAeQualifier(), decoded.callingAeQualifier());
        assertEquals(aarq.calledAeQualifier(), decoded.calledAeQualifier());
        assertEquals(aarq.presentationContextOids(), decoded.presentationContextOids());
        assertArrayEquals(auth, decoded.authenticationValue().orElseThrow());
        assertArrayEquals(assocInfo, decoded.userInformation().orElseThrow());
    }

    @Test
    void shouldEncodeAndDecodeAareApdu() {
        AcseModels.AAREApdu aare = new AcseModels.AAREApdu(true, Optional.of("accepted"));

        byte[] encoded = protocol.encode(aare);
        AcseModels.AcseApdu decoded = protocol.decode(encoded);

        assertEquals(0x61, encoded[0] & 0xFF, "AARE must use [APPLICATION 1]");
        assertEquals(aare, decoded);
    }

    @Test
    void shouldEncodeAndDecodeResultSourceDiagnosticAndUserInformation() {
        byte[] userInfo = "assoc-info".getBytes(StandardCharsets.US_ASCII);
        AcseModels.AAREApdu aare = new AcseModels.AAREApdu(
            false,
            Optional.empty(),
            Optional.of(new AcseModels.ResultSourceDiagnostic(2, 1)),
            Optional.of(userInfo),
            List.of("1.0.9506.2.1")
        );

        AcseModels.AAREApdu decoded = assertInstanceOf(AcseModels.AAREApdu.class, protocol.decode(protocol.encode(aare)));

        assertEquals(aare.accepted(), decoded.accepted());
        assertEquals(aare.resultSourceDiagnostic(), decoded.resultSourceDiagnostic());
        assertEquals(aare.presentationContextOids(), decoded.presentationContextOids());
        assertArrayEquals(userInfo, decoded.userInformation().orElseThrow());
    }

    @Test
    void shouldEncodeAndDecodeReleaseAndAbortApdus() {
        AcseModels.RLRQApdu rlrq = new AcseModels.RLRQApdu(Optional.of("normal"));
        AcseModels.RLREApdu rlre = new AcseModels.RLREApdu(true);
        AcseModels.ABRTApdu abrt = new AcseModels.ABRTApdu("acse-service-provider", Optional.of("timeout"));

        assertEquals(rlrq, protocol.decode(protocol.encode(rlrq)));
        assertEquals(rlre, protocol.decode(protocol.encode(rlre)));
        assertEquals(abrt, protocol.decode(protocol.encode(abrt)));
    }


    @Test
    void shouldDecodeInteroperablePresentationContextDefinitionList() {
        byte[] appCtx = BerCodec.encode(new BerTlv(2, true, 1, 0, 8,
            BerCodec.encode(new BerTlv(0, false, 6, 0, 6, new byte[] {0x56, 0x00, 0x01, 0x06, 0x01, 0x01}))));

        byte[] contextId = BerCodec.encode(new BerTlv(0, false, 2, 0, 1, new byte[] {0x01}));
        byte[] abstractSyntax = BerCodec.encode(new BerTlv(0, false, 6, 0, 6, new byte[] {0x56, 0x00, 0x01, 0x06, 0x01, 0x01}));
        byte[] transferSyntax = BerCodec.encode(new BerTlv(0, false, 6, 0, 2, new byte[] {0x51, 0x01}));
        byte[] transferSyntaxList = BerCodec.encode(new BerTlv(0, true, 16, 0, transferSyntax.length, transferSyntax));
        byte[] contextItemPayload = concat(contextId, abstractSyntax, transferSyntaxList);
        byte[] contextItem = BerCodec.encode(new BerTlv(0, true, 16, 0, contextItemPayload.length, contextItemPayload));
        byte[] contextList = BerCodec.encode(new BerTlv(0, true, 16, 0, contextItem.length, contextItem));
        byte[] wrappedContextList = BerCodec.encode(new BerTlv(2, true, 29, 0, contextList.length, contextList));

        byte[] apduPayload = concat(appCtx, wrappedContextList);
        byte[] encoded = BerCodec.encode(new BerTlv(1, true, 0, 0, apduPayload.length, apduPayload));

        AcseModels.AARQApdu decoded = assertInstanceOf(AcseModels.AARQApdu.class, protocol.decode(encoded));

        assertEquals(List.of("2.6.0.1.6.1.1"), decoded.presentationContextOids());
    }


    @Test
    void shouldEncodeAndDecodeControlledPresentationContextNegotiation() {
        AcseModels.AARQApdu aarq = new AcseModels.AARQApdu(
            "2.6.0.1.6.1",
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            List.of("2.6.0.1.6.1.1"),
            List.of(
                new PresentationContext(1, "2.6.0.1.6.1.1", List.of("2.1.1")),
                new PresentationContext(3, "1.3.12.2.1011.1.1", List.of("2.1.1"))
            )
        );

        AcseModels.AARQApdu decodedAarq = assertInstanceOf(AcseModels.AARQApdu.class, protocol.decode(protocol.encode(aarq)));
        assertEquals(2, decodedAarq.presentationContexts().size());
        assertEquals(1, decodedAarq.presentationContexts().get(0).identifier());

        AcseModels.AAREApdu aare = new AcseModels.AAREApdu(
            true,
            Optional.of("accepted"),
            Optional.empty(),
            Optional.empty(),
            List.of("2.6.0.1.6.1.1"),
            java.util.Set.of(1)
        );

        AcseModels.AAREApdu decodedAare = assertInstanceOf(AcseModels.AAREApdu.class, protocol.decode(protocol.encode(aare)));
        assertEquals(java.util.Set.of(1), decodedAare.acceptedPresentationContextIds());
    }


    @Test
    void shouldDecodeLargeAeQualifierAndUtf8AeTitle() {
        byte[] appCtx = BerCodec.encode(new BerTlv(2, true, 1, 0, 8,
            BerCodec.encode(new BerTlv(0, false, 6, 0, 6, new byte[] {0x56, 0x00, 0x01, 0x06, 0x01, 0x01}))));

        byte[] callingApTitle = BerCodec.encode(new BerTlv(2, true, 6, 0, 5,
            BerCodec.encode(new BerTlv(0, false, 6, 0, 3, new byte[] {0x2A, 0x03, 0x04}))));
        byte[] callingQualifier = BerCodec.encode(new BerTlv(2, false, 7, 0, 2, new byte[] {0x01, 0x2C}));

        byte[] calledApTitle = BerCodec.encode(new BerTlv(2, true, 2, 0, 5,
            BerCodec.encode(new BerTlv(0, false, 6, 0, 3, new byte[] {0x2A, 0x03, 0x05}))));
        byte[] calledUtf8 = "DEST-Ü".getBytes(StandardCharsets.UTF_8);
        byte[] calledField = BerCodec.encode(new BerTlv(2, true, 3, 0,
            2 + calledUtf8.length,
            BerCodec.encode(new BerTlv(0, false, 12, 0, calledUtf8.length, calledUtf8))));

        byte[] payload = concat(appCtx, calledApTitle, calledField, callingApTitle, callingQualifier);
        byte[] encoded = BerCodec.encode(new BerTlv(1, true, 0, 0, payload.length, payload));

        AcseModels.AARQApdu decoded = assertInstanceOf(AcseModels.AARQApdu.class, protocol.decode(encoded));
        assertEquals(Optional.of(new AcseModels.AeQualifier(300)), decoded.callingAeQualifier());
        assertEquals(Optional.of("DEST-Ü"), decoded.calledAeTitle());
    }

    @Test
    void shouldDecodeAuthenticationValueEncodedAsPrintableString() {
        byte[] appCtx = BerCodec.encode(new BerTlv(2, true, 1, 0, 8,
            BerCodec.encode(new BerTlv(0, false, 6, 0, 6, new byte[] {0x56, 0x00, 0x01, 0x06, 0x01, 0x01}))));
        byte[] auth = "TOKEN-123".getBytes(StandardCharsets.US_ASCII);
        byte[] authField = BerCodec.encode(new BerTlv(2, true, 12, 0,
            2 + auth.length,
            BerCodec.encode(new BerTlv(0, false, 19, 0, auth.length, auth))));
        byte[] payload = concat(appCtx, authField);
        byte[] encoded = BerCodec.encode(new BerTlv(1, true, 0, 0, payload.length, payload));

        AcseModels.AARQApdu decoded = assertInstanceOf(AcseModels.AARQApdu.class, protocol.decode(encoded));
        assertArrayEquals("TOKEN-123".getBytes(StandardCharsets.UTF_8), decoded.authenticationValue().orElseThrow());
    }


    @Test
    void shouldDecodeAuthenticationValueEncodedAsBmpString() {
        byte[] appCtx = BerCodec.encode(new BerTlv(2, true, 1, 0, 8,
            BerCodec.encode(new BerTlv(0, false, 6, 0, 6, new byte[] {0x56, 0x00, 0x01, 0x06, 0x01, 0x01}))));
        byte[] auth = "ÄÖ".getBytes(StandardCharsets.UTF_16BE);
        byte[] authField = BerCodec.encode(new BerTlv(2, true, 12, 0,
            2 + auth.length,
            BerCodec.encode(new BerTlv(0, false, 30, 0, auth.length, auth))));
        byte[] payload = concat(appCtx, authField);
        byte[] encoded = BerCodec.encode(new BerTlv(1, true, 0, 0, payload.length, payload));

        AcseModels.AARQApdu decoded = assertInstanceOf(AcseModels.AARQApdu.class, protocol.decode(encoded));
        assertArrayEquals("ÄÖ".getBytes(StandardCharsets.UTF_8), decoded.authenticationValue().orElseThrow());
    }

    @Test
    void shouldDecodeCalledAeTitleEncodedAsBmpString() {
        byte[] appCtx = BerCodec.encode(new BerTlv(2, true, 1, 0, 8,
            BerCodec.encode(new BerTlv(0, false, 6, 0, 6, new byte[] {0x56, 0x00, 0x01, 0x06, 0x01, 0x01}))));

        byte[] calledApTitle = BerCodec.encode(new BerTlv(2, true, 2, 0, 5,
            BerCodec.encode(new BerTlv(0, false, 6, 0, 3, new byte[] {0x2A, 0x03, 0x05}))));
        byte[] calledBmp = "DEST-Ä".getBytes(StandardCharsets.UTF_16BE);
        byte[] calledField = BerCodec.encode(new BerTlv(2, true, 3, 0,
            2 + calledBmp.length,
            BerCodec.encode(new BerTlv(0, false, 30, 0, calledBmp.length, calledBmp))));

        byte[] payload = concat(appCtx, calledApTitle, calledField);
        byte[] encoded = BerCodec.encode(new BerTlv(1, true, 0, 0, payload.length, payload));

        AcseModels.AARQApdu decoded = assertInstanceOf(AcseModels.AARQApdu.class, protocol.decode(encoded));
        assertEquals(Optional.of("DEST-Ä"), decoded.calledAeTitle());
    }

    @Test
    void shouldRejectPresentationContextDefinitionWithTrailingFields() {
        byte[] appCtx = BerCodec.encode(new BerTlv(2, true, 1, 0, 8,
            BerCodec.encode(new BerTlv(0, false, 6, 0, 6, new byte[] {0x56, 0x00, 0x01, 0x06, 0x01, 0x01}))));

        byte[] contextId = BerCodec.encode(new BerTlv(0, false, 2, 0, 1, new byte[] {0x01}));
        byte[] abstractSyntax = BerCodec.encode(new BerTlv(0, false, 6, 0, 6, new byte[] {0x56, 0x00, 0x01, 0x06, 0x01, 0x01}));
        byte[] transferSyntax = BerCodec.encode(new BerTlv(0, false, 6, 0, 2, new byte[] {0x51, 0x01}));
        byte[] transferSyntaxList = BerCodec.encode(new BerTlv(0, true, 16, 0, transferSyntax.length, transferSyntax));
        byte[] trailing = BerCodec.encode(new BerTlv(0, false, 5, 0, 0, new byte[0]));
        byte[] contextItemPayload = concat(contextId, abstractSyntax, transferSyntaxList, trailing);
        byte[] contextItem = BerCodec.encode(new BerTlv(0, true, 16, 0, contextItemPayload.length, contextItemPayload));
        byte[] contextList = BerCodec.encode(new BerTlv(0, true, 16, 0, contextItem.length, contextItem));
        byte[] wrappedContextList = BerCodec.encode(new BerTlv(2, true, 29, 0, contextList.length, contextList));

        byte[] apduPayload = concat(appCtx, wrappedContextList);
        byte[] encoded = BerCodec.encode(new BerTlv(1, true, 0, 0, apduPayload.length, apduPayload));

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> protocol.decode(encoded));
        assertTrue(ex.getMessage().contains("identifier, abstract syntax and transfer syntax list"));
    }

    @Test
    void shouldRejectDuplicatePresentationContextIdentifiers() {
        PresentationContext first = new PresentationContext(1, "2.6.0.1.6.1.1", List.of("2.1.1"));
        PresentationContext duplicate = new PresentationContext(1, "1.3.12.2.1011.1.1", List.of("2.1.1"));
        AcseModels.AARQApdu aarq = new AcseModels.AARQApdu(
            "2.6.0.1.6.1",
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            List.of("2.6.0.1.6.1.1", "1.3.12.2.1011.1.1"),
            List.of(first, duplicate)
        );

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> protocol.decode(protocol.encode(aarq)));
        assertTrue(ex.getMessage().contains("unique odd positive integer"));
    }

    @Test
    void shouldRejectNonApplicationClassApdus() {
        byte[] invalidApdu = new byte[] {0x30, 0x00};
        assertThrows(IllegalArgumentException.class, () -> protocol.decode(invalidApdu));
    }

    @Test
    void shouldProvideStableEncodingForInteroperabilityTests() {
        AcseModels.AAREApdu rejected = new AcseModels.AAREApdu(false, Optional.empty());

        byte[] encoded = protocol.encode(rejected);

        assertArrayEquals(new byte[] {(byte) 0x61, 0x03, (byte) 0x82, 0x01, 0x01}, encoded);
    }

    @Test
    void shouldDecodeUserInformationWithMultipleExternalElementsUsingFirstPayload() {
        byte[] appCtx = BerCodec.encode(new BerTlv(2, true, 1, 0, 8,
            BerCodec.encode(new BerTlv(0, false, 6, 0, 6, new byte[] {0x56, 0x00, 0x01, 0x06, 0x01, 0x01}))));

        byte[] assocInfo = BerCodec.encode(new BerTlv(0, false, 4, 0, 1, new byte[] {0x41}));
        byte[] external = BerCodec.encode(new BerTlv(0, true, 8, 0, assocInfo.length, assocInfo));
        byte[] userInfoSequencePayload = concat(external, external);
        byte[] userInfoSequence = BerCodec.encode(new BerTlv(0, true, 16, 0, userInfoSequencePayload.length, userInfoSequencePayload));
        byte[] wrappedUserInfo = BerCodec.encode(new BerTlv(2, true, 30, 0, userInfoSequence.length, userInfoSequence));

        byte[] apduPayload = concat(appCtx, wrappedUserInfo);
        byte[] encoded = BerCodec.encode(new BerTlv(1, true, 0, 0, apduPayload.length, apduPayload));

        AcseModels.AARQApdu decoded = assertInstanceOf(AcseModels.AARQApdu.class, protocol.decode(encoded));
        assertArrayEquals(new byte[] {0x41}, decoded.userInformation().orElseThrow());
    }

    @Test
    void shouldDecodeUserInformationExternalWithTrailingElements() {
        byte[] appCtx = BerCodec.encode(new BerTlv(2, true, 1, 0, 8,
            BerCodec.encode(new BerTlv(0, false, 6, 0, 6, new byte[] {0x56, 0x00, 0x01, 0x06, 0x01, 0x01}))));

        byte[] assocInfo = BerCodec.encode(new BerTlv(0, false, 4, 0, 1, new byte[] {0x41}));
        byte[] trailingOid = BerCodec.encode(new BerTlv(0, false, 6, 0, 2, new byte[] {0x51, 0x01}));
        byte[] externalPayload = concat(assocInfo, trailingOid);
        byte[] external = BerCodec.encode(new BerTlv(0, true, 8, 0, externalPayload.length, externalPayload));
        byte[] userInfoSequence = BerCodec.encode(new BerTlv(0, true, 16, 0, external.length, external));
        byte[] wrappedUserInfo = BerCodec.encode(new BerTlv(2, true, 30, 0, userInfoSequence.length, userInfoSequence));

        byte[] apduPayload = concat(appCtx, wrappedUserInfo);
        byte[] encoded = BerCodec.encode(new BerTlv(1, true, 0, 0, apduPayload.length, apduPayload));

        AcseModels.AARQApdu decoded = assertInstanceOf(AcseModels.AARQApdu.class, protocol.decode(encoded));
        assertArrayEquals(new byte[] {0x41}, decoded.userInformation().orElseThrow());
    }

    @Test
    void shouldDecodeUserInformationExternalWithOctetAlignedEncoding() {
        byte[] appCtx = BerCodec.encode(new BerTlv(2, true, 1, 0, 8,
            BerCodec.encode(new BerTlv(0, false, 6, 0, 6, new byte[] {0x56, 0x00, 0x01, 0x06, 0x01, 0x01}))));

        byte[] directReference = BerCodec.encode(new BerTlv(0, false, 6, 0, 2, new byte[] {0x51, 0x01}));
        byte[] octetAligned = BerCodec.encode(new BerTlv(2, false, 1, 0, 3, new byte[] {0x41, 0x42, 0x43}));
        byte[] externalPayload = concat(directReference, octetAligned);
        byte[] external = BerCodec.encode(new BerTlv(0, true, 8, 0, externalPayload.length, externalPayload));
        byte[] userInfoSequence = BerCodec.encode(new BerTlv(0, true, 16, 0, external.length, external));
        byte[] wrappedUserInfo = BerCodec.encode(new BerTlv(2, true, 30, 0, userInfoSequence.length, userInfoSequence));

        byte[] apduPayload = concat(appCtx, wrappedUserInfo);
        byte[] encoded = BerCodec.encode(new BerTlv(1, true, 0, 0, apduPayload.length, apduPayload));

        AcseModels.AARQApdu decoded = assertInstanceOf(AcseModels.AARQApdu.class, protocol.decode(encoded));
        assertArrayEquals("ABC".getBytes(StandardCharsets.US_ASCII), decoded.userInformation().orElseThrow());
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

}
