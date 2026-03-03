package it.amhs.service;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Optional;

import org.junit.jupiter.api.Test;

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
    void shouldEncodeAndDecodeAareApdu() {
        AcseModels.AAREApdu aare = new AcseModels.AAREApdu(true, Optional.of("accepted"));

        byte[] encoded = protocol.encode(aare);
        AcseModels.AcseApdu decoded = protocol.decode(encoded);

        assertEquals(0x61, encoded[0] & 0xFF, "AARE must use [APPLICATION 1]");
        assertEquals(aare, decoded);
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
}
