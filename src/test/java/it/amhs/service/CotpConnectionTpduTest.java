package it.amhs.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;

class CotpConnectionTpduTest {

    @Test
    void shouldParseAndSerializeCrWithTpduSize() {
        CotpConnectionTpdu cr = new CotpConnectionTpdu(
            CotpConnectionTpdu.PDU_CR,
            0x1001,
            0x2002,
            0,
            Optional.of(4096),
            List.of(new CotpConnectionTpdu.Parameter((byte) 0xC1, new byte[] {0x01, 0x02}))
        );

        byte[] encoded = cr.serialize();
        CotpConnectionTpdu decoded = CotpConnectionTpdu.parse(encoded);

        assertEquals(CotpConnectionTpdu.PDU_CR, decoded.type());
        assertEquals(0x1001, decoded.destinationReference());
        assertEquals(0x2002, decoded.sourceReference());
        assertEquals(4096, decoded.negotiatedMaxUserData());
        assertEquals(1, decoded.unknownParameters().size());
    }

    @Test
    void shouldDefaultNegotiatedSizeWhenAbsent() {
        CotpConnectionTpdu cr = new CotpConnectionTpdu(CotpConnectionTpdu.PDU_CR, 1, 2, 0, Optional.empty(), List.of());
        assertTrue(cr.serialize().length >= 7);
        assertEquals(16_384, cr.negotiatedMaxUserData());
    }
}
