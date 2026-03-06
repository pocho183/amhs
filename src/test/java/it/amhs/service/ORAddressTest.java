package it.amhs.service;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import it.amhs.service.address.ORAddress;

class ORAddressTest {

    @Test
    void shouldParseSemicolonSeparatedAddress() {
        assertDoesNotThrow(() -> ORAddress.parse("C=IT;A=ICAO;P=ROMA;O=ENAV;OU1=LIRRZQZX"));
    }

    @Test
    void shouldRejectUnsupportedAttribute() {
        assertThrows(IllegalArgumentException.class,
            () -> ORAddress.parse("C=IT/A=ICAO/P=ROMA/O=ENAV/OU1=LIRRZQZX/X121=12345"));
    }

    @Test
    void shouldRejectDisallowedCharacters() {
        assertThrows(IllegalArgumentException.class,
            () -> ORAddress.parse("C=IT/A=ICAO/P=ROMA/O=ENA+V/OU1=LIRRZQZX"));
    }

    @Test
    void shouldRejectAttributeExceedingMaxLength() {
        assertThrows(IllegalArgumentException.class,
            () -> ORAddress.parse("C=ITA/A=ICAO/P=ROMA/O=ENAV/OU1=LIRRZQZX"));
    }

    @Test
    void shouldAcceptNumericCountryCodesAndAdmdSpace() {
        ORAddress parsed = ORAddress.parse("C=380/A=\" \"/P=ROMA/O=ENAV/OU1=LIRRZQZX");
        assertEquals("380", parsed.get("C"));
        assertEquals(" ", parsed.get("ADMD"));
    }


    @Test
    void shouldAcceptAdditionalX402AttributesForInterop() {
        ORAddress parsed = ORAddress.parse("C=IT/A=ICAO/P=ROMA/O=ENAV/S=ROSSI/G=MARIO/I=MR/NUMUID=12345");
        assertEquals("ROSSI", parsed.get("S"));
        assertEquals("MARIO", parsed.get("G"));
        assertEquals("MR", parsed.get("I"));
        assertEquals("12345", parsed.get("NUMUID"));
    }

    @Test
    void shouldAcceptDomainDefinedAttributes() {
        ORAddress parsed = ORAddress.parse("C=IT/A=ICAO/P=ROMA/O=ENAV/DDA-CALLSIGN=AZA123");
        assertEquals("AZA123", parsed.get("DDA-CALLSIGN"));
    }

    @Test
    void shouldAcceptExtensionAttributes() {
        ORAddress parsed = ORAddress.parse("C=IT/A=ICAO/P=ROMA/O=ENAV/OU1=LIRRZQZX/EXT-CALLSIGN=AZ123");
        assertEquals("AZ123", parsed.get("EXT-CALLSIGN"));
    }
}
