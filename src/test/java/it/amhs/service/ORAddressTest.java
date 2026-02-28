package it.amhs.service;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

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
}
