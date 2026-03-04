package it.amhs.service;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class X411TagMapTest {

    @Test
    void shouldRecognizeKnownBindAndEnvelopeFieldTags() {
        assertTrue(X411TagMap.isKnownBindFieldTag(X411TagMap.BIND_ABSTRACT_SYNTAX));
        assertTrue(X411TagMap.isKnownEnvelopeFieldTag(X411TagMap.ENVELOPE_ORIGINATOR));
        assertTrue(X411TagMap.isExtensionEnvelopeFieldTag(10));
        assertFalse(X411TagMap.isKnownBindFieldTag(99));
        assertFalse(X411TagMap.isKnownEnvelopeFieldTag(99));
    }


    @Test
    void shouldRejectNonContextAssociationTagClass() {
        assertThrows(
            IllegalArgumentException.class,
            () -> X411TagMap.validateAssociationApdu(new X411TagMap.BerApduTag(X411TagMap.TAG_CLASS_APPLICATION, X411TagMap.APDU_BIND))
        );
    }

    @Test
    void shouldRejectUnknownAssociationApduTag() {
        assertThrows(IllegalArgumentException.class, () -> X411TagMap.validateAssociationApduTag(9));
    }
}
