package it.amhs.service;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;

import org.junit.jupiter.api.Test;

import it.amhs.service.protocol.p1.X411TagMap;

class X411CanonicalModuleConformanceTest {

    private static final Set<Integer> CANONICAL_ASSOCIATION_APDU_TAGS = Set.of(
        0, 1, 2, 3, 4, 10, 11, 12, 13, 14
    );

    @Test
    void shouldValidateCanonicalAssociationApduTagTable() {
        for (int tag : CANONICAL_ASSOCIATION_APDU_TAGS) {
            X411TagMap.validateAssociationApduTag(tag);
        }

        for (int unknown : Set.of(5, 6, 7, 8, 9, 15)) {
            assertThrows(IllegalArgumentException.class, () -> X411TagMap.validateAssociationApduTag(unknown));
        }
    }

    @Test
    void shouldValidateCanonicalBindAndEnvelopeBaseFieldTables() {
        for (int bindTag : Set.of(
            X411TagMap.BIND_CALLING_MTA,
            X411TagMap.BIND_CALLED_MTA,
            X411TagMap.BIND_ABSTRACT_SYNTAX,
            X411TagMap.BIND_PROTOCOL_VERSION,
            X411TagMap.BIND_AUTHENTICATION,
            X411TagMap.BIND_SECURITY,
            X411TagMap.BIND_MTS_APDU,
            X411TagMap.BIND_PRESENTATION_CONTEXT
        )) {
            assertTrue(X411TagMap.isKnownBindFieldTag(bindTag));
        }

        for (int envelopeTag : Set.of(
            X411TagMap.ENVELOPE_MTS_IDENTIFIER,
            X411TagMap.ENVELOPE_PER_RECIPIENT,
            X411TagMap.ENVELOPE_TRACE,
            X411TagMap.ENVELOPE_CONTENT_TYPE,
            X411TagMap.ENVELOPE_ORIGINATOR,
            X411TagMap.ENVELOPE_SECURITY_PARAMETERS,
            X411TagMap.ENVELOPE_EXTENSIONS
        )) {
            assertTrue(X411TagMap.isKnownEnvelopeFieldTag(envelopeTag));
        }

        assertFalse(X411TagMap.isKnownBindFieldTag(99));
        assertFalse(X411TagMap.isKnownEnvelopeFieldTag(99));
        assertTrue(X411TagMap.isExtensionEnvelopeFieldTag(7));
    }
}
