package it.amhs.service;

import java.util.Set;

public final class X411TagMap {

    public static final int APDU_BIND = 0;
    public static final int APDU_TRANSFER = 1;
    public static final int APDU_RELEASE = 2;
    public static final int APDU_ABORT = 3;
    public static final int APDU_ERROR = 4;
    public static final int APDU_BIND_RESULT = 10;
    public static final int APDU_RELEASE_RESULT = 11;
    public static final int APDU_TRANSFER_RESULT = 12;

    public static final int BIND_CALLING_MTA = 0;
    public static final int BIND_CALLED_MTA = 1;
    public static final int BIND_ABSTRACT_SYNTAX = 2;
    public static final int BIND_PROTOCOL_VERSION = 3;
    public static final int BIND_AUTHENTICATION = 4;
    public static final int BIND_SECURITY = 5;
    public static final int BIND_MTS_APDU = 6;
    public static final int BIND_PRESENTATION_CONTEXT = 7;

    public static final int ENVELOPE_MTS_IDENTIFIER = 0;
    public static final int ENVELOPE_PER_RECIPIENT = 1;
    public static final int ENVELOPE_TRACE = 2;
    public static final int ENVELOPE_CONTENT_TYPE = 3;
    public static final int ENVELOPE_ORIGINATOR = 4;
    public static final int ENVELOPE_SECURITY_PARAMETERS = 5;
    public static final int ENVELOPE_EXTENSIONS = 6;

    private static final Set<Integer> ASSOCIATION_APDU_TAGS = Set.of(
        APDU_BIND,
        APDU_TRANSFER,
        APDU_RELEASE,
        APDU_ABORT,
        APDU_ERROR,
        APDU_BIND_RESULT,
        APDU_RELEASE_RESULT,
        APDU_TRANSFER_RESULT
    );

    private X411TagMap() {
    }

    public static void validateAssociationApduTag(int tagNumber) {
        if (!ASSOCIATION_APDU_TAGS.contains(tagNumber)) {
            throw new IllegalArgumentException("Unsupported X.411 association APDU tag [" + tagNumber + "]");
        }
    }
}
