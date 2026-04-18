package it.amhs.service.protocol.p3;

import it.amhs.asn1.BerCodec;
import it.amhs.asn1.BerTlv;
import it.amhs.service.protocol.p3.P3OperationModels.P3Error;
import it.amhs.service.protocol.p3.P3OperationModels.ReleaseRequest;
import it.amhs.service.protocol.p3.P3OperationModels.ReleaseResult;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

import static it.amhs.service.protocol.p3.P3WireSupport.*;

@Component
public class P3ReleaseCodec {

    private static final int RELEASE_REQUEST_TAG = 6;
    private static final int RELEASE_RESPONSE_TAG = 7;
    private static final int ERROR_TAG = 8;

    public boolean isLikelyReleaseRequest(byte[] encodedApdu) {
        if (encodedApdu == null || encodedApdu.length == 0) {
            return false;
        }

        try {
            BerTlv apdu = BerCodec.decodeSingle(encodedApdu);
            return apdu.tagClass() == TAG_CLASS_CONTEXT
                && apdu.constructed()
                && apdu.tagNumber() == RELEASE_REQUEST_TAG;
        } catch (RuntimeException ex) {
            return false;
        }
    }

    public ReleaseRequest decodeReleaseRequest(byte[] encodedApdu) {
        BerTlv apdu = BerCodec.decodeSingle(encodedApdu);
        if (apdu.tagClass() != TAG_CLASS_CONTEXT || !apdu.constructed() || apdu.tagNumber() != RELEASE_REQUEST_TAG) {
            throw new IllegalArgumentException("Not a release request APDU");
        }
        return new ReleaseRequest(encodedApdu);
    }

    public byte[] encodeReleaseResult(ReleaseResult ignored) {
        return BerCodec.encode(new BerTlv(TAG_CLASS_CONTEXT, true, RELEASE_RESPONSE_TAG, 0, 0, new byte[0]));
    }

    public byte[] encodeReleaseError(P3Error error) {
        List<byte[]> fields = new ArrayList<>();
        fields.add(encodeUtf8ContextField(0, error.code()));
        fields.add(encodeUtf8ContextField(1, error.detail()));
        fields.add(encodeUtf8ContextField(2, Boolean.toString(error.retryable())));

        byte[] payload = concat(fields);
        return BerCodec.encode(new BerTlv(TAG_CLASS_CONTEXT, true, ERROR_TAG, 0, payload.length, payload));
    }
}