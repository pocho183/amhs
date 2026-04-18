package it.amhs.service.protocol.p3;

import static it.amhs.service.protocol.p3.P3WireSupport.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import it.amhs.asn1.BerCodec;
import it.amhs.asn1.BerTlv;
import it.amhs.service.protocol.p3.P3OperationModels.P3Error;
import it.amhs.service.protocol.p3.P3OperationModels.SubmitRequest;
import it.amhs.service.protocol.p3.P3OperationModels.SubmitResult;

@Component
public class P3SubmitCodec {

    private static final int SUBMIT_REQUEST_TAG = 2;
    private static final int SUBMIT_RESPONSE_TAG = 3;
    private static final int ERROR_TAG = 8;

    public boolean isLikelySubmitRequest(byte[] encodedApdu) {
        if (encodedApdu == null || encodedApdu.length == 0) {
            return false;
        }

        try {
            BerTlv apdu = BerCodec.decodeSingle(encodedApdu);
            return apdu.tagClass() == TAG_CLASS_CONTEXT
                && apdu.constructed()
                && apdu.tagNumber() == SUBMIT_REQUEST_TAG;
        } catch (RuntimeException ex) {
            return false;
        }
    }

    public SubmitRequest decodeSubmitRequest(byte[] encodedApdu) {
        BerTlv apdu = BerCodec.decodeSingle(encodedApdu);
        if (apdu.tagClass() != TAG_CLASS_CONTEXT || !apdu.constructed() || apdu.tagNumber() != SUBMIT_REQUEST_TAG) {
            throw new IllegalArgumentException("Not a submit request APDU");
        }

        Map<Integer, String> fields = decodeContextUtf8Fields(apdu.value());

        return new SubmitRequest(
            value(fields.get(0)),
            value(fields.get(1)),
            value(fields.get(2)),
            encodedApdu
        );
    }

    public byte[] encodeSubmitResult(SubmitResult result) {
        List<byte[]> fields = new ArrayList<>();
        fields.add(encodeUtf8ContextField(0, "submission-id=" + result.submissionId()));
        fields.add(encodeUtf8ContextField(1, "message-id=" + result.internalMessageId()));

        byte[] payload = concat(fields);
        return BerCodec.encode(new BerTlv(TAG_CLASS_CONTEXT, true, SUBMIT_RESPONSE_TAG, 0, payload.length, payload));
    }

    public byte[] encodeSubmitError(P3Error error) {
        List<byte[]> fields = new ArrayList<>();
        fields.add(encodeUtf8ContextField(0, error.code()));
        fields.add(encodeUtf8ContextField(1, error.detail()));
        fields.add(encodeUtf8ContextField(2, Boolean.toString(error.retryable())));

        byte[] payload = concat(fields);
        return BerCodec.encode(new BerTlv(TAG_CLASS_CONTEXT, true, ERROR_TAG, 0, payload.length, payload));
    }

    private Map<Integer, String> decodeContextUtf8Fields(byte[] payload) {
        Map<Integer, String> values = new HashMap<>();
        for (BerTlv field : decodeContextFieldList(payload)) {
            if (field.tagClass() != TAG_CLASS_CONTEXT) {
                continue;
            }

            if (field.constructed()) {
                List<String> atoms = collectTextualAtoms(field);
                if (!atoms.isEmpty()) {
                    values.put(field.tagNumber(), atoms.get(0));
                }
            } else {
                values.put(field.tagNumber(), new String(field.value(), java.nio.charset.StandardCharsets.UTF_8));
            }
        }
        return values;
    }

    private String value(String maybeNull) {
        return maybeNull == null ? "" : maybeNull;
    }
}