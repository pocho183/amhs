package it.amhs.service.protocol.p3;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import it.amhs.asn1.BerCodec;
import it.amhs.asn1.BerTlv;

/**
 * BER/ASN.1 gateway protocol for P3 ingress.
 *
 * <p>This codec provides a binary protocol surface for the AMHS P3 gateway and maps
 * APDUs to the existing session service workflow (bind/submit/status/release).
 */
@Component
public class P3Asn1GatewayProtocol {

    private static final Logger logger = LoggerFactory.getLogger(P3Asn1GatewayProtocol.class);

    private static final int TAG_CLASS_CONTEXT = 2;
    private static final int TAG_CLASS_APPLICATION = 1;
    private static final int TAG_CLASS_UNIVERSAL = 0;
    private static final int TAG_UNIVERSAL_SEQUENCE = 16;

    private static final int ROSE_INVOKE = 1;
    private static final int ROSE_RETURN_RESULT = 2;
    private static final int ROSE_RETURN_ERROR = 3;
    private static final int ROSE_REJECT = 4;

    private static final int RTSE_RTORQ = 16;
    private static final int RTSE_RTOAC = 17;
    private static final int RTSE_RTORJ = 18;
    private static final int RTSE_RTAB = 19;
    private static final int RTSE_RTTR = 21;
    private static final int RTSE_RTTD = 22;

    static final int APDU_BIND_REQUEST = 0;
    static final int APDU_BIND_RESPONSE = 1;
    static final int APDU_SUBMIT_REQUEST = 2;
    static final int APDU_SUBMIT_RESPONSE = 3;
    static final int APDU_STATUS_REQUEST = 4;
    static final int APDU_STATUS_RESPONSE = 5;
    static final int APDU_RELEASE_REQUEST = 6;
    static final int APDU_RELEASE_RESPONSE = 7;
    static final int APDU_REPORT_REQUEST = 9;
    static final int APDU_REPORT_RESPONSE = 10;
    static final int APDU_ERROR = 8;

    private final P3GatewaySessionService sessionService;

    public P3Asn1GatewayProtocol(P3GatewaySessionService sessionService) {
        this.sessionService = sessionService;
    }

    public byte[] handle(P3GatewaySessionService.SessionState session, byte[] encodedPdu) {
        BerTlv apdu = BerCodec.decodeSingle(encodedPdu);
        logger.info("P3 ASN.1 incoming APDU tagClass={} constructed={} tagNumber={} len={}", apdu.tagClass(), apdu.constructed(), apdu.tagNumber(), apdu.length());

        if (isRtseApdu(apdu)) {
            return handleRtse(session, apdu);
        }

        if (isRoseInvoke(apdu)) {
            return handleRoseInvoke(session, apdu);
        }

        if (apdu.tagClass() != TAG_CLASS_CONTEXT || !apdu.constructed()) {
            return error("invalid-apdu", "Expected context-specific constructed APDU");
        }

        return switch (apdu.tagNumber()) {
            case APDU_BIND_REQUEST -> mapBind(session, apdu.value());
            case APDU_SUBMIT_REQUEST -> mapSubmit(session, apdu.value());
            case APDU_STATUS_REQUEST -> mapStatus(session, apdu.value());
            case APDU_REPORT_REQUEST -> mapReport(session, apdu.value());
            case APDU_RELEASE_REQUEST -> mapRelease(session);
            default -> error("unsupported-operation", "Unsupported APDU " + apdu.tagNumber());
        };
    }

    private boolean isRtseApdu(BerTlv apdu) {
        return apdu.constructed()
            && apdu.tagClass() == TAG_CLASS_APPLICATION
            && apdu.tagNumber() >= RTSE_RTORQ
            && apdu.tagNumber() <= RTSE_RTTD;
    }

    private byte[] handleRtse(P3GatewaySessionService.SessionState session, BerTlv rtseApdu) {
        if (rtseApdu.tagNumber() == RTSE_RTAB) {
            String response = sessionService.handleCommand(session, "UNBIND");
            if (response.startsWith("OK")) {
                return wrapRtseResponse(RTSE_RTAB, envelope(APDU_RELEASE_RESPONSE, new byte[0]));
            }
            return wrapRtseResponse(RTSE_RTAB, errorFromResponse(response));
        }

        byte[] nestedApdu = findGatewayOrRoseApdu(rtseApdu);
        if (nestedApdu == null) {
            return wrapRtseResponse(rtseApdu.tagNumber(), error("unsupported-operation", "RTSE APDU did not contain a supported gateway operation"));
        }

        byte[] nestedResponse = handle(session, nestedApdu);
        return wrapRtseResponse(rtseApdu.tagNumber(), nestedResponse);
    }

    private byte[] findGatewayOrRoseApdu(BerTlv tlv) {
        if (isRoseInvoke(tlv)
            || (tlv.tagClass() == TAG_CLASS_CONTEXT && tlv.constructed() && isGatewayApduTag(tlv.tagNumber()))) {
            return BerCodec.encode(tlv);
        }
        if (!tlv.constructed()) {
            return null;
        }
        for (BerTlv nested : BerCodec.decodeAll(tlv.value())) {
            byte[] found = findGatewayOrRoseApdu(nested);
            if (found != null) {
                return found;
            }
        }
        return null;
    }

    private boolean isGatewayApduTag(int tagNumber) {
        return tagNumber >= APDU_BIND_REQUEST && tagNumber <= APDU_REPORT_RESPONSE;
    }

    private byte[] wrapRtseResponse(int inboundRtseTag, byte[] nestedResponse) {
        int responseTag = switch (inboundRtseTag) {
            case RTSE_RTORQ -> RTSE_RTOAC;
            case RTSE_RTTD -> RTSE_RTTR;
            case RTSE_RTOAC, RTSE_RTTR -> RTSE_RTORJ;
            case RTSE_RTORJ, RTSE_RTAB -> inboundRtseTag;
            default -> RTSE_RTORJ;
        };
        byte[] any = BerCodec.encode(new BerTlv(TAG_CLASS_CONTEXT, true, 0, 0, nestedResponse.length, nestedResponse));
        return BerCodec.encode(new BerTlv(TAG_CLASS_APPLICATION, true, responseTag, 0, any.length, any));
    }

    private boolean isRoseInvoke(BerTlv apdu) {
        return apdu.constructed()
            && apdu.tagNumber() == ROSE_INVOKE
            && (apdu.tagClass() == TAG_CLASS_APPLICATION || apdu.tagClass() == TAG_CLASS_CONTEXT);
    }

    private byte[] handleRoseInvoke(P3GatewaySessionService.SessionState session, BerTlv invoke) {
        try {
            RoseInvoke decodedInvoke = decodeRoseInvoke(invoke);
            byte[] operationResponse = handleGatewayOperation(session, decodedInvoke.operationCode(), decodedInvoke.argument());
            BerTlv responseTlv = BerCodec.decodeSingle(operationResponse);
            if (responseTlv.tagClass() == TAG_CLASS_CONTEXT && responseTlv.tagNumber() == APDU_ERROR) {
                return roseReturnError(decodedInvoke.invokeId(), operationResponse);
            }
            return roseReturnResult(decodedInvoke.invokeId(), operationResponse);
        } catch (RuntimeException ex) {
            logger.info("P3 ASN.1 ROSE invoke decode failed: {}", ex.getMessage());
            return roseReject(0, "malformed-rose-invoke");
        }
    }

    private RoseInvoke decodeRoseInvoke(BerTlv invoke) {
        List<BerTlv> fields = decodeRoseInvokeFields(invoke.value());
        Integer invokeId = null;
        Integer operationCode = null;
        byte[] argument = new byte[0];

        for (BerTlv field : fields) {
            if (!field.constructed() && field.tagClass() == TAG_CLASS_CONTEXT && field.tagNumber() == 0) {
                invokeId = decodeInteger(field.value());
                continue;
            }
            if (!field.constructed() && field.tagClass() == TAG_CLASS_CONTEXT && field.tagNumber() == 1) {
                operationCode = decodeInteger(field.value());
                continue;
            }
            if (field.tagClass() == TAG_CLASS_CONTEXT && field.tagNumber() == 2) {
                argument = field.constructed() ? unwrapConstructedAny(field) : field.value();
                continue;
            }

            if (!field.constructed() && field.tagClass() == TAG_CLASS_UNIVERSAL && field.tagNumber() == 2 && invokeId == null) {
                invokeId = decodeInteger(field.value());
                continue;
            }
            if (!field.constructed() && field.tagClass() == TAG_CLASS_UNIVERSAL && field.tagNumber() == 2 && operationCode == null) {
                operationCode = decodeInteger(field.value());
                continue;
            }
            if (argument.length == 0) {
                argument = BerCodec.encode(field);
            }
        }

        if (invokeId == null || operationCode == null) {
            throw new IllegalArgumentException("ROSE invoke-id or operation-code missing");
        }
        return new RoseInvoke(invokeId, operationCode, argument);
    }

    private List<BerTlv> decodeRoseInvokeFields(byte[] value) {
        try {
            BerTlv maybeSequence = BerCodec.decodeSingle(value);
            if (maybeSequence.tagClass() == TAG_CLASS_UNIVERSAL
                && maybeSequence.constructed()
                && maybeSequence.tagNumber() == TAG_UNIVERSAL_SEQUENCE) {
                return BerCodec.decodeAll(maybeSequence.value());
            }
        } catch (RuntimeException ignored) {
            // fallback to decoding as direct field list
        }
        return BerCodec.decodeAll(value);
    }

    private byte[] unwrapConstructedAny(BerTlv constructedAny) {
        List<BerTlv> nested = BerCodec.decodeAll(constructedAny.value());
        if (nested.isEmpty()) {
            return new byte[0];
        }
        return BerCodec.encode(nested.get(0));
    }

    private byte[] handleGatewayOperation(P3GatewaySessionService.SessionState session, int operationCode, byte[] argument) {
        return switch (operationCode) {
            case APDU_BIND_REQUEST -> mapBind(session, argument);
            case APDU_SUBMIT_REQUEST -> mapSubmit(session, argument);
            case APDU_STATUS_REQUEST -> mapStatus(session, argument);
            case APDU_REPORT_REQUEST -> mapReport(session, argument);
            case APDU_RELEASE_REQUEST -> mapRelease(session);
            default -> error("unsupported-operation", "Unsupported ROSE operation " + operationCode);
        };
    }

    private byte[] roseReturnResult(int invokeId, byte[] payload) {
        byte[] sequence = BerCodec.encode(new BerTlv(
            TAG_CLASS_UNIVERSAL,
            true,
            TAG_UNIVERSAL_SEQUENCE,
            0,
            concat(List.of(encodeIntegerUniversal(invokeId), payload)).length,
            concat(List.of(encodeIntegerUniversal(invokeId), payload))
        ));
        return BerCodec.encode(new BerTlv(TAG_CLASS_APPLICATION, true, ROSE_RETURN_RESULT, 0, sequence.length, sequence));
    }

    private byte[] roseReturnError(int invokeId, byte[] payload) {
        byte[] body = concat(List.of(encodeIntegerUniversal(invokeId), encodeIntegerUniversal(1), payload));
        return BerCodec.encode(new BerTlv(TAG_CLASS_APPLICATION, true, ROSE_RETURN_ERROR, 0, body.length, body));
    }

    private byte[] roseReject(int invokeId, String reason) {
        byte[] body = concat(List.of(encodeIntegerUniversal(invokeId), encodeUtf8ContextField(0, reason)));
        return BerCodec.encode(new BerTlv(TAG_CLASS_APPLICATION, true, ROSE_REJECT, 0, body.length, body));
    }

    public byte[] readPdu(InputStream inputStream) throws IOException {
        int firstOctet = inputStream.read();
        if (firstOctet < 0) {
            return null;
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(firstOctet);

        int secondOctet = inputStream.read();
        if (secondOctet < 0) {
            throw new EOFException("Missing BER length octet");
        }
        out.write(secondOctet);

        int valueLength;
        if ((secondOctet & 0x80) == 0) {
            valueLength = secondOctet;
        } else {
            int numLenOctets = secondOctet & 0x7F;
            if (numLenOctets == 0) {
                throw new IllegalArgumentException("Indefinite BER length is not supported");
            }
            byte[] lenBytes = inputStream.readNBytes(numLenOctets);
            if (lenBytes.length != numLenOctets) {
                throw new EOFException("Truncated BER length");
            }
            out.writeBytes(lenBytes);
            valueLength = 0;
            for (byte b : lenBytes) {
                valueLength = (valueLength << 8) | (b & 0xFF);
            }
        }

        byte[] value = inputStream.readNBytes(valueLength);
        if (value.length != valueLength) {
            throw new EOFException("Truncated BER value");
        }
        out.writeBytes(value);
        return out.toByteArray();
    }

    private byte[] mapBind(P3GatewaySessionService.SessionState session, byte[] payload) {
        Map<Integer, String> fields = decodeContextUtf8Fields(payload);
        logger.info(
            "P3 ASN.1 bind request fields username={} sender={} channel={} password-present={}",
            safe(fields.get(0)),
            safe(fields.get(2)),
            safe(fields.get(3)),
            StringUtils.hasText(fields.get(1))
        );
        String command = "BIND"
            + " username=" + value(fields.get(0))
            + ";password=" + value(fields.get(1))
            + ";sender=" + value(fields.get(2))
            + ";channel=" + value(fields.get(3));
        String response = sessionService.handleCommand(session, command);
        logger.info("P3 ASN.1 bind gateway-response={}", response);

        if (response.startsWith("OK")) {
            return envelope(APDU_BIND_RESPONSE, encodeKeyValuePayload(parseResponse(response)));
        }
        return errorFromResponse(response);
    }

    private byte[] mapSubmit(P3GatewaySessionService.SessionState session, byte[] payload) {
        Map<Integer, String> fields = decodeContextUtf8Fields(payload);
        logger.info(
            "P3 ASN.1 submit request fields recipient={} subject={} body-bytes={}",
            safe(fields.get(0)),
            safe(fields.get(1)),
            value(fields.get(2)).getBytes(StandardCharsets.UTF_8).length
        );
        String command = "SUBMIT"
            + " recipient=" + value(fields.get(0))
            + ";subject=" + value(fields.get(1))
            + ";body=" + value(fields.get(2));
        String response = sessionService.handleCommand(session, command);
        logger.info("P3 ASN.1 submit gateway-response={}", response);

        if (response.startsWith("OK")) {
            return envelope(APDU_SUBMIT_RESPONSE, encodeKeyValuePayload(parseResponse(response)));
        }
        return errorFromResponse(response);
    }

    private byte[] mapStatus(P3GatewaySessionService.SessionState session, byte[] payload) {
        Map<Integer, String> fields = decodeContextUtf8Fields(payload);
        logger.info(
            "P3 ASN.1 status request fields submission-id={} wait-timeout-ms={} retry-interval-ms={}",
            safe(fields.get(0)),
            safe(fields.get(1)),
            safe(fields.get(2))
        );
        String command = "STATUS"
            + " submission-id=" + value(fields.get(0))
            + ";wait-timeout-ms=" + value(fields.get(1))
            + ";retry-interval-ms=" + value(fields.get(2));
        String response = sessionService.handleCommand(session, command);
        logger.info("P3 ASN.1 status gateway-response={}", response);

        if (response.startsWith("OK")) {
            return envelope(APDU_STATUS_RESPONSE, encodeKeyValuePayload(parseResponse(response)));
        }
        return errorFromResponse(response);
    }

    private byte[] mapReport(P3GatewaySessionService.SessionState session, byte[] payload) {
        Map<Integer, String> fields = decodeContextUtf8Fields(payload);
        logger.info(
            "P3 ASN.1 report request fields recipient={} wait-timeout-ms={} retry-interval-ms={} ",
            safe(fields.get(0)),
            safe(fields.get(1)),
            safe(fields.get(2))
        );
        String command = "REPORT"
            + " recipient=" + value(fields.get(0))
            + ";wait-timeout-ms=" + value(fields.get(1))
            + ";retry-interval-ms=" + value(fields.get(2));
        String response = sessionService.handleCommand(session, command);
        logger.info("P3 ASN.1 report gateway-response={}", response);

        if (response.startsWith("OK")) {
            return envelope(APDU_REPORT_RESPONSE, encodeKeyValuePayload(parseResponse(response)));
        }
        return errorFromResponse(response);
    }

    private byte[] mapRelease(P3GatewaySessionService.SessionState session) {
        String response = sessionService.handleCommand(session, "UNBIND");
        logger.info("P3 ASN.1 release gateway-response={}", response);
        if (response.startsWith("OK")) {
            return envelope(APDU_RELEASE_RESPONSE, new byte[0]);
        }
        return errorFromResponse(response);
    }

    private byte[] errorFromResponse(String response) {
        Map<String, String> parsed = parseResponse(response);
        String code = parsed.getOrDefault("code", "gateway");
        String detail = parsed.getOrDefault("detail", response);
        String retryable = isRetryable(code) ? "true" : "false";
        return error(code, detail, retryable);
    }

    private byte[] error(String code, String detail) {
        return error(code, detail, "false");
    }

    private byte[] error(String code, String detail, String retryable) {
        List<byte[]> fields = new ArrayList<>();
        fields.add(encodeUtf8ContextField(0, code));
        fields.add(encodeUtf8ContextField(1, detail));
        fields.add(encodeUtf8ContextField(2, retryable));
        return envelope(APDU_ERROR, concat(fields));
    }

    private boolean isRetryable(String code) {
        return "interrupted".equals(code) || "routing-policy".equals(code);
    }

    private byte[] envelope(int tagNumber, byte[] payload) {
        return BerCodec.encode(new BerTlv(TAG_CLASS_CONTEXT, true, tagNumber, 0, payload.length, payload));
    }

    private Map<Integer, String> decodeContextUtf8Fields(byte[] payload) {
        Map<Integer, String> values = new HashMap<>();
        for (BerTlv field : BerCodec.decodeAll(payload)) {
            if (field.tagClass() != TAG_CLASS_CONTEXT) {
                continue;
            }
            if (field.constructed()) {
                BerTlv inner = BerCodec.decodeSingle(field.value());
                values.put(field.tagNumber(), decodeString(inner));
            } else {
                values.put(field.tagNumber(), new String(field.value(), StandardCharsets.UTF_8));
            }
        }
        return values;
    }

    private byte[] encodeKeyValuePayload(Map<String, String> map) {
        List<byte[]> fields = new ArrayList<>();
        int index = 0;
        for (Map.Entry<String, String> entry : map.entrySet()) {
            fields.add(encodeUtf8ContextField(index++, entry.getKey() + "=" + entry.getValue()));
        }
        return concat(fields);
    }

    private byte[] encodeUtf8ContextField(int tagNumber, String value) {
        byte[] bytes = value == null ? new byte[0] : value.getBytes(StandardCharsets.UTF_8);
        byte[] utf8 = BerCodec.encode(new BerTlv(TAG_CLASS_UNIVERSAL, false, 12, 0, bytes.length, bytes));
        return BerCodec.encode(new BerTlv(TAG_CLASS_CONTEXT, true, tagNumber, 0, utf8.length, utf8));
    }

    private String decodeString(BerTlv tlv) {
        return switch (tlv.tagNumber()) {
            case 12, 19, 22, 26, 27, 28, 30 -> new String(tlv.value(), StandardCharsets.UTF_8);
            case 2 -> decodeIntegerAsString(tlv.value());
            default -> new String(tlv.value(), StandardCharsets.UTF_8);
        };
    }

    private String decodeIntegerAsString(byte[] value) {
        return Integer.toString(decodeInteger(value));
    }

    private int decodeInteger(byte[] value) {
        if (value.length == 0) {
            return 0;
        }
        int number = 0;
        for (byte b : value) {
            number = (number << 8) | (b & 0xFF);
        }
        return number;
    }

    private byte[] encodeIntegerUniversal(int value) {
        if (value == 0) {
            return BerCodec.encode(new BerTlv(TAG_CLASS_UNIVERSAL, false, 2, 0, 1, new byte[] { 0x00 }));
        }
        int remaining = value;
        byte[] buf = new byte[4];
        int index = buf.length;
        while (remaining > 0) {
            buf[--index] = (byte) (remaining & 0xFF);
            remaining >>>= 8;
        }
        int len = buf.length - index;
        byte[] bytes = new byte[len];
        System.arraycopy(buf, index, bytes, 0, len);
        return BerCodec.encode(new BerTlv(TAG_CLASS_UNIVERSAL, false, 2, 0, bytes.length, bytes));
    }

    private Map<String, String> parseResponse(String response) {
        Map<String, String> map = new HashMap<>();
        for (String token : response.split("\\s+")) {
            int idx = token.indexOf('=');
            if (idx <= 0 || idx == token.length() - 1) {
                continue;
            }
            map.put(token.substring(0, idx), token.substring(idx + 1));
        }
        if (!map.containsKey("raw") && StringUtils.hasText(response)) {
            map.put("raw", response);
        }
        return map;
    }

    private String value(String maybeNull) {
        return maybeNull == null ? "" : maybeNull;
    }

    private byte[] concat(List<byte[]> chunks) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] chunk : chunks) {
            out.writeBytes(chunk);
        }
        return out.toByteArray();
    }

    private String safe(String value) {
        return StringUtils.hasText(value) ? value : "<empty>";
    }

    private record RoseInvoke(int invokeId, int operationCode, byte[] argument) {
    }
}
