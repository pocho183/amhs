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

    private static final int TAG_CLASS_CONTEXT = 2;
    private static final int TAG_CLASS_UNIVERSAL = 0;

    static final int APDU_BIND_REQUEST = 0;
    static final int APDU_BIND_RESPONSE = 1;
    static final int APDU_SUBMIT_REQUEST = 2;
    static final int APDU_SUBMIT_RESPONSE = 3;
    static final int APDU_STATUS_REQUEST = 4;
    static final int APDU_STATUS_RESPONSE = 5;
    static final int APDU_RELEASE_REQUEST = 6;
    static final int APDU_RELEASE_RESPONSE = 7;
    static final int APDU_ERROR = 8;
    static final int APDU_READ_REQUEST = 9;
    static final int APDU_READ_RESPONSE = 10;

    private final P3GatewaySessionService sessionService;

    public P3Asn1GatewayProtocol(P3GatewaySessionService sessionService) {
        this.sessionService = sessionService;
    }

    public byte[] handle(P3GatewaySessionService.SessionState session, byte[] encodedPdu) {
        BerTlv apdu = BerCodec.decodeSingle(encodedPdu);
        if (apdu.tagClass() != TAG_CLASS_CONTEXT || !apdu.constructed()) {
            return error("invalid-apdu", "Expected context-specific constructed APDU");
        }

        return switch (apdu.tagNumber()) {
            case APDU_BIND_REQUEST -> mapBind(session, apdu.value());
            case APDU_SUBMIT_REQUEST -> mapSubmit(session, apdu.value());
            case APDU_STATUS_REQUEST -> mapStatus(session, apdu.value());
            case APDU_RELEASE_REQUEST -> mapRelease(session);
            case APDU_READ_REQUEST -> mapRead(session, apdu.value());
            default -> error("unsupported-operation", "Unsupported APDU " + apdu.tagNumber());
        };
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
        String command = "BIND"
            + " username=" + value(fields.get(0))
            + ";password=" + value(fields.get(1))
            + ";sender=" + value(fields.get(2))
            + ";channel=" + value(fields.get(3));
        String response = sessionService.handleCommand(session, command);

        if (response.startsWith("OK")) {
            return envelope(APDU_BIND_RESPONSE, encodeKeyValuePayload(parseResponse(response)));
        }
        return errorFromResponse(response);
    }

    private byte[] mapSubmit(P3GatewaySessionService.SessionState session, byte[] payload) {
        Map<Integer, String> fields = decodeContextUtf8Fields(payload);
        String command = "SUBMIT"
            + " recipient=" + value(fields.get(0))
            + ";subject=" + value(fields.get(1))
            + ";body=" + value(fields.get(2));
        String response = sessionService.handleCommand(session, command);

        if (response.startsWith("OK")) {
            return envelope(APDU_SUBMIT_RESPONSE, encodeKeyValuePayload(parseResponse(response)));
        }
        return errorFromResponse(response);
    }

    private byte[] mapStatus(P3GatewaySessionService.SessionState session, byte[] payload) {
        Map<Integer, String> fields = decodeContextUtf8Fields(payload);
        String command = "STATUS"
            + " submission-id=" + value(fields.get(0))
            + ";wait-timeout-ms=" + value(fields.get(1))
            + ";retry-interval-ms=" + value(fields.get(2));
        String response = sessionService.handleCommand(session, command);

        if (response.startsWith("OK")) {
            return envelope(APDU_STATUS_RESPONSE, encodeKeyValuePayload(parseResponse(response)));
        }
        return errorFromResponse(response);
    }


    private byte[] mapRead(P3GatewaySessionService.SessionState session, byte[] payload) {
        Map<Integer, String> fields = decodeContextUtf8Fields(payload);
        String command = "READ"
            + " recipient=" + value(fields.get(0))
            + ";wait-timeout-ms=" + value(fields.get(1))
            + ";retry-interval-ms=" + value(fields.get(2));
        String response = sessionService.handleCommand(session, command);

        if (response.startsWith("OK")) {
            return envelope(APDU_READ_RESPONSE, encodeKeyValuePayload(parseResponse(response)));
        }
        return errorFromResponse(response);
    }

    private byte[] mapRelease(P3GatewaySessionService.SessionState session) {
        String response = sessionService.handleCommand(session, "UNBIND");
        if (response.startsWith("OK")) {
            return envelope(APDU_RELEASE_RESPONSE, new byte[0]);
        }
        return errorFromResponse(response);
    }

    private byte[] errorFromResponse(String response) {
        return error("gateway", response);
    }

    private byte[] error(String code, String detail) {
        List<byte[]> fields = new ArrayList<>();
        fields.add(encodeUtf8ContextField(0, code));
        fields.add(encodeUtf8ContextField(1, detail));
        return envelope(APDU_ERROR, concat(fields));
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
        if (value.length == 0) {
            return "0";
        }
        int number = 0;
        for (byte b : value) {
            number = (number << 8) | (b & 0xFF);
        }
        return Integer.toString(number);
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
}
