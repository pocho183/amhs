package it.amhs.service.protocol.p3;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import it.amhs.asn1.BerCodec;
import it.amhs.asn1.BerTlv;
import it.amhs.service.address.ORAddress;

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
    static final int APDU_READ_REQUEST = 11;
    static final int APDU_READ_RESPONSE = 12;
    static final int APDU_ERROR = 8;

    private static final Set<Integer> EXTERNAL_CLAIMED_APDU_VARIANTS = Set.of(
        APDU_BIND_REQUEST,
        APDU_BIND_RESPONSE,
        APDU_SUBMIT_REQUEST,
        APDU_SUBMIT_RESPONSE,
        APDU_STATUS_REQUEST,
        APDU_STATUS_RESPONSE,
        APDU_RELEASE_REQUEST,
        APDU_RELEASE_RESPONSE,
        APDU_ERROR,
        APDU_REPORT_REQUEST,
        APDU_REPORT_RESPONSE,
        APDU_READ_REQUEST,
        APDU_READ_RESPONSE
    );

    private static final Set<Integer> REQUEST_BIND_FIELD_TAGS = Set.of(0, 1, 2, 3);
    private static final Set<Integer> REQUEST_COMMON_FIELD_TAGS = Set.of(0, 1, 2);

    private final P3GatewaySessionService sessionService;

    public P3Asn1GatewayProtocol(P3GatewaySessionService sessionService) {
        this.sessionService = sessionService;
    }

    public byte[] handle(P3GatewaySessionService.SessionState session, byte[] encodedPdu) {
        BerTlv apdu;
        try {
            apdu = BerCodec.decodeSingle(encodedPdu);
        } catch (RuntimeException ex) {
            logger.info("P3 ASN.1 malformed APDU decode failed: {}", ex.getMessage());
            return error("malformed-apdu", "Unable to decode BER APDU");
        }
        logger.info("P3 ASN.1 incoming APDU tagClass={} constructed={} tagNumber={} len={}", apdu.tagClass(), apdu.constructed(), apdu.tagNumber(), apdu.length());

        if (isRtseApdu(apdu)) {
            return handleRtse(session, apdu);
        }

        if (isRoseInvoke(apdu)) {
            return handleRoseInvoke(session, apdu);
        }

        if (isRoseApdu(apdu)) {
            return roseReject(0, "unexpected-rose-apdu");
        }

        if (apdu.tagClass() != TAG_CLASS_CONTEXT || !apdu.constructed() || !looksLikeGatewayApdu(apdu)) {
            return error("invalid-apdu", "Expected gateway APDU");
        }

        return switch (apdu.tagNumber()) {
            case APDU_BIND_REQUEST -> {
                logger.info("P3 ASN.1 bind candidate raw={}", toHex(BerCodec.encode(apdu)));
                logger.info("P3 ASN.1 bind candidate payload={}", toHex(apdu.value()));
                yield mapBind(session, apdu.value());
            }
            case APDU_SUBMIT_REQUEST -> mapSubmit(session, apdu.value());
            case APDU_STATUS_REQUEST -> mapStatus(session, apdu.value());
            case APDU_REPORT_REQUEST -> mapReport(session, apdu.value());
            case APDU_READ_REQUEST -> mapRead(session, apdu.value());
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
        if (isRoseInvoke(tlv)) {
            return BerCodec.encode(tlv);
        }
        if (looksLikeGatewayApdu(tlv)) {
            logger.info("P3 ASN.1 accepted gateway candidate tag={} hex={}", tlv.tagNumber(), toHex(BerCodec.encode(tlv)));
            return BerCodec.encode(tlv);
        }
        if (!tlv.constructed()) {
            return null;
        }
        try {
            for (BerTlv nested : BerCodec.decodeAll(tlv.value())) {
                byte[] found = findGatewayOrRoseApdu(nested);
                if (found != null) {
                    return found;
                }
            }
        } catch (RuntimeException ex) {
            return null;
        }
        return null;
    }

    static Set<Integer> externalClaimedApduVariants() {
        return EXTERNAL_CLAIMED_APDU_VARIANTS;
    }

    private boolean isGatewayApduTag(int tagNumber) {
        return EXTERNAL_CLAIMED_APDU_VARIANTS.contains(tagNumber);
    }

    private boolean looksLikeGatewayApdu(BerTlv tlv) {
        if (tlv.tagClass() != TAG_CLASS_CONTEXT || !tlv.constructed() || !isGatewayApduTag(tlv.tagNumber())) {
            return false;
        }
        try {
            List<BerTlv> fields = decodeContextFieldList(tlv.value());
            if (fields.isEmpty()) {
                return tlv.tagNumber() == APDU_RELEASE_REQUEST || tlv.tagNumber() == APDU_RELEASE_RESPONSE;
            }
            Set<Integer> seenTags = new HashSet<>();
            for (BerTlv field : fields) {
                if (field.tagClass() != TAG_CLASS_CONTEXT) {
                    return false;
                }
                if (!isLikelyScalarField(field)) {
                    return false;
                }
                seenTags.add(field.tagNumber());
            }
            return hasExpectedFieldShape(tlv.tagNumber(), seenTags);
        } catch (RuntimeException ex) {
            return false;
        }
    }

    private boolean hasExpectedFieldShape(int apduTag, Set<Integer> seenTags) {
        return switch (apduTag) {
            case APDU_BIND_REQUEST -> seenTags.size() >= 2 && REQUEST_BIND_FIELD_TAGS.containsAll(seenTags);
            case APDU_SUBMIT_REQUEST, APDU_STATUS_REQUEST, APDU_REPORT_REQUEST, APDU_READ_REQUEST, APDU_ERROR ->
                !seenTags.isEmpty() && REQUEST_COMMON_FIELD_TAGS.containsAll(seenTags);
            default -> true;
        };
    }

    private boolean isLikelyScalarField(BerTlv field) {
        if (!field.constructed()) {
            return true;
        }
        try {
            BerTlv inner = BerCodec.decodeSingle(field.value());
            return !inner.constructed();
        } catch (RuntimeException ex) {
            return false;
        }
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

    private boolean isRoseApdu(BerTlv apdu) {
        return apdu.constructed()
            && apdu.tagNumber() >= ROSE_INVOKE
            && apdu.tagNumber() <= ROSE_REJECT
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
            case APDU_READ_REQUEST -> mapRead(session, argument);
            case APDU_RELEASE_REQUEST -> mapRelease(session);
            case APDU_BIND_RESPONSE, APDU_SUBMIT_RESPONSE, APDU_STATUS_RESPONSE, APDU_ERROR, APDU_RELEASE_RESPONSE, APDU_REPORT_RESPONSE, APDU_READ_RESPONSE ->
                error("invalid-operation-role", "ROSE invoke requires a request operation code, got " + operationCode);
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
        logger.info("P3 ASN.1 bind candidate payload={}", toHex(payload));
        Map<Integer, String> fields = decodeBindFields(payload);
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

    private Map<Integer, String> decodeBindFields(byte[] payload) {
        Map<Integer, String> fields = decodeContextUtf8Fields(payload);
        if (StringUtils.hasText(fields.get(0)) || StringUtils.hasText(fields.get(1)) || StringUtils.hasText(fields.get(2)) || StringUtils.hasText(fields.get(3))) {
            return fields;
        }

        logger.warn(
            "P3 ASN.1 bind payload did not expose canonical context-tagged bind fields; "
                + "falling back to diagnostic textual atom inference (heuristic compatibility mode)"
        );

        List<String> atoms = extractTextualAtoms(payload);
        String sender = findSenderAddress(atoms);
        String channel = findChannelName(atoms, sender);

        Map<Integer, String> inferred = new HashMap<>();
        if (StringUtils.hasText(sender)) {
            inferred.put(2, sender);
        }
        if (StringUtils.hasText(channel)) {
            inferred.put(3, channel);
        }

        if (!inferred.isEmpty()) {
            logger.info("P3 ASN.1 heuristic bind inference recovered sender={} channel={}", safe(sender), safe(channel));
        }

        return inferred;
    }

    private List<String> extractTextualAtoms(byte[] payload) {
        List<String> values = new ArrayList<>();
        collectTextualAtoms(payload, values);
        return values.stream().filter(StringUtils::hasText).distinct().toList();
    }

    private void collectTextualAtoms(byte[] encoded, List<String> values) {
        if (encoded == null || encoded.length == 0) {
            return;
        }
        try {
            BerTlv root = BerCodec.decodeSingle(encoded);
            collectTextualAtoms(root, values);
            return;
        } catch (RuntimeException ignored) {
            // fall back to a field list decode
        }
        try {
            for (BerTlv field : BerCodec.decodeAll(encoded)) {
                collectTextualAtoms(field, values);
            }
        } catch (RuntimeException ignored) {
            // ignore non-BER content
        }
    }

    private void collectTextualAtoms(BerTlv tlv, List<String> values) {
        if (tlv.constructed()) {
            try {
                for (BerTlv nested : BerCodec.decodeAll(tlv.value())) {
                    collectTextualAtoms(nested, values);
                }
            } catch (RuntimeException ignored) {
                // not a decodable BER sequence of children
            }
            return;
        }

        if (tlv.tagClass() != TAG_CLASS_UNIVERSAL) {
            maybeAddPrintable(values, tlv.value());
            return;
        }

        switch (tlv.tagNumber()) {
            case 2 -> values.add(decodeIntegerAsString(tlv.value()));
            case 4, 12, 19, 22, 26, 27, 28, 30 -> maybeAddPrintable(values, tlv.value());
            default -> {
                // ignore non-text universal primitives
            }
        }
    }

    private void maybeAddPrintable(List<String> values, byte[] raw) {
        if (raw == null || raw.length == 0) {
            return;
        }
        String decoded = new String(raw, StandardCharsets.UTF_8).trim();
        if (!StringUtils.hasText(decoded) || !isMostlyPrintable(decoded)) {
            return;
        }
        values.add(decoded);
    }

    private boolean isMostlyPrintable(String value) {
        long printable = value.chars().filter(ch -> ch >= 32 && ch < 127).count();
        return printable >= Math.max(1, value.length() - 1);
    }

    private String findSenderAddress(List<String> atoms) {
        for (String atom : atoms) {
            try {
                return ORAddress.parse(atom).toCanonicalString();
            } catch (IllegalArgumentException ignored) {
                // continue
            }
        }
        return null;
    }

    private String findChannelName(List<String> atoms, String sender) {
        List<String> candidates = atoms.stream()
            .filter(StringUtils::hasText)
            .filter(value -> !value.equals(sender))
            .filter(value -> CHANNEL_NAME_PATTERN.matcher(value).matches())
            .distinct()
            .toList();

        for (String preferredChannelName : PREFERRED_CHANNEL_NAMES) {
            if (candidates.contains(preferredChannelName)) {
                return preferredChannelName;
            }
        }

        if (candidates.size() == 1) {
            return candidates.get(0);
        }

        return null;
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

    private byte[] mapRead(P3GatewaySessionService.SessionState session, byte[] payload) {
        Map<Integer, String> fields = decodeContextUtf8Fields(payload);
        logger.info(
            "P3 ASN.1 read request fields recipient={} wait-timeout-ms={} retry-interval-ms={} ",
            safe(fields.get(0)),
            safe(fields.get(1)),
            safe(fields.get(2))
        );
        String command = "READ"
            + " recipient=" + value(fields.get(0))
            + ";wait-timeout-ms=" + value(fields.get(1))
            + ";retry-interval-ms=" + value(fields.get(2));
        String response = sessionService.handleCommand(session, command);
        logger.info("P3 ASN.1 read gateway-response={}", response);

        if (response.startsWith("OK")) {
            return envelope(APDU_READ_RESPONSE, encodeKeyValuePayload(parseResponse(response)));
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
        return "interrupted".equals(code)
            || "routing-policy".equals(code)
            || "resource-exhausted".equals(code)
            || "temporarily-unavailable".equals(code)
            || "transient-failure".equals(code)
            || "timeout".equals(code);
    }

    private byte[] envelope(int tagNumber, byte[] payload) {
        return BerCodec.encode(new BerTlv(TAG_CLASS_CONTEXT, true, tagNumber, 0, payload.length, payload));
    }

    private Map<Integer, String> decodeContextUtf8Fields(byte[] payload) {
        Map<Integer, String> values = new HashMap<>();
        for (BerTlv field : decodeContextFieldList(payload)) {
            if (field.tagClass() != TAG_CLASS_CONTEXT) {
                continue;
            }
            if (field.constructed()) {
                String nested = decodeConstructedFieldValue(field);
                if (StringUtils.hasText(nested)) {
                    values.put(field.tagNumber(), nested);
                }
            } else {
                values.put(field.tagNumber(), new String(field.value(), StandardCharsets.UTF_8));
            }
        }
        return values;
    }

    private String decodeConstructedFieldValue(BerTlv field) {
        List<String> atoms = new ArrayList<>();
        collectTextualAtoms(field, atoms);
        List<String> text = atoms.stream().filter(StringUtils::hasText).distinct().toList();
        if (text.isEmpty()) {
            return null;
        }
        String sender = findSenderAddress(text);
        if (StringUtils.hasText(sender)) {
            return sender;
        }
        return text.stream().max(Comparator.comparingInt(String::length)).orElse(null);
    }

    private List<BerTlv> decodeContextFieldList(byte[] payload) {
        try {
            BerTlv maybeSequence = BerCodec.decodeSingle(payload);
            if (maybeSequence.tagClass() == TAG_CLASS_UNIVERSAL
                && maybeSequence.constructed()
                && maybeSequence.tagNumber() == TAG_UNIVERSAL_SEQUENCE) {
                return BerCodec.decodeAll(maybeSequence.value());
            }
        } catch (RuntimeException ignored) {
            // fallback to decoding as a direct context-tagged field list
        }
        return BerCodec.decodeAll(payload);
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


    private String toHex(byte[] value) {
        if (value == null || value.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder(value.length * 2);
        for (byte b : value) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private String safe(String value) {
        return StringUtils.hasText(value) ? value : "<empty>";
    }

    private record RoseInvoke(int invokeId, int operationCode, byte[] argument) {
    }
}
