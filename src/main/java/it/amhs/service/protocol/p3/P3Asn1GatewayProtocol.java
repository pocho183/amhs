package it.amhs.service.protocol.p3;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import it.amhs.asn1.BerCodec;
import it.amhs.asn1.BerTlv;
import it.amhs.service.address.ORAddress;

@Component
public class P3Asn1GatewayProtocol {

    private static final Logger logger = LoggerFactory.getLogger(P3Asn1GatewayProtocol.class);

    private static final int TAG_CLASS_UNIVERSAL = 0;
    private static final int TAG_CLASS_APPLICATION = 1;
    private static final int TAG_CLASS_CONTEXT = 2;

    private static final int TAG_UNIVERSAL_INTEGER = 2;
    private static final int TAG_UNIVERSAL_SEQUENCE = 16;
    private static final int TAG_UNIVERSAL_UTF8STRING = 12;
    private static final int TAG_UNIVERSAL_PRINTABLESTRING = 19;
    private static final int TAG_UNIVERSAL_IA5STRING = 22;
    private static final int TAG_UNIVERSAL_VISIBLESTRING = 26;
    private static final int TAG_UNIVERSAL_GENERALSTRING = 27;
    private static final int TAG_UNIVERSAL_UNIVERSALSTRING = 28;
    private static final int TAG_UNIVERSAL_BMPSTRING = 30;

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
    static final int APDU_ERROR = 8;
    static final int APDU_REPORT_REQUEST = 9;
    static final int APDU_REPORT_RESPONSE = 10;
    static final int APDU_READ_REQUEST = 11;
    static final int APDU_READ_RESPONSE = 12;

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

        logger.info(
            "P3 ASN.1 incoming APDU tagClass={} constructed={} tagNumber={} len={}",
            apdu.tagClass(),
            apdu.constructed(),
            apdu.tagNumber(),
            apdu.length()
        );

        if (isRtseApdu(apdu)) {
            return handleRtse(session, apdu);
        }

        // IMPORTANT:
        // context-specific tags belong first to P3, not ROSE
        if (apdu.tagClass() == TAG_CLASS_CONTEXT && apdu.constructed()) {
            if (isGatewayApduTag(apdu.tagNumber()) && looksLikeGatewayApdu(apdu)) {
                return handleGatewayApdu(session, apdu);
            }

            if (isNativeP3Apdu(apdu)) {
                return handleNativeP3Apdu(session, apdu);
            }

            logger.warn(
                "P3 ASN.1 unsupported context APDU tag={} len={} hex={}",
                apdu.tagNumber(),
                apdu.length(),
                toHex(encodedPdu)
            );
            return error("unsupported-native-p3-apdu", "Unsupported native P3 APDU");
        }

        // ROSE only after excluding context-specific P3 APDUs
        if (isRoseInvoke(apdu)) {
            return handleRoseInvoke(session, apdu);
        }

        if (isRoseApdu(apdu)) {
            return roseReject(0, "unexpected-rose-apdu");
        }

        return error("invalid-apdu", "Expected P3 APDU");
    }

    private byte[] handleGatewayApdu(P3GatewaySessionService.SessionState session, BerTlv apdu) {
        return switch (apdu.tagNumber()) {
            case APDU_BIND_REQUEST -> {
                logger.info("P3 ASN.1 gateway bind candidate raw={}", toHex(BerCodec.encode(apdu)));
                logger.info("P3 ASN.1 gateway bind candidate payload={}", toHex(apdu.value()));
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

    private boolean isNativeP3Apdu(BerTlv apdu) {
        if (apdu == null || apdu.tagClass() != TAG_CLASS_CONTEXT || !apdu.constructed()) {
            return false;
        }

        if (apdu.tagNumber() != APDU_SUBMIT_REQUEST) {
            return false;
        }

        return apdu.length() > 32 && looksLikeNativeBind(apdu);
    }

    private void logBerTree(String prefix, BerTlv tlv) {
        if (tlv == null) {
            logger.info("{} <null>", prefix);
            return;
        }

        logger.info(
            "{} tagClass={} constructed={} tag={} len={}",
            prefix,
            tlv.tagClass(),
            tlv.constructed(),
            tlv.tagNumber(),
            tlv.length()
        );

        if (!tlv.constructed()) {
            return;
        }

        try {
            int index = 0;
            for (BerTlv child : BerCodec.decodeAll(tlv.value())) {
                logBerTree(prefix + "." + index++, child);
            }
        } catch (RuntimeException ex) {
            logger.info("{} <decode-error {}>", prefix, ex.getMessage());
        }
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
            return wrapRtseResponse(
                rtseApdu.tagNumber(),
                error("unsupported-operation", "RTSE APDU did not contain a supported gateway operation")
            );
        }

        byte[] nestedResponse = handle(session, nestedApdu);
        return wrapRtseResponse(rtseApdu.tagNumber(), nestedResponse);
    }
    
    private byte[] handleNativeP3Apdu(P3GatewaySessionService.SessionState session, BerTlv apdu) {
        byte[] encoded = BerCodec.encode(apdu);

        logger.info(
            "P3 ASN.1 native P3 APDU detected tag={} len={} hex={}",
            apdu.tagNumber(),
            apdu.length(),
            toHex(encoded)
        );

        if (looksLikeNativeBind(apdu)) {
            logger.info("P3 ASN.1 native bind-shaped APDU accepted on outer tag={}", apdu.tagNumber());
            return mapBind(session, encoded);
        }

        return error(
            "unsupported-native-p3-apdu",
            "Native P3 APDU decoding not implemented yet for tag " + apdu.tagNumber()
        );
    }
    
    private boolean looksLikeNativeBind(BerTlv apdu) {
        try {
            String sender = extractSenderFromBind(apdu);
            String password = extractPasswordFromBind(apdu);
            String username = extractUsernameFromBind(apdu);

            if (StringUtils.hasText(sender)) {
                logger.info(
                    "P3 ASN.1 native bind-shape detected sender={} username={} password-present={}",
                    sender,
                    safe(username),
                    StringUtils.hasText(password)
                );
                return true;
            }

            // fallback heuristic: username/password pair often exists even if address extraction
            // is not perfect yet
            if (StringUtils.hasText(username) && StringUtils.hasText(password)) {
                logger.info(
                    "P3 ASN.1 native bind-shape heuristic matched username={} password-present=true",
                    username
                );
                return true;
            }

            return false;
        } catch (RuntimeException ex) {
            logger.debug("P3 ASN.1 native bind-shape detection failed: {}", ex.getMessage());
            return false;
        }
    }
    
    private void logBerTree(String prefix, BerTlv tlv, int depth, int maxDepth) {
        if (tlv == null || depth > maxDepth) {
            return;
        }

        logger.info(
            "{} tagClass={} constructed={} tag={} len={}",
            prefix,
            tlv.tagClass(),
            tlv.constructed(),
            tlv.tagNumber(),
            tlv.length()
        );

        if (!tlv.constructed() || depth == maxDepth) {
            return;
        }

        try {
            List<BerTlv> children = BerCodec.decodeAll(tlv.value());
            for (int i = 0; i < children.size(); i++) {
                logBerTree(prefix + "." + i, children.get(i), depth + 1, maxDepth);
            }
        } catch (RuntimeException ex) {
            logger.debug("{} tree decode stopped: {}", prefix, ex.getMessage());
        }
    }


    private byte[] findGatewayOrRoseApdu(BerTlv tlv) {
        if (isRoseInvoke(tlv)) {
            logger.info(
                "P3 ASN.1 accepted ROSE invoke candidate tagClass={} tagNumber={} len={}",
                tlv.tagClass(),
                tlv.tagNumber(),
                tlv.value().length
            );
            return BerCodec.encode(tlv);
        }

        if (looksLikeGatewayApdu(tlv)) {
            logger.info(
                "P3 ASN.1 accepted gateway candidate tag={} len={} hex={}",
                tlv.tagNumber(),
                tlv.value().length,
                toHex(BerCodec.encode(tlv))
            );
            return BerCodec.encode(tlv);
        }

        if (isNativeP3Apdu(tlv)) {
            logger.info(
                "P3 ASN.1 accepted native candidate tag={} len={} hex={}",
                tlv.tagNumber(),
                tlv.value().length,
                toHex(BerCodec.encode(tlv))
            );
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
            logger.debug(
                "P3 ASN.1 nested decode skipped for tagClass={} tagNumber={} reason={}",
                tlv.tagClass(),
                tlv.tagNumber(),
                ex.getMessage()
            );
        }

        return null;
    }

    private boolean looksLikeGatewayApdu(BerTlv tlv) {
        if (tlv.tagClass() != TAG_CLASS_CONTEXT || !tlv.constructed() || !isGatewayApduTag(tlv.tagNumber())) {
            return false;
        }

        if (tlv.value().length == 0) {
            return tlv.tagNumber() == APDU_RELEASE_REQUEST;
        }

        final List<BerTlv> fields;
        try {
            fields = decodeContextFieldList(tlv.value());
        } catch (RuntimeException ex) {
            logger.debug(
                "P3 ASN.1 gateway candidate rejected tag={} len={} reason=field-decode-failed:{}",
                tlv.tagNumber(),
                tlv.value().length,
                ex.getMessage()
            );
            return false;
        }

        if (fields.isEmpty()) {
            return false;
        }

        Set<Integer> seenTags = new HashSet<>();
        boolean hasConstructedField = false;

        for (BerTlv field : fields) {
            if (field.tagClass() != TAG_CLASS_CONTEXT) {
                return false;
            }
            if (!isLikelyScalarField(field)) {
                return false;
            }
            if (field.constructed()) {
                hasConstructedField = true;
            }
            seenTags.add(field.tagNumber());
        }

        return switch (tlv.tagNumber()) {
            case APDU_BIND_REQUEST -> {
                boolean canonicalGatewayBind =
                    fields.size() >= 2
                        && fields.size() <= 8
                        && hasConstructedField
                        && REQUEST_BIND_FIELD_TAGS.containsAll(seenTags)
                        && fields.stream().allMatch(this::isGatewayScalarField);

                boolean nativeStructuredBind = StringUtils.hasText(findSenderAddressFromStructuredBer(tlv.value()));
                yield canonicalGatewayBind || nativeStructuredBind;
            }

            case APDU_SUBMIT_REQUEST, APDU_STATUS_REQUEST, APDU_REPORT_REQUEST, APDU_READ_REQUEST, APDU_ERROR -> {
                yield !seenTags.isEmpty()
                    && fields.size() <= 8
                    && REQUEST_COMMON_FIELD_TAGS.containsAll(seenTags)
                    && fields.stream().allMatch(this::isGatewayScalarField);
            }

            case APDU_RELEASE_REQUEST -> tlv.value().length == 0 || fields.size() <= 2;

            default -> false;
        };
    }

    static Set<Integer> externalClaimedApduVariants() {
        return EXTERNAL_CLAIMED_APDU_VARIANTS;
    }

    private boolean isGatewayApduTag(int tagNumber) {
        return EXTERNAL_CLAIMED_APDU_VARIANTS.contains(tagNumber);
    }

    private boolean isLikelyScalarField(BerTlv field) {
        if (!field.constructed()) {
            return true;
        }
        try {
            List<BerTlv> nested = BerCodec.decodeAll(field.value());
            return nested.size() == 1 && nested.get(0).tagClass() == TAG_CLASS_UNIVERSAL;
        } catch (RuntimeException ex) {
            return false;
        }
    }

    private boolean isGatewayScalarField(BerTlv field) {
        if (field.tagClass() != TAG_CLASS_CONTEXT) {
            return false;
        }

        if (!field.constructed()) {
            return true;
        }

        try {
            List<BerTlv> nested = BerCodec.decodeAll(field.value());
            if (nested.size() != 1) {
                return false;
            }
            BerTlv inner = nested.get(0);
            return inner.tagClass() == TAG_CLASS_UNIVERSAL && !inner.constructed();
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
            && apdu.tagClass() == TAG_CLASS_APPLICATION
            && apdu.tagNumber() == ROSE_INVOKE;
    }

    private boolean isRoseApdu(BerTlv apdu) {
        return apdu.constructed()
            && apdu.tagClass() == TAG_CLASS_APPLICATION
            && apdu.tagNumber() >= ROSE_INVOKE
            && apdu.tagNumber() <= ROSE_REJECT;
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

            if (!field.constructed()
                && field.tagClass() == TAG_CLASS_UNIVERSAL
                && field.tagNumber() == TAG_UNIVERSAL_INTEGER
                && invokeId == null) {
                invokeId = decodeInteger(field.value());
                continue;
            }

            if (!field.constructed()
                && field.tagClass() == TAG_CLASS_UNIVERSAL
                && field.tagNumber() == TAG_UNIVERSAL_INTEGER
                && operationCode == null) {
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

            case APDU_BIND_RESPONSE, APDU_SUBMIT_RESPONSE, APDU_STATUS_RESPONSE,
                 APDU_ERROR, APDU_RELEASE_RESPONSE, APDU_REPORT_RESPONSE, APDU_READ_RESPONSE ->
                error("invalid-operation-role", "ROSE invoke requires a request operation code, got " + operationCode);

            default -> error("unsupported-operation", "Unsupported ROSE operation " + operationCode);
        };
    }

    private byte[] roseReturnResult(int invokeId, byte[] payload) {
        byte[] content = concat(List.of(encodeIntegerUniversal(invokeId), payload));
        byte[] sequence = BerCodec.encode(
            new BerTlv(TAG_CLASS_UNIVERSAL, true, TAG_UNIVERSAL_SEQUENCE, 0, content.length, content)
        );
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

    private DecodedBind decodeBind(byte[] payload) {
        Map<Integer, String> gatewayFields = decodeContextUtf8Fields(payload);
        if (!gatewayFields.isEmpty() && REQUEST_BIND_FIELD_TAGS.containsAll(gatewayFields.keySet())) {
            return new DecodedBind(gatewayFields, BindStyle.GATEWAY);
        }

        Map<Integer, String> nativeFields = decodeNativeBindFields(payload);
        if (!nativeFields.isEmpty()) {
            return new DecodedBind(nativeFields, BindStyle.NATIVE);
        }

        // Retry native decode if caller passed only a TLV value that itself contains one root element.
        try {
            List<BerTlv> nested = BerCodec.decodeAll(payload);
            if (nested.size() == 1) {
                byte[] encodedRoot = BerCodec.encode(nested.get(0));
                nativeFields = decodeNativeBindFields(encodedRoot);
                if (!nativeFields.isEmpty()) {
                    return new DecodedBind(nativeFields, BindStyle.NATIVE);
                }
            }
        } catch (RuntimeException ignored) {
        }

        return new DecodedBind(Map.of(), BindStyle.NATIVE);
    }
    
    private byte[] mapBind(P3GatewaySessionService.SessionState session, byte[] payload) {
        logger.info("P3 ASN.1 bind candidate payload={}", toHex(payload));

        DecodedBind bind = decodeBind(payload);

        logger.info(
            "P3 ASN.1 bind decoded style={} username={} sender={} channel={} password-present={}",
            bind.style(),
            safe(bind.fields().get(0)),
            safe(bind.fields().get(2)),
            safe(bind.fields().get(3)),
            StringUtils.hasText(bind.fields().get(1))
        );

        if (bind.fields().isEmpty() || !StringUtils.hasText(bind.fields().get(2))) {
            logger.warn("P3 ASN.1 bind rejected: unsupported native bind argument shape");
            return bind.style() == BindStyle.NATIVE
                ? nativeBindReject("unsupported-native-p3-bind", "Unsupported native bind argument shape")
                : error(
                    "unsupported-native-p3-bind",
                    "Bind argument did not contain gateway fields or a decodable X.411 ORName sender"
                );
        }

        String command = "BIND"
            + " username=" + value(bind.fields().get(0))
            + ";password=" + value(bind.fields().get(1))
            + ";sender=" + value(bind.fields().get(2))
            + ";channel=" + value(bind.fields().get(3));

        String response = sessionService.handleCommand(session, command);
        logger.info("P3 ASN.1 bind gateway-response={}", response);

        if (bind.style() == BindStyle.NATIVE) {
            if (response.startsWith("OK")) {
                return nativeBindAccept(bind.fields().get(2), bind.fields().get(3));
            }
            return nativeBindRejectFromResponse(response);
        }

        if (response.startsWith("OK")) {
            return envelope(APDU_BIND_RESPONSE, encodeKeyValuePayload(parseResponse(response)));
        }
        return errorFromResponse(response);
    }

    private Map<Integer, String> decodeNativeBindFields(byte[] payload) {
        Map<Integer, String> fields = new HashMap<>();

        try {
            BerTlv root = BerCodec.decodeSingle(payload);

            String sender = extractSenderFromBind(root);
            if (StringUtils.hasText(sender)) {
                fields.put(2, sender);
                logger.info("P3 ASN.1 structured bind decode recovered sender={}", sender);
            }

            String password = extractPasswordFromBind(root);
            if (StringUtils.hasText(password)) {
                fields.put(1, password);
            }

            String username = extractUsernameFromBind(root);
            if (StringUtils.hasText(username)) {
                fields.put(0, username);
            }

            String channel = extractChannelFromBind(root);
            if (StringUtils.hasText(channel)) {
                fields.put(3, channel);
            }

            return fields;
        } catch (RuntimeException ex) {
            logger.debug("P3 ASN.1 native bind decode failed: {}", ex.getMessage());
            return Map.of();
        }
    }

    private byte[] nativeBindAccept(String sender, String channel) {
        return envelope(APDU_BIND_RESPONSE, encodeContextInteger(0, 0));
    }

    private byte[] nativeBindRejectFromResponse(String response) {
        Map<String, String> parsed = parseResponse(response);
        String detail = parsed.getOrDefault("detail", response);
        String code = parsed.getOrDefault("code", "bind-rejected");
        return nativeBindReject(code, detail);
    }

    private byte[] nativeBindReject(String code, String detail) {
        List<byte[]> fields = new ArrayList<>();
        fields.add(encodeContextInteger(0, 1));
        fields.add(encodeUtf8ContextField(1, code));
        fields.add(encodeUtf8ContextField(2, detail));
        return envelope(APDU_BIND_RESPONSE, concat(fields));
    }

    private String extractSenderFromBind(BerTlv root) {
        BerTlv addressNode = findAddressContainer(root);
        if (addressNode == null) {
            return null;
        }

        Map<String, String> attrs = new LinkedHashMap<>();
        collectNativeOrAddressAttributes(addressNode, attrs);
        normalizeNativeOrAddressAttributes(attrs);

        if (!looksLikeAddressCandidate(attrs)) {
            logger.info("P3 ASN.1 native bind candidate missing mandatory attrs={}", attrs);
            return null;
        }

        if (!hasAnyOrganizationalIdentity(attrs)) {
            logger.info("P3 ASN.1 native bind candidate missing OU/CN attrs={}", attrs);
            return null;
        }

        try {
            String canonical = ORAddress.of(attrs).toCanonicalString();
            logger.info("P3 ASN.1 native bind candidate accepted attrs={} canonical={}", attrs, canonical);
            return canonical;
        } catch (RuntimeException ex) {
            logger.info(
                "P3 ASN.1 native bind candidate rejected by ORAddress builder attrs={} reason={}",
                attrs,
                ex.getMessage()
            );
            return null;
        }
    }

    private String extractPasswordFromBind(BerTlv root) {
        BerTlv addressNode = findAddressContainer(root);
        return findPasswordOutsideAddress(root, addressNode);
    }

    private String extractUsernameFromBind(BerTlv root) {
        BerTlv addressNode = findAddressContainer(root);
        return findUtf8ContextValueOutsideAddress(root, addressNode, 0);
    }

    private String extractChannelFromBind(BerTlv root) {
        BerTlv addressNode = findAddressContainer(root);
        return findUtf8ContextValueOutsideAddress(root, addressNode, 3);
    }

    private String findPasswordOutsideAddress(BerTlv node, BerTlv addressNode) {
        if (node == null || node == addressNode) {
            return null;
        }

        if (!node.constructed()) {
            return null;
        }

        if (node.tagClass() == TAG_CLASS_CONTEXT && node.tagNumber() == 2) {
            try {
                List<BerTlv> nested = BerCodec.decodeAll(node.value());
                if (nested.size() == 1 && !nested.get(0).constructed()) {
                    String decoded = decodeBerStringValue(nested.get(0));
                    if (StringUtils.hasText(decoded) && !"Local".equalsIgnoreCase(decoded)) {
                        return decoded;
                    }
                }
            } catch (RuntimeException ignored) {
            }
        }

        try {
            for (BerTlv child : BerCodec.decodeAll(node.value())) {
                if (child == addressNode) {
                    continue;
                }
                String found = findPasswordOutsideAddress(child, addressNode);
                if (StringUtils.hasText(found)) {
                    return found;
                }
            }
        } catch (RuntimeException ignored) {
        }

        return null;
    }

    private String findUtf8ContextValueOutsideAddress(BerTlv node, BerTlv addressNode, int wantedTag) {
        if (node == null || node == addressNode) {
            return null;
        }

        if (!node.constructed()) {
            return null;
        }

        if (node.tagClass() == TAG_CLASS_CONTEXT && node.tagNumber() == wantedTag) {
            try {
                List<BerTlv> nested = BerCodec.decodeAll(node.value());
                if (nested.size() == 1 && !nested.get(0).constructed()) {
                    String decoded = decodeBerStringValue(nested.get(0));
                    if (StringUtils.hasText(decoded)) {
                        return decoded;
                    }
                }
            } catch (RuntimeException ignored) {
            }
        }

        try {
            for (BerTlv child : BerCodec.decodeAll(node.value())) {
                if (child == addressNode) {
                    continue;
                }
                String found = findUtf8ContextValueOutsideAddress(child, addressNode, wantedTag);
                if (StringUtils.hasText(found)) {
                    return found;
                }
            }
        } catch (RuntimeException ignored) {
        }

        return null;
    }

    private BerTlv findAddressContainer(BerTlv node) {
        if (node == null || !node.constructed()) {
            return null;
        }

        try {
            List<BerTlv> children = BerCodec.decodeAll(node.value());

            boolean hasCountry = false;
            boolean hasAdmd = false;
            boolean hasPrmd = false;
            boolean hasOrgLike = false;

            for (BerTlv child : children) {
                if (isAddressAttributeTag(child, TAG_CLASS_APPLICATION, 1)) {
                    hasCountry = true;
                } else if (isAddressAttributeTag(child, TAG_CLASS_APPLICATION, 2)) {
                    hasAdmd = true;
                } else if (isAddressAttributeTag(child, TAG_CLASS_CONTEXT, 2)) {
                    hasPrmd = true;
                } else if (isAddressAttributeTag(child, TAG_CLASS_CONTEXT, 3)) {
                    hasOrgLike = true;
                }
            }

            if (hasCountry && hasAdmd && hasPrmd && hasOrgLike) {
                return node;
            }

            for (BerTlv child : children) {
                BerTlv found = findAddressContainer(child);
                if (found != null) {
                    return found;
                }
            }
        } catch (RuntimeException ignored) {
        }

        return null;
    }

    private boolean isAddressAttributeTag(BerTlv tlv, int expectedClass, int expectedTag) {
        if (tlv == null || tlv.tagClass() != expectedClass || tlv.tagNumber() != expectedTag) {
            return false;
        }

        if (!tlv.constructed()) {
            return StringUtils.hasText(decodeBerStringValue(tlv));
        }

        try {
            List<BerTlv> nested = BerCodec.decodeAll(tlv.value());
            return nested.size() == 1
                && !nested.get(0).constructed()
                && StringUtils.hasText(decodeBerStringValue(nested.get(0)));
        } catch (RuntimeException ex) {
            return false;
        }
    }

    private String findSenderAddressFromStructuredBer(byte[] payload) {
        if (payload == null || payload.length == 0) {
            return null;
        }

        try {
            BerTlv root = BerCodec.decodeSingle(payload);
            return extractSenderFromBind(root);
        } catch (RuntimeException ex) {
            logger.debug("P3 ASN.1 structured bind decode failed: {}", ex.getMessage());
            return null;
        }
    }

    private boolean hasAnyOrganizationalIdentity(Map<String, String> attrs) {
        return StringUtils.hasText(attrs.get("OU1"))
            || StringUtils.hasText(attrs.get("OU2"))
            || StringUtils.hasText(attrs.get("OU3"))
            || StringUtils.hasText(attrs.get("OU4"))
            || StringUtils.hasText(attrs.get("CN"));
    }

    private boolean looksLikeAddressCandidate(Map<String, String> attrs) {
        return StringUtils.hasText(attrs.get("C"))
            && StringUtils.hasText(attrs.get("ADMD"))
            && StringUtils.hasText(attrs.get("PRMD"))
            && StringUtils.hasText(attrs.get("O"));
    }

    private void collectNativeOrAddressAttributes(BerTlv node, Map<String, String> attrs) {
        if (node == null) {
            return;
        }

        String key = switch (node.tagClass()) {
            case TAG_CLASS_APPLICATION -> switch (node.tagNumber()) {
                case 1 -> "C";
                case 2 -> "ADMD";
                default -> null;
            };
            case TAG_CLASS_CONTEXT -> switch (node.tagNumber()) {
                case 2 -> "PRMD";
                case 3 -> "O";
                case 4 -> "OU1";
                case 5 -> "OU2";
                case 6 -> "OU3";
                case 7 -> "OU4";
                case 8 -> "CN";
                default -> null;
            };
            default -> null;
        };

        if (key != null) {
            String decoded = decodeBerStringValue(node);
            if (StringUtils.hasText(decoded) && !attrs.containsKey(key)) {
                attrs.put(key, decoded);
            }
        }

        if (!node.constructed()) {
            return;
        }

        try {
            for (BerTlv child : BerCodec.decodeAll(node.value())) {
                collectNativeOrAddressAttributes(child, attrs);
            }
        } catch (RuntimeException ignored) {
        }
    }

    private void normalizeNativeOrAddressAttributes(Map<String, String> attrs) {
        if (!attrs.containsKey("C")) {
            String maybeCountry = attrs.get("CN");
            if (maybeCountry != null && maybeCountry.matches("[A-Z]{2}")) {
                attrs.remove("CN");
                attrs.put("C", maybeCountry);
            }
        }

        if ("changeit".equalsIgnoreCase(attrs.get("PRMD"))) {
            attrs.remove("PRMD");
        }

        compactOrganizationalUnits(attrs);
    }

    private void compactOrganizationalUnits(Map<String, String> attrs) {
        List<String> values = new ArrayList<>();

        for (int i = 1; i <= 4; i++) {
            String value = attrs.remove("OU" + i);
            if (StringUtils.hasText(value)) {
                values.add(value);
            }
        }

        for (int i = 0; i < values.size(); i++) {
            attrs.put("OU" + (i + 1), values.get(i));
        }
    }

    private String decodeBerStringValue(BerTlv tlv) {
        if (tlv == null) {
            return null;
        }

        if (tlv.constructed()) {
            try {
                List<BerTlv> nested = BerCodec.decodeAll(tlv.value());
                if (nested.size() == 1) {
                    return decodeBerStringValue(nested.get(0));
                }
            } catch (RuntimeException ignored) {
                return null;
            }
        }

        return switch (tlv.tagClass()) {
            case TAG_CLASS_UNIVERSAL -> switch (tlv.tagNumber()) {
                case TAG_UNIVERSAL_UTF8STRING -> new String(tlv.value(), StandardCharsets.UTF_8).trim();
                case TAG_UNIVERSAL_PRINTABLESTRING,
                     TAG_UNIVERSAL_IA5STRING,
                     25,
                     TAG_UNIVERSAL_VISIBLESTRING,
                     TAG_UNIVERSAL_GENERALSTRING ->
                    new String(tlv.value(), StandardCharsets.US_ASCII).trim();
                case 20 -> new String(tlv.value(), StandardCharsets.ISO_8859_1).trim();
                case TAG_UNIVERSAL_UNIVERSALSTRING -> decodeUniversalStringSafe(tlv.value());
                case TAG_UNIVERSAL_BMPSTRING -> decodeBmpStringSafe(tlv.value());
                default -> new String(tlv.value(), StandardCharsets.UTF_8).trim();
            };
            default -> new String(tlv.value(), StandardCharsets.UTF_8).trim();
        };
    }

    private String decodeBmpStringSafe(byte[] value) {
        if ((value.length & 1) != 0) {
            return null;
        }
        return new String(value, StandardCharsets.UTF_16BE).trim();
    }

    private String decodeUniversalStringSafe(byte[] value) {
        if ((value.length & 3) != 0) {
            return null;
        }
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < value.length; i += 4) {
            int codePoint = ((value[i] & 0xFF) << 24)
                | ((value[i + 1] & 0xFF) << 16)
                | ((value[i + 2] & 0xFF) << 8)
                | (value[i + 3] & 0xFF);
            builder.appendCodePoint(codePoint);
        }
        return builder.toString().trim();
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
            "P3 ASN.1 report request fields recipient={} wait-timeout-ms={} retry-interval-ms={}",
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
            "P3 ASN.1 read request fields recipient={} wait-timeout-ms={} retry-interval-ms={}",
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

        if (text.size() == 1) {
            return text.get(0);
        }

        logger.debug(
            "P3 ASN.1 constructed field value is ambiguous; skipping heuristic selection from candidates={}",
            text.size()
        );
        return null;
    }

    private void collectTextualAtoms(BerTlv tlv, List<String> values) {
        if (tlv.constructed()) {
            try {
                for (BerTlv nested : BerCodec.decodeAll(tlv.value())) {
                    collectTextualAtoms(nested, values);
                }
            } catch (RuntimeException ignored) {
            }
            return;
        }

        if (tlv.tagClass() != TAG_CLASS_UNIVERSAL) {
            maybeAddPrintable(values, tlv.value());
            return;
        }

        switch (tlv.tagNumber()) {
            case TAG_UNIVERSAL_INTEGER -> values.add(decodeIntegerAsString(tlv.value()));
            case 4,
                 TAG_UNIVERSAL_UTF8STRING,
                 TAG_UNIVERSAL_PRINTABLESTRING,
                 TAG_UNIVERSAL_IA5STRING,
                 TAG_UNIVERSAL_VISIBLESTRING,
                 TAG_UNIVERSAL_GENERALSTRING,
                 TAG_UNIVERSAL_UNIVERSALSTRING,
                 TAG_UNIVERSAL_BMPSTRING -> maybeAddPrintable(values, tlv.value());
            default -> {
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
            }
        }
        return null;
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
        byte[] utf8 = BerCodec.encode(
            new BerTlv(TAG_CLASS_UNIVERSAL, false, TAG_UNIVERSAL_UTF8STRING, 0, bytes.length, bytes)
        );
        return BerCodec.encode(new BerTlv(TAG_CLASS_CONTEXT, true, tagNumber, 0, utf8.length, utf8));
    }

    private byte[] encodeContextInteger(int tagNumber, int value) {
        byte[] integer = encodeIntegerUniversal(value);
        return BerCodec.encode(new BerTlv(TAG_CLASS_CONTEXT, true, tagNumber, 0, integer.length, integer));
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
            return BerCodec.encode(
                new BerTlv(TAG_CLASS_UNIVERSAL, false, TAG_UNIVERSAL_INTEGER, 0, 1, new byte[] { 0x00 })
            );
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
        return BerCodec.encode(
            new BerTlv(TAG_CLASS_UNIVERSAL, false, TAG_UNIVERSAL_INTEGER, 0, bytes.length, bytes)
        );
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

    private enum BindStyle {
        GATEWAY,
        NATIVE
    }

    private record DecodedBind(Map<Integer, String> fields, BindStyle style) {
    }

    private record RoseInvoke(int invokeId, int operationCode, byte[] argument) {
    }
}