package it.amhs.service.protocol.p3;

import static it.amhs.service.protocol.p3.P3WireSupport.*;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import it.amhs.asn1.BerCodec;
import it.amhs.asn1.BerTlv;
import it.amhs.service.address.ORAddress;
import it.amhs.service.protocol.p3.P3OperationModels.BindRequest;
import it.amhs.service.protocol.p3.P3OperationModels.BindResult;
import it.amhs.service.protocol.p3.P3OperationModels.P3Error;

@Component
public class P3BindCodec {

    private static final Logger logger = LoggerFactory.getLogger(P3BindCodec.class);

    private static final int NATIVE_BIND_REQUEST_OUTER_TAG = 2;
    private static final int NATIVE_BIND_ERROR_OUTER_TAG = 8;

    public boolean isLikelyNativeBind(byte[] encodedApdu) {
        if (encodedApdu == null || encodedApdu.length == 0) {
            return false;
        }

        try {
            BerTlv apdu = BerCodec.decodeSingle(encodedApdu);
            if (apdu.tagClass() != TAG_CLASS_CONTEXT
                || !apdu.constructed()
                || apdu.tagNumber() != NATIVE_BIND_REQUEST_OUTER_TAG) {
                return false;
            }

            String sender = extractSenderFromBind(apdu);
            String password = extractPasswordFromBind(apdu);
            return StringUtils.hasText(sender) && StringUtils.hasText(password);
        } catch (RuntimeException ex) {
            return false;
        }
    }

    public BindRequest decodeBindRequest(byte[] encodedApdu) {
        BerTlv apdu = BerCodec.decodeSingle(encodedApdu);

        if (apdu.tagClass() != TAG_CLASS_CONTEXT
            || !apdu.constructed()
            || apdu.tagNumber() != NATIVE_BIND_REQUEST_OUTER_TAG) {
            throw new IllegalArgumentException("Not a native P3 bind APDU");
        }

        String sender = extractSenderFromBind(apdu);
        String password = extractPasswordFromBind(apdu);
        String username = extractUsernameFromBind(apdu);
        String channel = extractChannelFromBind(apdu);

        if (!StringUtils.hasText(sender)) {
            throw new IllegalArgumentException("Native P3 bind does not contain sender O/R address");
        }
        if (!StringUtils.hasText(password)) {
            throw new IllegalArgumentException("Native P3 bind does not contain password");
        }

        logger.info(
            "P3 bind decoded authenticatedIdentity={} sender={} channel={} password='{}' password-length={}",
            safe(username),
            sender,
            safe(channel),
            password,
            password.length()
        );

        logger.info(
            "P3 bind decoded authenticatedIdentity={} sender={} channel={} password-present=true",
            safe(username),
            sender,
            safe(channel)
        );

        return new BindRequest(
            trimToNull(username),
            password,
            sender,
            Optional.ofNullable(trimToNull(channel)),
            encodedApdu
        );
    }

    public byte[] encodeBindResult(byte[] inboundBindApdu, BindResult result) {
        if (inboundBindApdu == null || inboundBindApdu.length == 0) {
            throw new IllegalArgumentException("Invalid native bind APDU");
        }

        BerTlv inboundRoot = BerCodec.decodeSingle(inboundBindApdu);

        if (inboundRoot.tagClass() != TAG_CLASS_CONTEXT
            || !inboundRoot.constructed()
            || inboundRoot.tagNumber() != NATIVE_BIND_REQUEST_OUTER_TAG) {
            throw new IllegalArgumentException("Invalid native bind APDU");
        }

        byte[] mtsBindResult = encodeMtsBindResultFromInbound(inboundRoot, result);

        logger.info("P3 bind result encoded as bare MTSBindResult={}", toHex(mtsBindResult));
        return mtsBindResult;
    }

    private byte[] encodeMtsBindResultFromInbound(BerTlv inboundBindRoot, BindResult result) {
        List<byte[]> children = new ArrayList<>();

        children.add(encodeResponderNameFromInbound(inboundBindRoot));

        resolveBindResultLocalIdentifier(inboundBindRoot, result)
            .map(this::encodeBindResultLocalField)
            .ifPresent(children::add);

        byte[] payload = concat(children);

        return BerCodec.encode(
            new BerTlv(
                TAG_CLASS_UNIVERSAL,
                true,
                17,
                0,
                payload.length,
                payload
            )
        );
    }

    private Optional<String> resolveBindResultLocalIdentifier(BerTlv inboundBindRoot, BindResult result) {
        String inbound = extractLastIa5OrGraphicStringByContextTag(inboundBindRoot, 2);
        if (StringUtils.hasText(inbound)) {
            String normalized = inbound.trim();
            logger.info("P3 bind result local identifier resolved from inbound context[2]={}", normalized);
            return Optional.of(normalized);
        }

        logger.info("P3 bind result local identifier not available from inbound bind");
        return Optional.empty();
    }

    private byte[] encodeBindResultLocalField(String value) {
        String normalized = value == null ? "" : value.trim();
        if (!StringUtils.hasText(normalized)) {
            throw new IllegalArgumentException("Bind result local field must not be blank");
        }

        byte[] ascii = normalized.getBytes(StandardCharsets.US_ASCII);

        byte[] ia5 = BerCodec.encode(
            new BerTlv(
                TAG_CLASS_UNIVERSAL,
                false,
                22,
                0,
                ascii.length,
                ascii
            )
        );

        return BerCodec.encode(
            new BerTlv(
                TAG_CLASS_CONTEXT,
                true,
                2,
                0,
                ia5.length,
                ia5
            )
        );
    }

    public byte[] encodeBindError(byte[] inboundBindApdu, P3Error error) {
        List<byte[]> children = new ArrayList<>();
        children.add(encodeUtf8ContextField(0, value(error.code())));
        children.add(encodeUtf8ContextField(1, value(error.detail())));
        children.add(encodeUtf8ContextField(2, Boolean.toString(error.retryable())));

        byte[] payload = concat(children);

        byte[] encoded = BerCodec.encode(
            new BerTlv(
                TAG_CLASS_CONTEXT,
                true,
                NATIVE_BIND_ERROR_OUTER_TAG,
                0,
                payload.length,
                payload
            )
        );

        logger.info("P3 native bind error encoded={}", toHex(encoded));
        return encoded;
    }

    private String extractLastIa5OrGraphicStringByContextTag(BerTlv node, int wantedTag) {
        if (node == null) {
            return null;
        }

        String found = null;

        if (node.constructed()) {
            try {
                List<BerTlv> children = BerCodec.decodeAll(node.value());
                for (BerTlv child : children) {
                    String nested = extractLastIa5OrGraphicStringByContextTag(child, wantedTag);
                    if (StringUtils.hasText(nested)) {
                        found = nested;
                    }
                }
            } catch (RuntimeException ignored) {
            }
        }

        if (node.tagClass() == TAG_CLASS_CONTEXT && node.tagNumber() == wantedTag) {
            try {
                if (node.constructed()) {
                    List<BerTlv> nested = BerCodec.decodeAll(node.value());
                    if (nested.size() == 1 && !nested.get(0).constructed()) {
                        String decoded = decodeIa5OrGraphicString(nested.get(0));
                        if (StringUtils.hasText(decoded)) {
                            found = decoded;
                        }
                    }
                } else {
                    String decoded = new String(node.value(), StandardCharsets.US_ASCII).trim();
                    if (StringUtils.hasText(decoded)) {
                        found = decoded;
                    }
                }
            } catch (RuntimeException ignored) {
            }
        }

        return found;
    }

    private String decodeIa5OrGraphicString(BerTlv tlv) {
        if (tlv == null || tlv.constructed()) {
            return null;
        }

        return switch (tlv.tagClass()) {
            case TAG_CLASS_UNIVERSAL -> switch (tlv.tagNumber()) {
                case 22, 25, 19, 20, 26 -> new String(tlv.value(), StandardCharsets.US_ASCII).trim();
                case 12 -> new String(tlv.value(), StandardCharsets.UTF_8).trim();
                default -> null;
            };
            default -> null;
        };
    }

    private byte[] encodeResponderNameFromInbound(BerTlv inboundBindRoot) {
        BerTlv orName = findInboundOrName(inboundBindRoot);
        if (orName == null) {
            throw new IllegalArgumentException("Cannot build bind result: inbound bind has no ORName");
        }
        return BerCodec.encode(orName);
    }

    private BerTlv findInboundOrName(BerTlv node) {
        if (node == null || !node.constructed()) {
            return null;
        }

        if (node.tagClass() == TAG_CLASS_APPLICATION && node.tagNumber() == 0) {
            try {
                List<BerTlv> children = BerCodec.decodeAll(node.value());
                for (BerTlv child : children) {
                    if (looksLikeOrAddressSequence(child)) {
                        return node;
                    }
                }
            } catch (RuntimeException ignored) {
            }
        }

        try {
            for (BerTlv child : BerCodec.decodeAll(node.value())) {
                BerTlv found = findInboundOrName(child);
                if (found != null) {
                    return found;
                }
            }
        } catch (RuntimeException ignored) {
        }

        return null;
    }

    private boolean looksLikeOrAddressSequence(BerTlv tlv) {
        if (tlv == null || !tlv.constructed()) {
            return false;
        }

        try {
            List<BerTlv> children = BerCodec.decodeAll(tlv.value());

            boolean hasCountry = false;
            boolean hasAdmd = false;
            boolean hasPrmd = false;
            boolean hasOrg = false;

            for (BerTlv child : children) {
                if (isAddressAttributeTag(child, TAG_CLASS_APPLICATION, 1)) {
                    hasCountry = true;
                } else if (isAddressAttributeTag(child, TAG_CLASS_APPLICATION, 2)) {
                    hasAdmd = true;
                } else if (isAddressAttributeTag(child, TAG_CLASS_CONTEXT, 2)) {
                    hasPrmd = true;
                } else if (isAddressAttributeTag(child, TAG_CLASS_CONTEXT, 3)) {
                    hasOrg = true;
                }
            }

            return hasCountry && hasAdmd && hasPrmd && hasOrg;
        } catch (RuntimeException ex) {
            return false;
        }
    }

    private String extractSenderFromBind(BerTlv root) {
        BerTlv addressNode = findAddressContainer(root);
        if (addressNode == null) {
            return null;
        }

        Map<String, String> attrs = new LinkedHashMap<>();
        collectNativeOrAddressAttributes(addressNode, attrs);
        normalizeNativeOrAddressAttributes(attrs);

        logger.info("P3 bind normalized native attrs={}", attrs);

        if (!looksLikeAddressCandidate(attrs)) {
            return null;
        }

        try {
            return ORAddress.of(attrs).toCanonicalString();
        } catch (RuntimeException ex) {
            return null;
        }
    }

    private String extractPasswordFromBind(BerTlv root) {
        BerTlv addressNode = findAddressContainer(root);
        return findLastUtf8ContextValueOutsideAddress(root, addressNode, 2);
    }

    private String extractUsernameFromBind(BerTlv root) {
        BerTlv addressNode = findAddressContainer(root);
        return findUtf8ContextValueOutsideAddress(root, addressNode, 0);
    }

    private String extractChannelFromBind(BerTlv root) {
        BerTlv addressNode = findAddressContainer(root);
        return findUtf8ContextValueOutsideAddress(root, addressNode, 3);
    }

    private String findLastUtf8ContextValueOutsideAddress(BerTlv node, BerTlv addressNode, int wantedTag) {
        if (node == null || node == addressNode) {
            return null;
        }

        String found = null;

        if (node.constructed()) {
            try {
                List<BerTlv> children = BerCodec.decodeAll(node.value());

                for (int i = children.size() - 1; i >= 0; i--) {
                    BerTlv child = children.get(i);
                    if (child == addressNode) {
                        continue;
                    }

                    String nested = findLastUtf8ContextValueOutsideAddress(child, addressNode, wantedTag);
                    if (StringUtils.hasText(nested)) {
                        return nested;
                    }
                }
            } catch (RuntimeException ignored) {
            }
        }

        if (node.tagClass() == TAG_CLASS_CONTEXT && node.tagNumber() == wantedTag) {
            try {
                if (!node.constructed()) {
                    String decoded = new String(node.value(), StandardCharsets.UTF_8).trim();
                    if (StringUtils.hasText(decoded)) {
                        found = decoded;
                    }
                } else {
                    List<BerTlv> nested = BerCodec.decodeAll(node.value());
                    if (nested.size() == 1 && !nested.get(0).constructed()) {
                        String decoded = decodeBerStringValue(nested.get(0));
                        if (StringUtils.hasText(decoded)) {
                            found = decoded;
                        }
                    }
                }
            } catch (RuntimeException ignored) {
            }
        }

        return found;
    }

    private String findUtf8ContextValueOutsideAddress(BerTlv node, BerTlv addressNode, int wantedTag) {
        if (node == null || node == addressNode || !node.constructed()) {
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

    private boolean looksLikeAddressCandidate(Map<String, String> attrs) {
        return StringUtils.hasText(attrs.get("C"))
            && StringUtils.hasText(attrs.get("ADMD"))
            && StringUtils.hasText(attrs.get("PRMD"))
            && StringUtils.hasText(attrs.get("O"));
    }

    private String safe(String value) {
        return StringUtils.hasText(value) ? value : "<empty>";
    }

    private String value(String value) {
        return value == null ? "" : value;
    }

    private String toHex(byte[] value) {
        if (value == null || value.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder(value.length * 2);
        for (byte b : value) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}