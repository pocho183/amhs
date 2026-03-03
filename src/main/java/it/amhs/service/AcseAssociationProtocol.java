package it.amhs.service;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Component;

import it.amhs.asn1.BerCodec;
import it.amhs.asn1.BerTlv;

@Component
public class AcseAssociationProtocol {

    private static final int TAG_CLASS_APPLICATION = 1;
    private static final int TAG_CLASS_CONTEXT = 2;

    private static final int AARQ_TAG = 0;
    private static final int AARE_TAG = 1;
    private static final int RLRQ_TAG = 2;
    private static final int RLRE_TAG = 3;
    private static final int ABRT_TAG = 4;

    public byte[] encode(AcseModels.AcseApdu apdu) {
        if (apdu instanceof AcseModels.AARQApdu aarq) {
            return encodeAarq(aarq);
        }
        if (apdu instanceof AcseModels.AAREApdu aare) {
            return encodeAare(aare);
        }
        if (apdu instanceof AcseModels.RLRQApdu rlrq) {
            return encodeRlrq(rlrq);
        }
        if (apdu instanceof AcseModels.RLREApdu rlre) {
            return encodeRlre(rlre);
        }
        if (apdu instanceof AcseModels.ABRTApdu abrt) {
            return encodeAbrt(abrt);
        }
        throw new IllegalArgumentException("Unsupported ACSE APDU type: " + apdu.getClass().getSimpleName());
    }

    public AcseModels.AcseApdu decode(byte[] payload) {
        BerTlv apdu = BerCodec.decodeSingle(payload);
        if (apdu.tagClass() != TAG_CLASS_APPLICATION || !apdu.constructed()) {
            throw new IllegalArgumentException("ACSE APDU must use APPLICATION class constructed encoding");
        }
        return switch (apdu.tagNumber()) {
            case AARQ_TAG -> decodeAarq(apdu.value());
            case AARE_TAG -> decodeAare(apdu.value());
            case RLRQ_TAG -> decodeRlrq(apdu.value());
            case RLRE_TAG -> decodeRlre(apdu.value());
            case ABRT_TAG -> decodeAbrt(apdu.value());
            default -> throw new IllegalArgumentException("Unsupported ACSE APDU application tag [" + apdu.tagNumber() + "]");
        };
    }

    private byte[] encodeAarq(AcseModels.AARQApdu aarq) {
        byte[] payload = concat(
            encodeBitString(0, 0x80),
            encodeOid(1, aarq.applicationContextName()),
            aarq.calledAeTitle().map(v -> encodeGraphicString(3, v)).orElse(new byte[0]),
            aarq.callingAeTitle().map(v -> encodeGraphicString(7, v)).orElse(new byte[0])
        );
        return BerCodec.encode(new BerTlv(TAG_CLASS_APPLICATION, true, AARQ_TAG, 0, payload.length, payload));
    }

    private AcseModels.AARQApdu decodeAarq(byte[] payload) {
        List<BerTlv> fields = BerCodec.decodeAll(payload);
        String appCtx = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 1)
            .map(this::decodeOid)
            .orElseThrow(() -> new IllegalArgumentException("AARQ is missing application-context-name [1]"));
        Optional<String> calledAe = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 3)
            .map(this::decodeGraphicString);
        Optional<String> callingAe = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 7)
            .map(this::decodeGraphicString);
        return new AcseModels.AARQApdu(appCtx, callingAe, calledAe);
    }

    private byte[] encodeAare(AcseModels.AAREApdu aare) {
        int result = aare.accepted() ? 0 : 1;
        byte[] payload = concat(
            encodeResult(2, result),
            aare.diagnostic().map(v -> encodeGraphicString(3, v)).orElse(new byte[0])
        );
        return BerCodec.encode(new BerTlv(TAG_CLASS_APPLICATION, true, AARE_TAG, 0, payload.length, payload));
    }

    private AcseModels.AAREApdu decodeAare(byte[] payload) {
        List<BerTlv> fields = BerCodec.decodeAll(payload);
        int result = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 2)
            .map(this::decodeSmallInteger)
            .orElseThrow(() -> new IllegalArgumentException("AARE is missing result [2]"));
        Optional<String> diagnostic = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 3)
            .map(this::decodeGraphicString);
        return new AcseModels.AAREApdu(result == 0, diagnostic);
    }

    private byte[] encodeRlrq(AcseModels.RLRQApdu rlrq) {
        byte[] payload = rlrq.reason().map(v -> encodeGraphicString(0, v)).orElse(new byte[0]);
        return BerCodec.encode(new BerTlv(TAG_CLASS_APPLICATION, true, RLRQ_TAG, 0, payload.length, payload));
    }

    private AcseModels.RLRQApdu decodeRlrq(byte[] payload) {
        List<BerTlv> fields = BerCodec.decodeAll(payload);
        Optional<String> reason = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 0)
            .map(this::decodeGraphicString);
        return new AcseModels.RLRQApdu(reason);
    }

    private byte[] encodeRlre(AcseModels.RLREApdu rlre) {
        byte[] payload = encodeResult(0, rlre.normal() ? 0 : 1);
        return BerCodec.encode(new BerTlv(TAG_CLASS_APPLICATION, true, RLRE_TAG, 0, payload.length, payload));
    }

    private AcseModels.RLREApdu decodeRlre(byte[] payload) {
        List<BerTlv> fields = BerCodec.decodeAll(payload);
        int result = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 0)
            .map(this::decodeSmallInteger)
            .orElse(0);
        return new AcseModels.RLREApdu(result == 0);
    }

    private byte[] encodeAbrt(AcseModels.ABRTApdu abrt) {
        byte[] payload = concat(
            encodeGraphicString(0, abrt.source()),
            abrt.diagnostic().map(v -> encodeGraphicString(1, v)).orElse(new byte[0])
        );
        return BerCodec.encode(new BerTlv(TAG_CLASS_APPLICATION, true, ABRT_TAG, 0, payload.length, payload));
    }

    private AcseModels.ABRTApdu decodeAbrt(byte[] payload) {
        List<BerTlv> fields = BerCodec.decodeAll(payload);
        String source = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 0)
            .map(this::decodeGraphicString)
            .orElse("acse-service-user");
        Optional<String> diagnostic = BerCodec.findOptional(fields, TAG_CLASS_CONTEXT, 1)
            .map(this::decodeGraphicString);
        return new AcseModels.ABRTApdu(source, diagnostic);
    }

    private byte[] encodeGraphicString(int tagNumber, String text) {
        byte[] textBytes = text.trim().getBytes(StandardCharsets.US_ASCII);
        byte[] primitive = BerCodec.encode(new BerTlv(0, false, 25, 0, textBytes.length, textBytes));
        return BerCodec.encode(new BerTlv(TAG_CLASS_CONTEXT, true, tagNumber, 0, primitive.length, primitive));
    }

    private String decodeGraphicString(BerTlv wrapped) {
        BerTlv graphicString = BerCodec.decodeSingle(wrapped.value());
        if (!graphicString.isUniversal() || graphicString.tagNumber() != 25) {
            throw new IllegalArgumentException("ACSE expected GraphicString inside field [" + wrapped.tagNumber() + "]");
        }
        return new String(graphicString.value(), StandardCharsets.US_ASCII);
    }

    private byte[] encodeOid(int tagNumber, String dottedOid) {
        byte[] oidEncoded = encodeOidValue(dottedOid);
        byte[] oidTlv = BerCodec.encode(new BerTlv(0, false, 6, 0, oidEncoded.length, oidEncoded));
        return BerCodec.encode(new BerTlv(TAG_CLASS_CONTEXT, true, tagNumber, 0, oidTlv.length, oidTlv));
    }

    private String decodeOid(BerTlv wrappedOid) {
        BerTlv oidTlv = BerCodec.decodeSingle(wrappedOid.value());
        if (!oidTlv.isUniversal() || oidTlv.tagNumber() != 6) {
            throw new IllegalArgumentException("ACSE expected OBJECT IDENTIFIER inside field [" + wrappedOid.tagNumber() + "]");
        }
        return decodeOidValue(oidTlv.value());
    }

    private byte[] encodeBitString(int tagNumber, int bits) {
        byte[] bitString = BerCodec.encode(new BerTlv(0, false, 3, 0, 2, new byte[] {0x00, (byte) bits}));
        return BerCodec.encode(new BerTlv(TAG_CLASS_CONTEXT, true, tagNumber, 0, bitString.length, bitString));
    }

    private byte[] encodeResult(int tagNumber, int value) {
        return BerCodec.encode(new BerTlv(TAG_CLASS_CONTEXT, false, tagNumber, 0, 1, new byte[] {(byte) value}));
    }

    private int decodeSmallInteger(BerTlv encoded) {
        if (encoded.value().length != 1) {
            throw new IllegalArgumentException("ACSE integer/ENUMERATED field must be one octet");
        }
        return encoded.value()[0] & 0xFF;
    }

    private byte[] encodeOidValue(String oid) {
        String[] parts = oid.split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException("OID must contain at least two arcs");
        }
        int first = Integer.parseInt(parts[0]);
        int second = Integer.parseInt(parts[1]);
        if (first < 0 || first > 2 || second < 0 || (first < 2 && second > 39)) {
            throw new IllegalArgumentException("Invalid first OID arcs");
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write((first * 40) + second);
        for (int i = 2; i < parts.length; i++) {
            long arc = Long.parseLong(parts[i]);
            if (arc < 0) {
                throw new IllegalArgumentException("OID arcs must be >= 0");
            }
            writeBase128(out, arc);
        }
        return out.toByteArray();
    }

    private String decodeOidValue(byte[] oidBytes) {
        if (oidBytes.length == 0) {
            throw new IllegalArgumentException("BER OBJECT IDENTIFIER is empty");
        }
        int first = oidBytes[0] & 0xFF;
        StringBuilder oid = new StringBuilder();
        oid.append(first / 40).append('.').append(first % 40);

        long value = 0;
        for (int i = 1; i < oidBytes.length; i++) {
            int octet = oidBytes[i] & 0xFF;
            value = (value << 7) | (octet & 0x7F);
            if ((octet & 0x80) == 0) {
                oid.append('.').append(value);
                value = 0;
            }
        }
        if (value != 0) {
            throw new IllegalArgumentException("Invalid BER OBJECT IDENTIFIER encoding");
        }
        return oid.toString();
    }

    private void writeBase128(ByteArrayOutputStream out, long arc) {
        int count = 0;
        int[] tmp = new int[10];
        tmp[count++] = (int) (arc & 0x7F);
        arc >>= 7;
        while (arc > 0) {
            tmp[count++] = (int) (arc & 0x7F);
            arc >>= 7;
        }
        for (int i = count - 1; i >= 0; i--) {
            int value = tmp[i];
            if (i != 0) {
                value |= 0x80;
            }
            out.write(value);
        }
    }

    private byte[] concat(byte[]... chunks) {
        int total = 0;
        for (byte[] chunk : chunks) {
            total += chunk.length;
        }
        byte[] out = new byte[total];
        int offset = 0;
        for (byte[] chunk : chunks) {
            System.arraycopy(chunk, 0, out, offset, chunk.length);
            offset += chunk.length;
        }
        return out;
    }
}
