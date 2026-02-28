package it.amhs.service;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Component;

import it.amhs.asn1.BerCodec;
import it.amhs.asn1.BerTlv;

@Component
public class P1AssociationProtocol {

    private static final String ICAO_AMHS_P1_ABSTRACT_SYNTAX = "2.6.0.1.6.1";

    public Pdu decode(byte[] payload) {
        BerTlv pdu = BerCodec.decodeSingle(payload);
        if (pdu.tagClass() != 2 || !pdu.constructed()) {
            throw new IllegalArgumentException("P1 association PDU must use context-specific constructed tags");
        }

        return switch (pdu.tagNumber()) {
            case 0 -> decodeBind(pdu.value());
            case 1 -> new TransferPdu(pdu.value());
            case 2 -> new ReleasePdu();
            case 3 -> decodeAbort(pdu.value());
            case 4 -> decodeError(pdu.value());
            default -> throw new IllegalArgumentException("Unsupported P1 association PDU tag [" + pdu.tagNumber() + "]");
        };
    }

    public byte[] encodeBindResult(boolean accepted, String diagnostic) {
        byte[] diagnosticBytes = diagnostic.getBytes(StandardCharsets.UTF_8);
        byte[] payload = concat(
            BerCodec.encode(new BerTlv(2, false, 0, 0, 1, new byte[] {(byte) (accepted ? 1 : 0)})),
            BerCodec.encode(new BerTlv(2, false, 1, 0, diagnosticBytes.length, diagnosticBytes))
        );
        return BerCodec.encode(new BerTlv(2, true, 10, 0, payload.length, payload));
    }

    public byte[] encodeReleaseResult() {
        return BerCodec.encode(new BerTlv(2, true, 11, 0, 0, new byte[0]));
    }

    public byte[] encodeAbort(String diagnostic) {
        byte[] bytes = diagnostic.getBytes(StandardCharsets.UTF_8);
        return BerCodec.encode(new BerTlv(2, true, 3, 0, bytes.length, bytes));
    }

    public byte[] encodeError(String code, String diagnostic) {
        byte[] codeBytes = code.getBytes(StandardCharsets.US_ASCII);
        byte[] diagnosticBytes = diagnostic.getBytes(StandardCharsets.UTF_8);
        byte[] payload = concat(
            BerCodec.encode(new BerTlv(2, false, 0, 0, codeBytes.length, codeBytes)),
            BerCodec.encode(new BerTlv(2, false, 1, 0, diagnosticBytes.length, diagnosticBytes))
        );
        return BerCodec.encode(new BerTlv(2, true, 4, 0, payload.length, payload));
    }

    private BindPdu decodeBind(byte[] payload) {
        List<BerTlv> fields = BerCodec.decodeAll(payload);
        Optional<String> calling = BerCodec.findOptional(fields, 2, 0)
            .map(value -> new String(value.value(), StandardCharsets.US_ASCII));
        Optional<String> called = BerCodec.findOptional(fields, 2, 1)
            .map(value -> new String(value.value(), StandardCharsets.US_ASCII));
        String abstractSyntax = BerCodec.findOptional(fields, 2, 2)
            .map(this::decodeOid)
            .orElseThrow(() -> new IllegalArgumentException("P1 bind does not include abstract syntax"));

        if (!ICAO_AMHS_P1_ABSTRACT_SYNTAX.equals(abstractSyntax)) {
            throw new IllegalArgumentException("Unsupported P1 abstract syntax OID " + abstractSyntax);
        }

        return new BindPdu(calling, called, abstractSyntax);
    }

    private AbortPdu decodeAbort(byte[] payload) {
        String diagnostic = new String(payload, StandardCharsets.UTF_8);
        return new AbortPdu(diagnostic);
    }

    private ErrorPdu decodeError(byte[] payload) {
        List<BerTlv> fields = BerCodec.decodeAll(payload);
        String code = BerCodec.findOptional(fields, 2, 0)
            .map(value -> new String(value.value(), StandardCharsets.US_ASCII))
            .orElse("UNSPECIFIED");
        String diagnostic = BerCodec.findOptional(fields, 2, 1)
            .map(value -> new String(value.value(), StandardCharsets.UTF_8))
            .orElse("");
        return new ErrorPdu(code, diagnostic);
    }

    private String decodeOid(BerTlv oidTlv) {
        if (!oidTlv.isUniversal() || oidTlv.tagNumber() != 6) {
            throw new IllegalArgumentException("P1 bind abstract syntax must be OBJECT IDENTIFIER");
        }
        byte[] encoded = oidTlv.value();
        if (encoded.length == 0) {
            throw new IllegalArgumentException("Invalid OID encoding");
        }
        StringBuilder oid = new StringBuilder();
        int first = encoded[0] & 0xFF;
        oid.append(first / 40).append('.').append(first % 40);
        long value = 0;
        for (int i = 1; i < encoded.length; i++) {
            int octet = encoded[i] & 0xFF;
            value = (value << 7) | (octet & 0x7F);
            if ((octet & 0x80) == 0) {
                oid.append('.').append(value);
                value = 0;
            }
        }
        if (value != 0) {
            throw new IllegalArgumentException("Invalid OID encoding");
        }
        return oid.toString();
    }

    private byte[] concat(byte[]... chunks) {
        int len = 0;
        for (byte[] chunk : chunks) {
            len += chunk.length;
        }
        byte[] out = new byte[len];
        int offset = 0;
        for (byte[] chunk : chunks) {
            System.arraycopy(chunk, 0, out, offset, chunk.length);
            offset += chunk.length;
        }
        return out;
    }

    public sealed interface Pdu permits BindPdu, TransferPdu, ReleasePdu, AbortPdu, ErrorPdu {
    }

    public record BindPdu(Optional<String> callingMta, Optional<String> calledMta, String abstractSyntaxOid) implements Pdu {
    }

    public record TransferPdu(byte[] messagePayload) implements Pdu {
    }

    public record ReleasePdu() implements Pdu {
    }

    public record AbortPdu(String diagnostic) implements Pdu {
    }

    public record ErrorPdu(String code, String diagnostic) implements Pdu {
    }
}
