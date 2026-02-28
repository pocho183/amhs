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
    private static final int DEFAULT_PROTOCOL_VERSION = 1;

    public byte[] encodeBind(
        Optional<String> callingMta,
        Optional<String> calledMta,
        Optional<String> authenticationParameters,
        Optional<String> securityParameters
    ) {
        byte[] oidValue = new byte[] { 0x56, 0x00, 0x01, 0x06, 0x01 };
        byte[] oidTlv = BerCodec.encode(new BerTlv(0, false, 6, 0, oidValue.length, oidValue));
        byte[] protocolVersion = BerCodec.encode(new BerTlv(2, false, 3, 0, 1, new byte[] {(byte) DEFAULT_PROTOCOL_VERSION}));
        byte[] mtsApdu = BerCodec.encode(new BerTlv(2, true, 6, 0, 0, new byte[0]));
        byte[] presentationContext = BerCodec.encode(new BerTlv(2, true, 7, 0, oidTlv.length, oidTlv));

        byte[] payload = concat(
            callingMta
                .map(v -> BerCodec.encode(new BerTlv(2, false, 0, 0, v.getBytes(StandardCharsets.US_ASCII).length, v.getBytes(StandardCharsets.US_ASCII))))
                .orElse(new byte[0]),
            calledMta
                .map(v -> BerCodec.encode(new BerTlv(2, false, 1, 0, v.getBytes(StandardCharsets.US_ASCII).length, v.getBytes(StandardCharsets.US_ASCII))))
                .orElse(new byte[0]),
            BerCodec.encode(new BerTlv(2, true, 2, 0, oidTlv.length, oidTlv)),
            protocolVersion,
            authenticationParameters
                .map(v -> {
                    byte[] bytes = v.getBytes(StandardCharsets.UTF_8);
                    return BerCodec.encode(new BerTlv(2, false, 4, 0, bytes.length, bytes));
                })
                .orElse(new byte[0]),
            securityParameters
                .map(v -> {
                    byte[] bytes = v.getBytes(StandardCharsets.UTF_8);
                    return BerCodec.encode(new BerTlv(2, false, 5, 0, bytes.length, bytes));
                })
                .orElse(new byte[0]),
            mtsApdu,
            presentationContext
        );
        return BerCodec.encode(new BerTlv(2, true, 0, 0, payload.length, payload));
    }

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
            case 10 -> decodeBindResult(pdu.value());
            case 11 -> new ReleaseResultPdu();
            case 12 -> decodeTransferResult(pdu.value());
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

    public byte[] encodeTransferResult(boolean accepted, String mtsIdentifier, List<RecipientTransferResult> recipientResults) {
        byte[] diagnosticBytes = (accepted ? "accepted" : "rejected").getBytes(StandardCharsets.UTF_8);
        byte[] payload = concat(
            BerCodec.encode(new BerTlv(2, false, 0, 0, 1, new byte[] {(byte) (accepted ? 1 : 0)})),
            BerCodec.encode(new BerTlv(2, false, 1, 0, diagnosticBytes.length, diagnosticBytes)),
            encodeOptionalIa5(2, mtsIdentifier),
            encodeRecipientResults(recipientResults)
        );
        return BerCodec.encode(new BerTlv(2, true, 12, 0, payload.length, payload));
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
        int protocolVersion = BerCodec.findOptional(fields, 2, 3)
            .map(this::decodeProtocolVersion)
            .orElseThrow(() -> new IllegalArgumentException("P1 bind does not include protocol version"));
        Optional<String> authentication = BerCodec.findOptional(fields, 2, 4)
            .map(value -> new String(value.value(), StandardCharsets.UTF_8));
        Optional<String> security = BerCodec.findOptional(fields, 2, 5)
            .map(value -> new String(value.value(), StandardCharsets.UTF_8));
        boolean mtsApduPresent = BerCodec.findOptional(fields, 2, 6).isPresent();
        boolean presentationContextPresent = BerCodec.findOptional(fields, 2, 7).isPresent();

        if (!ICAO_AMHS_P1_ABSTRACT_SYNTAX.equals(abstractSyntax)) {
            throw new IllegalArgumentException("Unsupported P1 abstract syntax OID " + abstractSyntax);
        }
        if (protocolVersion != DEFAULT_PROTOCOL_VERSION) {
            throw new IllegalArgumentException("Unsupported P1 protocol version " + protocolVersion);
        }
        if (!mtsApduPresent) {
            throw new IllegalArgumentException("P1 bind does not include MTS APDU container");
        }
        if (!presentationContextPresent) {
            throw new IllegalArgumentException("P1 bind does not include presentation context");
        }

        return new BindPdu(calling, called, abstractSyntax, protocolVersion, authentication, security, mtsApduPresent, presentationContextPresent);
    }


    private BindResultPdu decodeBindResult(byte[] payload) {
        List<BerTlv> fields = BerCodec.decodeAll(payload);
        boolean accepted = BerCodec.findOptional(fields, 2, 0)
            .map(this::decodeBooleanFlag)
            .orElse(false);
        String diagnostic = BerCodec.findOptional(fields, 2, 1)
            .map(value -> new String(value.value(), StandardCharsets.UTF_8))
            .orElse("");
        return new BindResultPdu(accepted, diagnostic);
    }

    private TransferResultPdu decodeTransferResult(byte[] payload) {
        List<BerTlv> fields = BerCodec.decodeAll(payload);
        boolean accepted = BerCodec.findOptional(fields, 2, 0)
            .map(this::decodeBooleanFlag)
            .orElse(false);
        String diagnostic = BerCodec.findOptional(fields, 2, 1)
            .map(value -> new String(value.value(), StandardCharsets.UTF_8))
            .orElse("");
        Optional<String> mtsIdentifier = BerCodec.findOptional(fields, 2, 2)
            .map(value -> new String(value.value(), StandardCharsets.US_ASCII));
        List<RecipientTransferResult> recipientResults = BerCodec.findOptional(fields, 2, 3)
            .filter(BerTlv::constructed)
            .map(this::decodeRecipientTransferResults)
            .orElse(List.of());
        return new TransferResultPdu(accepted, diagnostic, mtsIdentifier, recipientResults);
    }

    private List<RecipientTransferResult> decodeRecipientTransferResults(BerTlv recipients) {
        return BerCodec.decodeAll(recipients.value()).stream()
            .filter(BerTlv::constructed)
            .map(this::decodeRecipientTransferResult)
            .toList();
    }

    private RecipientTransferResult decodeRecipientTransferResult(BerTlv recipient) {
        List<BerTlv> fields = BerCodec.decodeAll(recipient.value());
        String address = BerCodec.findOptional(fields, 2, 0)
            .map(value -> new String(value.value(), StandardCharsets.US_ASCII))
            .orElse("UNKNOWN");
        int status = BerCodec.findOptional(fields, 2, 1)
            .map(this::decodeInteger)
            .orElse(0);
        Optional<String> diagnostic = BerCodec.findOptional(fields, 2, 2)
            .map(value -> new String(value.value(), StandardCharsets.UTF_8));
        return new RecipientTransferResult(address, status, diagnostic);
    }

    private byte[] encodeRecipientResults(List<RecipientTransferResult> recipientResults) {
        if (recipientResults == null || recipientResults.isEmpty()) {
            return new byte[0];
        }
        byte[] encoded = concat(recipientResults.stream()
            .map(this::encodeRecipientResult)
            .toArray(byte[][]::new));
        return BerCodec.encode(new BerTlv(2, true, 3, 0, encoded.length, encoded));
    }

    private byte[] encodeRecipientResult(RecipientTransferResult recipientResult) {
        byte[] payload = concat(
            encodeOptionalIa5(0, recipientResult.recipient()),
            encodeInteger(1, recipientResult.status()),
            recipientResult.diagnostic()
                .map(value -> {
                    byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
                    return BerCodec.encode(new BerTlv(2, false, 2, 0, bytes.length, bytes));
                })
                .orElse(new byte[0])
        );
        return BerCodec.encode(new BerTlv(2, true, 0, 0, payload.length, payload));
    }

    private byte[] encodeOptionalIa5(int tag, String value) {
        if (value == null || value.isBlank()) {
            return new byte[0];
        }
        byte[] bytes = value.trim().getBytes(StandardCharsets.US_ASCII);
        return BerCodec.encode(new BerTlv(2, false, tag, 0, bytes.length, bytes));
    }

    private byte[] encodeInteger(int tag, int value) {
        if (value < 0 || value > 255) {
            throw new IllegalArgumentException("P1 integer field is currently limited to 0..255");
        }
        return BerCodec.encode(new BerTlv(2, false, tag, 0, 1, new byte[] {(byte) value}));
    }

    private int decodeInteger(BerTlv value) {
        if (value.value().length == 0 || value.value().length > 4) {
            throw new IllegalArgumentException("P1 integer field must be between 1 and 4 octets");
        }
        int number = 0;
        for (byte b : value.value()) {
            number = (number << 8) | (b & 0xFF);
        }
        return number;
    }

    private boolean decodeBooleanFlag(BerTlv value) {
        if (value.value().length != 1) {
            throw new IllegalArgumentException("P1 boolean-like status field must be one octet");
        }
        return (value.value()[0] & 0xFF) != 0;
    }

    private int decodeProtocolVersion(BerTlv version) {
        if (version.value().length != 1) {
            throw new IllegalArgumentException("P1 bind protocol version must be one octet");
        }
        return version.value()[0] & 0xFF;
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

    public sealed interface Pdu permits BindPdu, TransferPdu, ReleasePdu, AbortPdu, ErrorPdu, BindResultPdu, ReleaseResultPdu, TransferResultPdu {
    }

    public record BindPdu(
        Optional<String> callingMta,
        Optional<String> calledMta,
        String abstractSyntaxOid,
        int protocolVersion,
        Optional<String> authenticationParameters,
        Optional<String> securityParameters,
        boolean mtsApduPresent,
        boolean presentationContextPresent
    ) implements Pdu {
    }

    public record TransferPdu(byte[] messagePayload) implements Pdu {
    }

    public record ReleasePdu() implements Pdu {
    }

    public record AbortPdu(String diagnostic) implements Pdu {
    }

    public record ErrorPdu(String code, String diagnostic) implements Pdu {
    }

    public record BindResultPdu(boolean accepted, String diagnostic) implements Pdu {
    }

    public record ReleaseResultPdu() implements Pdu {
    }

    public record TransferResultPdu(
        boolean accepted,
        String diagnostic,
        Optional<String> mtsIdentifier,
        List<RecipientTransferResult> recipientResults
    ) implements Pdu {
    }

    public record RecipientTransferResult(String recipient, int status, Optional<String> diagnostic) {
    }
}

