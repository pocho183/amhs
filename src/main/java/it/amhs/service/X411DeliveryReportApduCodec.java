package it.amhs.service;

import java.nio.charset.StandardCharsets;
import java.util.List;

import it.amhs.asn1.BerCodec;
import it.amhs.asn1.BerTlv;
import it.amhs.domain.AMHSDeliveryStatus;

/**
 * Minimal X.411-oriented report APDU encoder used to materialize a wire-level report structure
 * from persistence entities before transport integration.
 */
public class X411DeliveryReportApduCodec {

    public byte[] encodeNonDeliveryReport(NonDeliveryReportApdu report) {
        if (report.reportedRecipientInfo() == null || report.reportedRecipientInfo().isEmpty()) {
            throw new IllegalArgumentException("NonDeliveryReport requires at least one ReportedRecipientInfo");
        }
        byte[] payload = concat(
            encodeIa5(0, report.mtsIdentifier()),
            encodeBoolean(1, report.returnOfContent()),
            encodeReportedRecipientInfo(report.reportedRecipientInfo()),
            encodeOptionalIa5(3, report.nonDeliveryReason())
        );
        return BerCodec.encode(new BerTlv(2, true, X411TagMap.APDU_NON_DELIVERY_REPORT, 0, payload.length, payload));
    }

    public NonDeliveryReportApdu decodeNonDeliveryReport(byte[] apdu) {
        BerTlv tlv = BerCodec.decodeSingle(apdu);
        if (tlv.tagClass() != 2 || !tlv.constructed() || tlv.tagNumber() != X411TagMap.APDU_NON_DELIVERY_REPORT) {
            throw new IllegalArgumentException("Unexpected APDU tag for NonDeliveryReport");
        }
        List<BerTlv> fields = BerCodec.decodeAll(tlv.value());
        String mtsId = decodeRequiredIa5(fields, 0, "mtsIdentifier");
        boolean returnContent = BerCodec.findOptional(fields, 2, 1)
            .map(flag -> flag.value().length > 0 && flag.value()[0] != 0)
            .orElse(false);
        List<ReportedRecipientInfo> recipients = decodeRecipients(fields);
        String reason = BerCodec.findOptional(fields, 2, 3)
            .map(v -> new String(v.value(), StandardCharsets.US_ASCII))
            .orElse(null);
        return new NonDeliveryReportApdu(mtsId, returnContent, recipients, reason);
    }

    private List<ReportedRecipientInfo> decodeRecipients(List<BerTlv> fields) {
        BerTlv container = BerCodec.findOptional(fields, 2, 2)
            .orElseThrow(() -> new IllegalArgumentException("Missing reported-recipient-info"));
        List<BerTlv> items = BerCodec.decodeAll(container.value());
        if (items.isEmpty()) {
            throw new IllegalArgumentException("reported-recipient-info must not be empty");
        }
        return items.stream().map(item -> {
            List<BerTlv> recipientFields = BerCodec.decodeAll(item.value());
            String recipient = decodeRequiredIa5(recipientFields, 0, "recipient");
            String statusValue = decodeRequiredIa5(recipientFields, 1, "status");
            String diagnostic = BerCodec.findOptional(recipientFields, 2, 2)
                .map(v -> new String(v.value(), StandardCharsets.US_ASCII))
                .orElse(null);
            return new ReportedRecipientInfo(recipient, statusValue, diagnostic);
        }).toList();
    }

    private byte[] encodeReportedRecipientInfo(List<ReportedRecipientInfo> recipients) {
        byte[] content = concat(recipients.stream().map(this::encodeRecipientInfo).toArray(byte[][]::new));
        return BerCodec.encode(new BerTlv(2, true, 2, 0, content.length, content));
    }

    private byte[] encodeRecipientInfo(ReportedRecipientInfo info) {
        byte[] value = concat(
            encodeIa5(0, info.recipient()),
            encodeIa5(1, info.deliveryStatus()),
            encodeOptionalIa5(2, info.diagnosticCode())
        );
        return BerCodec.encode(new BerTlv(2, true, 16, 0, value.length, value));
    }

    private byte[] encodeIa5(int tag, String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Required report field is blank [tag=" + tag + "]");
        }
        byte[] bytes = value.trim().getBytes(StandardCharsets.US_ASCII);
        return BerCodec.encode(new BerTlv(2, false, tag, 0, bytes.length, bytes));
    }

    private String decodeRequiredIa5(List<BerTlv> fields, int tag, String field) {
        return BerCodec.findOptional(fields, 2, tag)
            .map(v -> new String(v.value(), StandardCharsets.US_ASCII))
            .filter(s -> !s.isBlank())
            .orElseThrow(() -> new IllegalArgumentException("Missing report field '" + field + "'"));
    }

    private byte[] encodeOptionalIa5(int tag, String value) {
        if (value == null || value.isBlank()) {
            return new byte[0];
        }
        byte[] bytes = value.trim().getBytes(StandardCharsets.US_ASCII);
        return BerCodec.encode(new BerTlv(2, false, tag, 0, bytes.length, bytes));
    }

    private byte[] encodeBoolean(int tag, boolean value) {
        return BerCodec.encode(new BerTlv(2, false, tag, 0, 1, new byte[] {(byte) (value ? 0xFF : 0x00)}));
    }

    private static byte[] concat(byte[]... chunks) {
        int len = 0;
        for (byte[] chunk : chunks) {
            if (chunk != null) {
                len += chunk.length;
            }
        }
        byte[] out = new byte[len];
        int offset = 0;
        for (byte[] chunk : chunks) {
            if (chunk == null || chunk.length == 0) {
                continue;
            }
            System.arraycopy(chunk, 0, out, offset, chunk.length);
            offset += chunk.length;
        }
        return out;
    }

    public record NonDeliveryReportApdu(
        String mtsIdentifier,
        boolean returnOfContent,
        List<ReportedRecipientInfo> reportedRecipientInfo,
        String nonDeliveryReason
    ) {
    }

    public record ReportedRecipientInfo(String recipient, String deliveryStatus, String diagnosticCode) {
        public static ReportedRecipientInfo from(String recipient, AMHSDeliveryStatus status, String diagnosticCode) {
            return new ReportedRecipientInfo(recipient, status.name(), diagnosticCode);
        }
    }
}
