package it.amhs.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;

import org.junit.jupiter.api.Test;

import it.amhs.asn1.BerCodec;
import it.amhs.asn1.BerTlv;
import it.amhs.domain.AMHSDeliveryStatus;

class X411DeliveryReportApduCodecTest {

    private final X411DeliveryReportApduCodec codec = new X411DeliveryReportApduCodec();

    @Test
    void encodesAndDecodesNonDeliveryReportWithRecipientSequence() {
        X411DeliveryReportApduCodec.NonDeliveryReportApdu source = new X411DeliveryReportApduCodec.NonDeliveryReportApdu(
            "MTS-123",
            true,
            List.of(
                new X411DeliveryReportApduCodec.ReportedRecipientInfo("/CN=OPS-1", "FAILED", 22),
                new X411DeliveryReportApduCodec.ReportedRecipientInfo("/CN=OPS-2", "DEFERRED", 28)
            ),
            "transfer-failure"
        );

        byte[] encoded = codec.encodeNonDeliveryReport(source);
        X411DeliveryReportApduCodec.NonDeliveryReportApdu decoded = codec.decodeNonDeliveryReport(encoded);

        assertEquals("MTS-123", decoded.mtsIdentifier());
        assertEquals(2, decoded.reportedRecipientInfo().size());
        assertEquals("/CN=OPS-1", decoded.reportedRecipientInfo().get(0).recipient());
        assertEquals("FAILED", decoded.reportedRecipientInfo().get(0).deliveryStatus());
        assertEquals(28, decoded.reportedRecipientInfo().get(1).diagnosticCode());
    }

    @Test
    void encodesTopLevelApduAsApplicationTag() {
        X411DeliveryReportApduCodec.NonDeliveryReportApdu source = new X411DeliveryReportApduCodec.NonDeliveryReportApdu(
            "MTS-123",
            false,
            List.of(new X411DeliveryReportApduCodec.ReportedRecipientInfo("/CN=OPS-1", "FAILED", 16)),
            null
        );

        byte[] encoded = codec.encodeNonDeliveryReport(source);
        BerTlv tlv = BerCodec.decodeSingle(encoded);

        assertEquals(1, tlv.tagClass());
        assertEquals(X411TagMap.APDU_NON_DELIVERY_REPORT, tlv.tagNumber());
    }

    @Test
    void parsesDiagnosticCodeFromPersistenceFormat() {
        X411DeliveryReportApduCodec.ReportedRecipientInfo info =
            X411DeliveryReportApduCodec.ReportedRecipientInfo.from("/CN=OPS-1", AMHSDeliveryStatus.FAILED, "X411:16");

        assertEquals(16, info.diagnosticCode());
    }

    @Test
    void rejectsNonDeliveryReportWithoutRecipients() {
        X411DeliveryReportApduCodec.NonDeliveryReportApdu source = new X411DeliveryReportApduCodec.NonDeliveryReportApdu(
            "MTS-123",
            false,
            List.of(),
            "failure"
        );

        assertThrows(IllegalArgumentException.class, () -> codec.encodeNonDeliveryReport(source));
    }
}
