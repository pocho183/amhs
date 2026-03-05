package it.amhs.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
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
    void encodesStructuredMtsIdentifierRecipientAndEnumeratedStatus() {
        X411DeliveryReportApduCodec.NonDeliveryReportApdu source = new X411DeliveryReportApduCodec.NonDeliveryReportApdu(
            "MTS-777",
            false,
            List.of(new X411DeliveryReportApduCodec.ReportedRecipientInfo("/C=IT/ADMD=ICAO/PRMD=ROMA/CN=OPS-1", "FAILED", 16)),
            null
        );

        byte[] encoded = codec.encodeNonDeliveryReport(source);
        BerTlv apdu = BerCodec.decodeSingle(encoded);
        List<BerTlv> fields = BerCodec.decodeAll(apdu.value());

        BerTlv mtsIdentifier = BerCodec.findOptional(fields, X411TagMap.TAG_CLASS_CONTEXT, 0).orElseThrow();
        assertTrue(mtsIdentifier.constructed());
        List<BerTlv> mtsFields = BerCodec.decodeAll(mtsIdentifier.value());
        assertTrue(BerCodec.findOptional(mtsFields, X411TagMap.TAG_CLASS_CONTEXT, 0).isPresent());
        assertTrue(BerCodec.findOptional(mtsFields, X411TagMap.TAG_CLASS_CONTEXT, 1).isPresent());

        BerTlv recipientContainer = BerCodec.findOptional(fields, X411TagMap.TAG_CLASS_CONTEXT, 2).orElseThrow();
        BerTlv recipientEntry = BerCodec.decodeAll(recipientContainer.value()).get(0);
        List<BerTlv> recipientFields = BerCodec.decodeAll(recipientEntry.value());

        BerTlv recipient = BerCodec.findOptional(recipientFields, X411TagMap.TAG_CLASS_CONTEXT, 0).orElseThrow();
        BerTlv status = BerCodec.findOptional(recipientFields, X411TagMap.TAG_CLASS_CONTEXT, 1).orElseThrow();
        assertTrue(recipient.constructed());
        assertEquals(1, status.value().length);
        assertEquals(3, status.value()[0]);
    }

    @Test
    void decodesStructuredMtsIdentifierWithGlobalDomainAndMessageIdentifier() {
        byte[] gdiContent = concat(
            BerCodec.encode(new BerTlv(X411TagMap.TAG_CLASS_CONTEXT, false, 0, 0, 2, "IT".getBytes(StandardCharsets.US_ASCII))),
            BerCodec.encode(new BerTlv(X411TagMap.TAG_CLASS_CONTEXT, false, 1, 0, 4, "ICAO".getBytes(StandardCharsets.US_ASCII))),
            BerCodec.encode(new BerTlv(X411TagMap.TAG_CLASS_CONTEXT, false, 2, 0, 4, "ROMA".getBytes(StandardCharsets.US_ASCII)))
        );
        byte[] gdiSequence = BerCodec.encode(new BerTlv(0, true, 16, 0, gdiContent.length, gdiContent));
        byte[] mtsIdentifier = concat(
            BerCodec.encode(new BerTlv(X411TagMap.TAG_CLASS_CONTEXT, true, 0, 0, gdiSequence.length, gdiSequence)),
            BerCodec.encode(new BerTlv(X411TagMap.TAG_CLASS_CONTEXT, false, 1, 0, 7, "MTS-NEW".getBytes(StandardCharsets.US_ASCII)))
        );

        byte[] entryValue = concat(
            BerCodec.encode(new BerTlv(X411TagMap.TAG_CLASS_CONTEXT, false, 0, 0, 9, "/CN=OPS-1".getBytes(StandardCharsets.US_ASCII))),
            BerCodec.encode(new BerTlv(X411TagMap.TAG_CLASS_CONTEXT, false, 1, 0, 1, new byte[] {3}))
        );
        byte[] recipientEntry = BerCodec.encode(new BerTlv(X411TagMap.TAG_CLASS_CONTEXT, true, 16, 0, entryValue.length, entryValue));
        byte[] recipients = BerCodec.encode(new BerTlv(X411TagMap.TAG_CLASS_CONTEXT, true, 2, 0, recipientEntry.length, recipientEntry));
        byte[] payload = concat(
            BerCodec.encode(new BerTlv(X411TagMap.TAG_CLASS_CONTEXT, true, 0, 0, mtsIdentifier.length, mtsIdentifier)),
            BerCodec.encode(new BerTlv(X411TagMap.TAG_CLASS_CONTEXT, false, 1, 0, 1, new byte[] {(byte) 0xFF})),
            recipients
        );
        byte[] apdu = BerCodec.encode(new BerTlv(X411TagMap.TAG_CLASS_APPLICATION, true, X411TagMap.APDU_NON_DELIVERY_REPORT, 0, payload.length, payload));

        X411DeliveryReportApduCodec.NonDeliveryReportApdu decoded = codec.decodeNonDeliveryReport(apdu);

        assertEquals("MTS-NEW", decoded.mtsIdentifier());
    }

    @Test
    void decodesLegacyIa5AndStatusNameFormatForBackwardCompatibility() {
        byte[] entryValue = concat(
            BerCodec.encode(new BerTlv(X411TagMap.TAG_CLASS_CONTEXT, false, 0, 0, 9, "/CN=OPS-1".getBytes(StandardCharsets.US_ASCII))),
            BerCodec.encode(new BerTlv(X411TagMap.TAG_CLASS_CONTEXT, false, 1, 0, 6, "FAILED".getBytes(StandardCharsets.US_ASCII))),
            BerCodec.encode(new BerTlv(X411TagMap.TAG_CLASS_CONTEXT, false, 2, 0, 2, "22".getBytes(StandardCharsets.US_ASCII)))
        );
        byte[] recipientEntry = BerCodec.encode(new BerTlv(X411TagMap.TAG_CLASS_CONTEXT, true, 16, 0, entryValue.length, entryValue));
        byte[] recipients = BerCodec.encode(new BerTlv(X411TagMap.TAG_CLASS_CONTEXT, true, 2, 0, recipientEntry.length, recipientEntry));
        byte[] payload = concat(
            BerCodec.encode(new BerTlv(X411TagMap.TAG_CLASS_CONTEXT, false, 0, 0, 7, "MTS-LEG".getBytes(StandardCharsets.US_ASCII))),
            BerCodec.encode(new BerTlv(X411TagMap.TAG_CLASS_CONTEXT, false, 1, 0, 1, new byte[] {(byte) 0xFF})),
            recipients
        );
        byte[] apdu = BerCodec.encode(new BerTlv(X411TagMap.TAG_CLASS_APPLICATION, true, X411TagMap.APDU_NON_DELIVERY_REPORT, 0, payload.length, payload));

        X411DeliveryReportApduCodec.NonDeliveryReportApdu decoded = codec.decodeNonDeliveryReport(apdu);

        assertEquals("MTS-LEG", decoded.mtsIdentifier());
        assertEquals("FAILED", decoded.reportedRecipientInfo().get(0).deliveryStatus());
        assertEquals(22, decoded.reportedRecipientInfo().get(0).diagnosticCode());
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
    void validatesEncodedNonDeliveryReportAgainstProfileTagTable() {
        X411DeliveryReportApduCodec.NonDeliveryReportApdu source = new X411DeliveryReportApduCodec.NonDeliveryReportApdu(
            "MTS-321",
            false,
            List.of(X411DeliveryReportApduCodec.ReportedRecipientInfo.from("/CN=OPS-1", AMHSDeliveryStatus.FAILED, "X411:22")),
            "transfer-failure"
        );

        byte[] encoded = codec.encodeNonDeliveryReport(source);
        X411DeliveryReportApduCodec.ValidationResult validation = codec.validateEncodedNonDeliveryReport(encoded);

        assertEquals(X411TagMap.TAG_CLASS_APPLICATION, validation.tagClass());
        assertEquals(X411TagMap.APDU_NON_DELIVERY_REPORT, validation.tagNumber());
        assertTrue(validation.fieldCount() >= 3);
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

    private static byte[] concat(byte[]... chunks) {
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
}
