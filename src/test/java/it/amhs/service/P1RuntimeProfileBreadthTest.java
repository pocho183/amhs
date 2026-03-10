package it.amhs.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import it.amhs.asn1.BerCodec;
import it.amhs.asn1.BerTlv;
import it.amhs.service.protocol.p1.P1AssociationProtocol;
import it.amhs.service.protocol.p1.X411TagMap;

class P1RuntimeProfileBreadthTest {

    private final P1AssociationProtocol protocol = new P1AssociationProtocol();

    @Test
    void shouldCoverAllClaimedInboundRelayProfileApduVariants() {
        Map<Integer, byte[]> inboundSupportedVectors = Map.of(
            X411TagMap.APDU_BIND, protocol.encodeBind(
                java.util.Optional.of("CALLING-MTA"),
                java.util.Optional.of("CALLED-MTA"),
                java.util.Optional.of("auth"),
                java.util.Optional.of("sec")
            ),
            X411TagMap.APDU_TRANSFER, BerCodec.encode(new BerTlv(2, true, X411TagMap.APDU_TRANSFER, 0, 4, "body".getBytes(StandardCharsets.UTF_8))),
            X411TagMap.APDU_RELEASE, BerCodec.encode(new BerTlv(2, true, X411TagMap.APDU_RELEASE, 0, 0, new byte[0])),
            X411TagMap.APDU_ABORT, protocol.encodeAbort("peer-abort"),
            X411TagMap.APDU_ERROR, protocol.encodeError("peer", "peer-notification")
        );

        assertInstanceOf(P1AssociationProtocol.BindPdu.class, protocol.decode(inboundSupportedVectors.get(X411TagMap.APDU_BIND)));
        assertInstanceOf(P1AssociationProtocol.TransferPdu.class, protocol.decode(inboundSupportedVectors.get(X411TagMap.APDU_TRANSFER)));
        assertInstanceOf(P1AssociationProtocol.ReleasePdu.class, protocol.decode(inboundSupportedVectors.get(X411TagMap.APDU_RELEASE)));
        assertInstanceOf(P1AssociationProtocol.AbortPdu.class, protocol.decode(inboundSupportedVectors.get(X411TagMap.APDU_ABORT)));
        assertInstanceOf(P1AssociationProtocol.ErrorPdu.class, protocol.decode(inboundSupportedVectors.get(X411TagMap.APDU_ERROR)));

        Map<Integer, String> inboundUnsupportedDiagnostics = Map.of(
            X411TagMap.APDU_BIND_RESULT,
            "unsupported-operation: bind-result APDU is responder-only in the declared P1 relay/interpersonal profile",
            X411TagMap.APDU_RELEASE_RESULT,
            "unsupported-operation: release-result APDU is responder-only in the declared P1 relay/interpersonal profile",
            X411TagMap.APDU_TRANSFER_RESULT,
            "unsupported-operation: transfer-result APDU is responder-only in the declared P1 relay/interpersonal profile",
            X411TagMap.APDU_NON_DELIVERY_REPORT,
            "unsupported-operation: non-delivery-report APDU is not accepted on inbound relay association traffic",
            X411TagMap.APDU_DELIVERY_REPORT,
            "unsupported-operation: delivery-report APDU is not accepted on inbound relay association traffic"
        );

        Set<Integer> claimedApduTags = X411TagMap.associationApduTags();
        Set<Integer> exercisedApduTags = new java.util.HashSet<>();
        exercisedApduTags.addAll(inboundSupportedVectors.keySet());
        exercisedApduTags.addAll(inboundUnsupportedDiagnostics.keySet());
        assertEquals(claimedApduTags, exercisedApduTags);

        assertEquals(
            inboundUnsupportedDiagnostics.get(X411TagMap.APDU_BIND_RESULT),
            protocol.unsupportedRelayProfileDiagnostic(assertInstanceOf(
                P1AssociationProtocol.BindResultPdu.class,
                protocol.decode(protocol.encodeBindResult(true, "ok"))
            )).orElseThrow()
        );
        assertEquals(
            inboundUnsupportedDiagnostics.get(X411TagMap.APDU_RELEASE_RESULT),
            protocol.unsupportedRelayProfileDiagnostic(assertInstanceOf(
                P1AssociationProtocol.ReleaseResultPdu.class,
                protocol.decode(protocol.encodeReleaseResult())
            )).orElseThrow()
        );
        assertEquals(
            inboundUnsupportedDiagnostics.get(X411TagMap.APDU_TRANSFER_RESULT),
            protocol.unsupportedRelayProfileDiagnostic(assertInstanceOf(
                P1AssociationProtocol.TransferResultPdu.class,
                protocol.decode(protocol.encodeTransferResult(true, "MTS-1", java.util.List.of()))
            )).orElseThrow()
        );
        assertEquals(
            inboundUnsupportedDiagnostics.get(X411TagMap.APDU_NON_DELIVERY_REPORT),
            protocol.unsupportedRelayProfileDiagnostic(assertInstanceOf(
                P1AssociationProtocol.NonDeliveryReportPdu.class,
                protocol.decode(BerCodec.encode(new BerTlv(2, true, X411TagMap.APDU_NON_DELIVERY_REPORT, 0, 1, new byte[] {0x01})))
            )).orElseThrow()
        );
        assertEquals(
            inboundUnsupportedDiagnostics.get(X411TagMap.APDU_DELIVERY_REPORT),
            protocol.unsupportedRelayProfileDiagnostic(assertInstanceOf(
                P1AssociationProtocol.DeliveryReportPdu.class,
                protocol.decode(BerCodec.encode(new BerTlv(2, true, X411TagMap.APDU_DELIVERY_REPORT, 0, 1, new byte[] {0x02})))
            )).orElseThrow()
        );
    }
}
