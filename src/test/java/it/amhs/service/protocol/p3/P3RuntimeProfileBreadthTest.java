package it.amhs.service.protocol.p3;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import it.amhs.asn1.BerCodec;
import it.amhs.asn1.BerTlv;

class P3RuntimeProfileBreadthTest {

    @Test
    void shouldCoverClaimedGatewayRoseAndRtseVariants() {
        StubSessionService sessionService = new StubSessionService();
        P3Asn1GatewayProtocol protocol = new P3Asn1GatewayProtocol(sessionService);
        P3GatewaySessionService.SessionState session = sessionService.newSession();

        byte[] bindRequest = gatewayRequest(P3Asn1GatewayProtocol.APDU_BIND_REQUEST, bindPayload());
        assertEquals(P3Asn1GatewayProtocol.APDU_BIND_RESPONSE, BerCodec.decodeSingle(protocol.handle(session, bindRequest)).tagNumber());

        Map<Integer, byte[]> requestPayloads = Map.of(
            P3Asn1GatewayProtocol.APDU_SUBMIT_REQUEST, submitPayload(),
            P3Asn1GatewayProtocol.APDU_STATUS_REQUEST, statusPayload(),
            P3Asn1GatewayProtocol.APDU_REPORT_REQUEST, reportPayload(),
            P3Asn1GatewayProtocol.APDU_READ_REQUEST, readPayload(),
            P3Asn1GatewayProtocol.APDU_RELEASE_REQUEST, new byte[0]
        );

        Set<Integer> expectedClaimedVariants = Set.of(
            P3Asn1GatewayProtocol.APDU_BIND_REQUEST,
            P3Asn1GatewayProtocol.APDU_BIND_RESPONSE,
            P3Asn1GatewayProtocol.APDU_SUBMIT_REQUEST,
            P3Asn1GatewayProtocol.APDU_SUBMIT_RESPONSE,
            P3Asn1GatewayProtocol.APDU_STATUS_REQUEST,
            P3Asn1GatewayProtocol.APDU_STATUS_RESPONSE,
            P3Asn1GatewayProtocol.APDU_RELEASE_REQUEST,
            P3Asn1GatewayProtocol.APDU_RELEASE_RESPONSE,
            P3Asn1GatewayProtocol.APDU_REPORT_REQUEST,
            P3Asn1GatewayProtocol.APDU_REPORT_RESPONSE,
            P3Asn1GatewayProtocol.APDU_READ_REQUEST,
            P3Asn1GatewayProtocol.APDU_READ_RESPONSE,
            P3Asn1GatewayProtocol.APDU_ERROR
        );
        assertEquals(expectedClaimedVariants, P3Asn1GatewayProtocol.externalClaimedApduVariants());

        Map<Integer, Integer> successTags = Map.of(
            P3Asn1GatewayProtocol.APDU_SUBMIT_REQUEST, P3Asn1GatewayProtocol.APDU_SUBMIT_RESPONSE,
            P3Asn1GatewayProtocol.APDU_STATUS_REQUEST, P3Asn1GatewayProtocol.APDU_STATUS_RESPONSE,
            P3Asn1GatewayProtocol.APDU_REPORT_REQUEST, P3Asn1GatewayProtocol.APDU_REPORT_RESPONSE,
            P3Asn1GatewayProtocol.APDU_READ_REQUEST, P3Asn1GatewayProtocol.APDU_READ_RESPONSE,
            P3Asn1GatewayProtocol.APDU_RELEASE_REQUEST, P3Asn1GatewayProtocol.APDU_RELEASE_RESPONSE
        );

        for (Map.Entry<Integer, byte[]> vector : requestPayloads.entrySet()) {
            byte[] apdu = gatewayRequest(vector.getKey(), vector.getValue());
            BerTlv response = BerCodec.decodeSingle(protocol.handle(session, apdu));
            assertEquals(successTags.get(vector.getKey()), response.tagNumber());
        }

        session = sessionService.newSession();
        for (Map.Entry<Integer, byte[]> vector : requestPayloads.entrySet()) {
            if (vector.getKey() == P3Asn1GatewayProtocol.APDU_RELEASE_REQUEST) {
                continue;
            }
            byte[] rose = roseInvoke(31, vector.getKey(), vector.getValue());
            BerTlv response = BerCodec.decodeSingle(protocol.handle(session, rose));
            assertEquals(2, response.tagNumber());
        }

        byte[] responseOpcodeInvoke = roseInvoke(41, P3Asn1GatewayProtocol.APDU_BIND_RESPONSE, new byte[0]);
        assertEquals(3, BerCodec.decodeSingle(protocol.handle(sessionService.newSession(), responseOpcodeInvoke)).tagNumber());

        byte[] unknownOpcodeInvoke = roseInvoke(42, 99, new byte[0]);
        assertEquals(3, BerCodec.decodeSingle(protocol.handle(sessionService.newSession(), unknownOpcodeInvoke)).tagNumber());

        assertEquals(4, BerCodec.decodeSingle(protocol.handle(sessionService.newSession(), BerCodec.encode(new BerTlv(1, true, 2, 0, 0, new byte[0])))).tagNumber());

        byte[] rtorq = rtseEnvelope(16, bindRequest);
        assertEquals(17, BerCodec.decodeSingle(protocol.handle(sessionService.newSession(), rtorq)).tagNumber());

        byte[] rttd = rtseEnvelope(22, roseInvoke(51, P3Asn1GatewayProtocol.APDU_BIND_REQUEST, bindPayload()));
        assertEquals(21, BerCodec.decodeSingle(protocol.handle(sessionService.newSession(), rttd)).tagNumber());

        byte[] rtab = rtseEnvelope(19, new byte[0]);
        assertEquals(19, BerCodec.decodeSingle(protocol.handle(sessionService.newSession(), rtab)).tagNumber());

        byte[] unsupportedRtse = rtseEnvelope(20, new byte[0]);
        assertEquals(18, BerCodec.decodeSingle(protocol.handle(sessionService.newSession(), unsupportedRtse)).tagNumber());
    }

    @Test
    void shouldRejectInboundResponseAndErrorApduOpcodesAsUnsupportedOperations() {
        StubSessionService sessionService = new StubSessionService();
        P3Asn1GatewayProtocol protocol = new P3Asn1GatewayProtocol(sessionService);

        for (int unsupportedInboundOpcode : new int[] {
            P3Asn1GatewayProtocol.APDU_BIND_RESPONSE,
            P3Asn1GatewayProtocol.APDU_SUBMIT_RESPONSE,
            P3Asn1GatewayProtocol.APDU_STATUS_RESPONSE,
            P3Asn1GatewayProtocol.APDU_REPORT_RESPONSE,
            P3Asn1GatewayProtocol.APDU_READ_RESPONSE,
            P3Asn1GatewayProtocol.APDU_ERROR
        }) {
            BerTlv response = BerCodec.decodeSingle(protocol.handle(
                sessionService.newSession(),
                gatewayRequest(unsupportedInboundOpcode, new byte[0])
            ));
            assertEquals(P3Asn1GatewayProtocol.APDU_ERROR, response.tagNumber());
            assertEquals("unsupported-operation", decodeErrorField(response, 0));
        }

        BerTlv releaseResponse = BerCodec.decodeSingle(protocol.handle(
            sessionService.newSession(),
            gatewayRequest(P3Asn1GatewayProtocol.APDU_RELEASE_RESPONSE, new byte[0])
        ));
        assertEquals(P3Asn1GatewayProtocol.APDU_ERROR, releaseResponse.tagNumber());
        assertEquals("invalid-apdu", decodeErrorField(releaseResponse, 0));
    }

    private static byte[] gatewayRequest(int tagNumber, byte[] payload) {
        return BerCodec.encode(new BerTlv(2, true, tagNumber, 0, payload.length, payload));
    }

    private static byte[] roseInvoke(int invokeId, int operationCode, byte[] argumentApduValue) {
        byte[] operation = BerCodec.encode(new BerTlv(2, false, 1, 0, 1, new byte[] {(byte) operationCode}));
        byte[] argumentApdu = gatewayRequest(operationCode, argumentApduValue);
        byte[] argument = BerCodec.encode(new BerTlv(2, true, 2, 0, argumentApdu.length, argumentApdu));
        byte[] invokeIdField = BerCodec.encode(new BerTlv(2, false, 0, 0, 1, new byte[] {(byte) invokeId}));
        byte[] payload = concat(invokeIdField, operation, argument);
        return BerCodec.encode(new BerTlv(1, true, 1, 0, payload.length, payload));
    }

    private static byte[] rtseEnvelope(int tagNumber, byte[] payload) {
        byte[] any = BerCodec.encode(new BerTlv(2, true, 0, 0, payload.length, payload));
        return BerCodec.encode(new BerTlv(1, true, tagNumber, 0, any.length, any));
    }

    private static byte[] bindPayload() {
        return concat(
            utf8Context(0, "amhsuser"),
            utf8Context(1, "changeit"),
            utf8Context(2, "/C=IT/ADMD=ICAO/PRMD=ENAV/O=ENAV/OU1=LIRR/CN=alice"),
            utf8Context(3, "ATFM")
        );
    }

    private static byte[] submitPayload() {
        return concat(
            utf8Context(0, "/C=IT/ADMD=ICAO/PRMD=ENAV/O=ENAV/OU1=LIRR/CN=bob"),
            utf8Context(1, "subject"),
            utf8Context(2, "hello")
        );
    }

    private static byte[] statusPayload() {
        return concat(utf8Context(0, "sub-1"), integerContext(1, 1000), integerContext(2, 200));
    }

    private static byte[] reportPayload() {
        return concat(
            utf8Context(0, "/C=IT/ADMD=ICAO/PRMD=ENAV/O=ENAV/OU1=LIRR/CN=alice"),
            integerContext(1, 1000),
            integerContext(2, 200)
        );
    }

    private static byte[] readPayload() {
        return concat(
            utf8Context(0, "/C=IT/ADMD=ICAO/PRMD=ENAV/O=ENAV/OU1=LIRR/CN=alice"),
            integerContext(1, 1000),
            integerContext(2, 200)
        );
    }

    private static byte[] utf8Context(int tag, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        return BerCodec.encode(new BerTlv(2, false, tag, 0, bytes.length, bytes));
    }

    private static byte[] integerContext(int tag, int value) {
        return BerCodec.encode(new BerTlv(2, false, tag, 0, 1, new byte[] {(byte) value}));
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

    private static String decodeErrorField(BerTlv errorApdu, int tagNumber) {
        return BerCodec.findOptional(BerCodec.decodeAll(errorApdu.value()), 2, tagNumber)
            .map(value -> new String(value.value(), StandardCharsets.UTF_8))
            .orElse("");
    }
}
