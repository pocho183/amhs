package it.amhs.service.protocol.p3;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import it.amhs.asn1.BerCodec;
import it.amhs.asn1.BerTlv;

class P3Asn1GatewayProtocolTest {

    @Test
    void mapsBindAndSubmitAndStatusToSessionService() {
        StubSessionService sessionService = new StubSessionService();
        P3Asn1GatewayProtocol protocol = new P3Asn1GatewayProtocol(sessionService);
        P3GatewaySessionService.SessionState session = sessionService.newSession();

        byte[] bindResponse = protocol.handle(session, bindRequest("amhsuser", "changeit", "/C=IT/ADMD=ICAO/PRMD=ENAV/O=ENAV/OU1=LIRR/CN=alice", "ATFM"));
        BerTlv bind = BerCodec.decodeSingle(bindResponse);
        assertEquals(P3Asn1GatewayProtocol.APDU_BIND_RESPONSE, bind.tagNumber());

        byte[] submitResponse = protocol.handle(session, submitRequest("/C=IT/ADMD=ICAO/PRMD=ENAV/O=ENAV/OU1=LIRR/CN=bob", "subject", "hello"));
        BerTlv submit = BerCodec.decodeSingle(submitResponse);
        assertEquals(P3Asn1GatewayProtocol.APDU_SUBMIT_RESPONSE, submit.tagNumber());

        byte[] statusResponse = protocol.handle(session, statusRequest("sub-1", 1000, 200));
        BerTlv status = BerCodec.decodeSingle(statusResponse);
        assertEquals(P3Asn1GatewayProtocol.APDU_STATUS_RESPONSE, status.tagNumber());
    }

    @Test
    void readPduReturnsNullAtEof() throws Exception {
        StubSessionService sessionService = new StubSessionService();
        P3Asn1GatewayProtocol protocol = new P3Asn1GatewayProtocol(sessionService);
        assertNull(protocol.readPdu(new ByteArrayInputStream(new byte[0])));
    }

    @Test
    void readPduReadsSingleBerPacket() throws Exception {
        StubSessionService sessionService = new StubSessionService();
        P3Asn1GatewayProtocol protocol = new P3Asn1GatewayProtocol(sessionService);
        byte[] pdu = bindRequest("u", "p", "/C=IT/ADMD=ICAO/PRMD=ENAV/O=ENAV/OU1=LIRR/CN=alice", "ATFM");

        byte[] read = protocol.readPdu(new ByteArrayInputStream(pdu));
        assertEquals(pdu.length, read.length);
    }

    private static byte[] bindRequest(String username, String password, String sender, String channel) {
        byte[] payload = concat(
            utf8Context(0, username),
            utf8Context(1, password),
            utf8Context(2, sender),
            utf8Context(3, channel)
        );
        return BerCodec.encode(new BerTlv(2, true, P3Asn1GatewayProtocol.APDU_BIND_REQUEST, 0, payload.length, payload));
    }

    private static byte[] submitRequest(String recipient, String subject, String body) {
        byte[] payload = concat(
            utf8Context(0, recipient),
            utf8Context(1, subject),
            utf8Context(2, body)
        );
        return BerCodec.encode(new BerTlv(2, true, P3Asn1GatewayProtocol.APDU_SUBMIT_REQUEST, 0, payload.length, payload));
    }

    private static byte[] statusRequest(String submissionId, int waitMs, int retryMs) {
        byte[] payload = concat(
            utf8Context(0, submissionId),
            integerContext(1, waitMs),
            integerContext(2, retryMs)
        );
        return BerCodec.encode(new BerTlv(2, true, P3Asn1GatewayProtocol.APDU_STATUS_REQUEST, 0, payload.length, payload));
    }

    private static byte[] utf8Context(int tagNumber, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        byte[] utf8 = BerCodec.encode(new BerTlv(0, false, 12, 0, bytes.length, bytes));
        return BerCodec.encode(new BerTlv(2, true, tagNumber, 0, utf8.length, utf8));
    }

    private static byte[] integerContext(int tagNumber, int value) {
        byte[] integer = BerCodec.encode(new BerTlv(0, false, 2, 0, 1, new byte[] { (byte) value }));
        return BerCodec.encode(new BerTlv(2, true, tagNumber, 0, integer.length, integer));
    }

    private static byte[] concat(byte[]... arrays) {
        int size = 0;
        for (byte[] array : arrays) {
            size += array.length;
        }
        byte[] out = new byte[size];
        int offset = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, out, offset, array.length);
            offset += array.length;
        }
        return out;
    }

    private static final class StubSessionService extends P3GatewaySessionService {

        StubSessionService() {
            super(
                null,
                null,
                null,
                null,
                null,
                null,
                1000,
                100,
                true,
                "amhsuser",
                "changeit",
                "RFC1006",
                "127.0.0.1:102",
                "AMHS-P3-GATEWAY"
            );
        }

        @Override
        public String handleCommand(SessionState state, String rawCommand) {
            String op = rawCommand.split("\\s+", 2)[0].toUpperCase();
            return switch (op) {
                case "BIND" -> {
                    yield "OK code=bind-accepted sender=/C=IT/ADMD=ICAO/PRMD=ENAV/O=ENAV/OU1=LIRR/CN=alice";
                }
                case "SUBMIT" -> "OK code=submitted submission-id=sub-1 message-id=42";
                case "STATUS" -> "OK code=status submission-id=sub-1 message-id=42 state=REPORTED dr-status=DELIVERED ipn-status=REPORTED";
                case "UNBIND" -> {
                    yield "OK code=release";
                }
                default -> "ERR code=unsupported-operation detail=Unsupported";
            };
        }
    }
}
