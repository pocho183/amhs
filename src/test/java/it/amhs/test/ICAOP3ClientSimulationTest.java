package it.amhs.test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import it.amhs.asn1.BerCodec;
import it.amhs.asn1.BerTlv;
import it.amhs.service.protocol.p3.P3Asn1GatewayProtocol;
import it.amhs.service.protocol.p3.P3GatewaySessionService;

public class ICAOP3ClientSimulationTest {

    private static final int APDU_BIND_REQUEST = 0;
    private static final int APDU_BIND_RESPONSE = 1;
    private static final int APDU_SUBMIT_REQUEST = 2;
    private static final int APDU_SUBMIT_RESPONSE = 3;

    private static final int RTSE_RTORQ = 16;
    private static final int RTSE_RTOAC = 17;
    private static final int RTSE_RTTR = 21;
    private static final int RTSE_RTTD = 22;

    public static void main(String[] args) {
        RecordingSessionService sessionService = new RecordingSessionService();
        P3Asn1GatewayProtocol protocol = new P3Asn1GatewayProtocol(sessionService);
        P3GatewaySessionService.SessionState session = sessionService.newSession();

        byte[] bindRequest = rtseEnvelope(
            RTSE_RTORQ,
            roseInvoke(1, APDU_BIND_REQUEST, nativeBindRequest("changeit", "ATFM"))
        );

        byte[] bindResponse = protocol.handle(session, bindRequest);

        requireEquals(RTSE_RTOAC, BerCodec.decodeSingle(bindResponse).tagNumber(), "Unexpected RTSE bind response tag");
        requireEquals(
            "BIND username=;password=changeit;sender=/C=IT/ADMD=ICAO/PRMD=ENAV/O=ORG/OU1=LIMCZZZX/CN=LIMCZZZX;channel=ATFM",
            sessionService.commands.get(0),
            "Unexpected bind command"
        );
        assertNativeBindAccept(bindResponse);

        byte[] submitRequest = rtseEnvelope(
            RTSE_RTTD,
            roseInvoke(
                2,
                APDU_SUBMIT_REQUEST,
                submitRequest(
                    "/C=IT/ADMD=ICAO/PRMD=ENAV/O=ORG/OU1=LIRRZZZX/CN=LIRRZZZX",
                    "ICAO P3 test message",
                    "GG LIRRZQZX 191200\nTHIS IS A FULL ICAO P3 CLIENT SIMULATION TEST"
                )
            )
        );

        byte[] submitResponse = protocol.handle(session, submitRequest);

        requireEquals(RTSE_RTTR, BerCodec.decodeSingle(submitResponse).tagNumber(), "Unexpected RTSE submit response tag");
        requireEquals(
            "SUBMIT recipient=/C=IT/ADMD=ICAO/PRMD=ENAV/O=ORG/OU1=LIRRZZZX/CN=LIRRZZZX;subject=ICAO P3 test message;body=GG LIRRZQZX 191200\nTHIS IS A FULL ICAO P3 CLIENT SIMULATION TEST",
            sessionService.commands.get(1),
            "Unexpected submit command"
        );
        assertSubmitAccepted(submitResponse);
        System.out.println("ICAO P3 client simulation completed successfully");
    }

    private static void assertNativeBindAccept(byte[] rtseResponse) {
        BerTlv rtse = BerCodec.decodeSingle(rtseResponse);
        BerTlv roseResult = unwrapSingle(rtse.value());
        requireEquals(2, roseResult.tagNumber(), "Unexpected ROSE result tag for bind");

        BerTlv sequence = BerCodec.decodeSingle(roseResult.value());
        List<BerTlv> fields = BerCodec.decodeAll(sequence.value());
        requireEquals(2, fields.size(), "Unexpected ROSE bind result field count");
        requireEquals(1, fields.get(1).tagNumber(), "Unexpected bind response APDU tag");

        List<BerTlv> bindResponseFields = BerCodec.decodeAll(fields.get(1).value());
        requireEquals(1, bindResponseFields.size(), "Unexpected bind response field count");
        requireEquals(0, bindResponseFields.get(0).tagNumber(), "Unexpected bind result field tag");
        requireEquals(0, bindResponseFields.get(0).value()[0] & 0xFF, "Unexpected bind result status");
    }

    private static void assertSubmitAccepted(byte[] rtseResponse) {
        BerTlv rtse = BerCodec.decodeSingle(rtseResponse);
        BerTlv roseResult = unwrapSingle(rtse.value());
        requireEquals(2, roseResult.tagNumber(), "Unexpected ROSE result tag for submit");

        BerTlv sequence = BerCodec.decodeSingle(roseResult.value());
        List<BerTlv> fields = BerCodec.decodeAll(sequence.value());
        requireEquals(2, fields.size(), "Unexpected ROSE submit result field count");
        requireEquals(APDU_SUBMIT_RESPONSE, fields.get(1).tagNumber(), "Unexpected submit response APDU tag");

        List<BerTlv> submitResponseFields = BerCodec.decodeAll(fields.get(1).value());
        requireTrue(!submitResponseFields.isEmpty(), "Submit response fields must not be empty");
        requireEquals(0, submitResponseFields.get(0).tagNumber(), "Unexpected first submit response field tag");
    }


    private static void requireEquals(Object expected, Object actual, String message) {
        if (expected == null ? actual != null : !expected.equals(actual)) {
            throw new IllegalStateException(message + ": expected=" + expected + ", actual=" + actual);
        }
    }

    private static void requireTrue(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }

    private static BerTlv unwrapSingle(byte[] encodedChildren) {
        return BerCodec.decodeSingle(BerCodec.decodeAll(encodedChildren).get(0).value());
    }

    private static byte[] nativeBindRequest(String password, String channel) {
        BerTlv senderAddress = nativeAddress();
        byte[] payload = concat(
            // Keep the explicit channel field ahead of the OR-address subtree so the native bind
            // heuristics resolve ATFM instead of the nested O=ORG attribute.
            wrappedUtf8Context(2, password),
            wrappedUtf8Context(3, channel),
            BerCodec.encode(senderAddress)
        );
        byte[] bindArgument = BerCodec.encode(new BerTlv(0, true, 16, 0, payload.length, payload));
        return BerCodec.encode(new BerTlv(2, true, APDU_BIND_REQUEST, 0, bindArgument.length, bindArgument));
    }

    private static BerTlv nativeAddress() {
        byte[] payload = concat(
            wrappedPrintableApplication(1, "IT"),
            wrappedPrintableApplication(2, "ICAO"),
            wrappedUtf8Context(2, "ENAV"),
            wrappedUtf8Context(3, "ORG"),
            wrappedUtf8Context(4, "LIMCZZZX"),
            wrappedUtf8Context(8, "LIMCZZZX")
        );
        return new BerTlv(0, true, 16, 0, payload.length, payload);
    }

    private static byte[] submitRequest(String recipient, String subject, String body) {
        byte[] payload = concat(
            wrappedUtf8Context(0, recipient),
            wrappedUtf8Context(1, subject),
            wrappedUtf8Context(2, body)
        );
        return BerCodec.encode(new BerTlv(2, true, APDU_SUBMIT_REQUEST, 0, payload.length, payload));
    }

    private static byte[] roseInvoke(int invokeId, int operationCode, byte[] argumentApdu) {
        byte[] body = BerCodec.encode(new BerTlv(
            0,
            true,
            16,
            0,
            concat(
                new byte[] { (byte) 0x80, 0x01, (byte) invokeId },
                new byte[] { (byte) 0x81, 0x01, (byte) operationCode },
                BerCodec.encode(new BerTlv(2, true, 2, 0, argumentApdu.length, argumentApdu))
            ).length,
            concat(
                new byte[] { (byte) 0x80, 0x01, (byte) invokeId },
                new byte[] { (byte) 0x81, 0x01, (byte) operationCode },
                BerCodec.encode(new BerTlv(2, true, 2, 0, argumentApdu.length, argumentApdu))
            )
        ));
        return BerCodec.encode(new BerTlv(1, true, 1, 0, body.length, body));
    }

    private static byte[] rtseEnvelope(int tagNumber, byte[] payload) {
        byte[] any = BerCodec.encode(new BerTlv(2, true, 0, 0, payload.length, payload));
        return BerCodec.encode(new BerTlv(1, true, tagNumber, 0, any.length, any));
    }

    private static byte[] wrappedUtf8Context(int tagNumber, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        byte[] utf8 = BerCodec.encode(new BerTlv(0, false, 12, 0, bytes.length, bytes));
        return BerCodec.encode(new BerTlv(2, true, tagNumber, 0, utf8.length, utf8));
    }

    private static byte[] wrappedPrintableApplication(int tagNumber, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
        byte[] printable = BerCodec.encode(new BerTlv(0, false, 19, 0, bytes.length, bytes));
        return BerCodec.encode(new BerTlv(1, true, tagNumber, 0, printable.length, printable));
    }

    private static byte[] concat(byte[]... chunks) {
        int totalLength = 0;
        for (byte[] chunk : chunks) {
            totalLength += chunk.length;
        }
        byte[] merged = new byte[totalLength];
        int offset = 0;
        for (byte[] chunk : chunks) {
            System.arraycopy(chunk, 0, merged, offset, chunk.length);
            offset += chunk.length;
        }
        return merged;
    }

    private static final class RecordingSessionService extends P3GatewaySessionService {

        private final List<String> commands = new ArrayList<>();

        private RecordingSessionService() {
            super(null, null, null, null, null, null, 1000, 100, true, null, "changeit", "RFC1006", "127.0.0.1:102", "AMHS-P3-GATEWAY");
        }

        @Override
        public String handleCommand(SessionState state, String rawCommand) {
            commands.add(rawCommand);
            if (rawCommand.startsWith("BIND ")) {
                return "OK code=bind-accepted sender=/C=IT/ADMD=ICAO/PRMD=ENAV/O=ORG/OU1=LIMCZZZX/CN=LIMCZZZX";
            }
            if (rawCommand.startsWith("SUBMIT ")) {
                return "OK code=submitted submission-id=icao-p3-sub-1 message-id=42";
            }
            return super.handleCommand(state, rawCommand);
        }
    }
}
