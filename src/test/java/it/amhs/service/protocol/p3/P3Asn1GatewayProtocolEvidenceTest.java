package it.amhs.service.protocol.p3;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.jupiter.api.Test;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import it.amhs.asn1.BerCodec;
import it.amhs.asn1.BerTlv;

class P3Asn1GatewayProtocolEvidenceTest {

    @Test
    void emitsDeterministicPacketAndLogEvidenceForSuccessAndFailurePaths() {
        StubSessionService sessionService = new StubSessionService();
        P3Asn1GatewayProtocol protocol = new P3Asn1GatewayProtocol(sessionService);
        P3GatewaySessionService.SessionState session = sessionService.newSession();

        Logger logger = (Logger) org.slf4j.LoggerFactory.getLogger(P3Asn1GatewayProtocol.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        logger.setLevel(Level.INFO);

        byte[] bindRequest = bindRequest("amhsuser", "changeit", "/C=IT/ADMD=ICAO/PRMD=ENAV/O=ENAV/OU1=LIRR/CN=alice", "ATFM");
        byte[] bindResponse = protocol.handle(session, bindRequest);

        byte[] invalidApdu = BerCodec.encode(new BerTlv(2, false, P3Asn1GatewayProtocol.APDU_BIND_REQUEST, 0, 0, new byte[0]));
        byte[] errorResponse = protocol.handle(sessionService.newSession(), invalidApdu);

        logger.detachAppender(appender);

        assertEquals("a04f800c616d687375736572810a6368616e6765697482322f433d49542f41444d443d4943414f2f50524d443d454e41562f4f3d454e41562f4f55313d4c4952522f434e3d616c69636583064154464d", toHex(bindRequest));
        assertTrue(toHex(bindResponse).startsWith("a1"));

        BerTlv error = BerCodec.decodeSingle(errorResponse);
        assertEquals(P3Asn1GatewayProtocol.APDU_ERROR, error.tagNumber());
        assertEquals("a000", toHex(invalidApdu));
        assertTrue(toHex(errorResponse).startsWith("a8"));

        List<String> logLines = appender.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
        assertTrue(logLines.stream().anyMatch(line -> line.contains("incoming APDU") && line.contains("tagNumber=0")));
        assertTrue(logLines.stream().anyMatch(line -> line.contains("bind request fields username=amhsuser")));
        assertTrue(logLines.stream().anyMatch(line -> line.contains("bind gateway-response=OK")));
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

    private static byte[] utf8Context(int tagNumber, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        byte[] utf8 = BerCodec.encode(new BerTlv(0, false, 12, 0, bytes.length, bytes));
        return BerCodec.encode(new BerTlv(2, true, tagNumber, 0, utf8.length, utf8));
    }

    private static byte[] concat(byte[]... chunks) {
        int total = 0;
        for (byte[] chunk : chunks) {
            total += chunk.length;
        }
        byte[] merged = new byte[total];
        int offset = 0;
        for (byte[] chunk : chunks) {
            System.arraycopy(chunk, 0, merged, offset, chunk.length);
            offset += chunk.length;
        }
        return merged;
    }

    private static String toHex(byte[] data) {
        StringBuilder hex = new StringBuilder(data.length * 2);
        for (byte b : data) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }
}
