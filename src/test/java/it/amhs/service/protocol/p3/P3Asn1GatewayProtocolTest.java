package it.amhs.service.protocol.p3;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import it.amhs.asn1.BerCodec;
import it.amhs.asn1.BerTlv;

class P3Asn1GatewayProtocolTest {

    @Test
    void mapsBindAndSubmitAndStatusAndReadToSessionService() {
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

        byte[] reportResponse = protocol.handle(session, reportRequest("/C=IT/ADMD=ICAO/PRMD=ENAV/O=ENAV/OU1=LIRR/CN=alice", 1000, 200));
        BerTlv report = BerCodec.decodeSingle(reportResponse);
        assertEquals(P3Asn1GatewayProtocol.APDU_REPORT_RESPONSE, report.tagNumber());

        byte[] readResponse = protocol.handle(session, readRequest("/C=IT/ADMD=ICAO/PRMD=ENAV/O=ENAV/OU1=LIRR/CN=alice", 1000, 200));
        BerTlv read = BerCodec.decodeSingle(readResponse);
        assertEquals(P3Asn1GatewayProtocol.APDU_READ_RESPONSE, read.tagNumber());
    }


    @Test
    void mapsBindWhenPayloadIsWrappedInUniversalSequence() {
        StubSessionService sessionService = new StubSessionService();
        P3Asn1GatewayProtocol protocol = new P3Asn1GatewayProtocol(sessionService);
        P3GatewaySessionService.SessionState session = sessionService.newSession();

        byte[] bindPayload = bindPayload("amhsuser", "changeit", "C=IT;ADMD=ICAO;PRMD=ENAV;CN=MARIO.CORINI", "ATFM");
        byte[] sequenceWrappedPayload = BerCodec.encode(new BerTlv(0, true, 16, 0, bindPayload.length, bindPayload));
        byte[] bindRequest = BerCodec.encode(new BerTlv(2, true, P3Asn1GatewayProtocol.APDU_BIND_REQUEST, 0, sequenceWrappedPayload.length, sequenceWrappedPayload));

        byte[] response = protocol.handle(session, bindRequest);

        BerTlv responseTlv = BerCodec.decodeSingle(response);
        assertEquals(P3Asn1GatewayProtocol.APDU_BIND_RESPONSE, responseTlv.tagNumber());
    }

    @Test
    void unwrapsRtseRtorqAndReturnsRtoacWithGatewayPayload() {
        StubSessionService sessionService = new StubSessionService();
        P3Asn1GatewayProtocol protocol = new P3Asn1GatewayProtocol(sessionService);
        P3GatewaySessionService.SessionState session = sessionService.newSession();

        byte[] bind = bindRequest("amhsuser", "changeit", "/C=IT/ADMD=ICAO/PRMD=ENAV/O=ENAV/OU1=LIRR/CN=alice", "ATFM");
        byte[] rtorq = rtseEnvelope(16, bind);

        byte[] response = protocol.handle(session, rtorq);
        BerTlv rtse = BerCodec.decodeSingle(response);
        assertEquals(1, rtse.tagClass());
        assertEquals(17, rtse.tagNumber());

        BerTlv any = BerCodec.decodeSingle(rtse.value());
        BerTlv bindResponse = BerCodec.decodeSingle(any.value());
        assertEquals(P3Asn1GatewayProtocol.APDU_BIND_RESPONSE, bindResponse.tagNumber());
    }

    @Test
    void unwrapsRtseRttdAndReturnsRttrWithRosePayload() {
        StubSessionService sessionService = new StubSessionService();
        P3Asn1GatewayProtocol protocol = new P3Asn1GatewayProtocol(sessionService);
        P3GatewaySessionService.SessionState session = sessionService.newSession();

        byte[] roseBind = roseInvoke(
            9,
            P3Asn1GatewayProtocol.APDU_BIND_REQUEST,
            bindPayload("amhsuser", "changeit", "/C=IT/ADMD=ICAO/PRMD=ENAV/O=ENAV/OU1=LIRR/CN=alice", "ATFM")
        );
        byte[] rttd = rtseEnvelope(22, roseBind);

        byte[] response = protocol.handle(session, rttd);
        BerTlv rtse = BerCodec.decodeSingle(response);
        assertEquals(1, rtse.tagClass());
        assertEquals(21, rtse.tagNumber());

        BerTlv any = BerCodec.decodeSingle(rtse.value());
        BerTlv roseResponse = BerCodec.decodeSingle(any.value());
        assertEquals(1, roseResponse.tagClass());
        assertEquals(2, roseResponse.tagNumber());
    }

    @Test
    void mapsRtabToReleaseResponse() {
        StubSessionService sessionService = new StubSessionService();
        P3Asn1GatewayProtocol protocol = new P3Asn1GatewayProtocol(sessionService);
        P3GatewaySessionService.SessionState session = sessionService.newSession();

        byte[] response = protocol.handle(session, rtseEnvelope(19, new byte[0]));
        BerTlv rtse = BerCodec.decodeSingle(response);
        assertEquals(1, rtse.tagClass());
        assertEquals(19, rtse.tagNumber());

        BerTlv any = BerCodec.decodeSingle(rtse.value());
        BerTlv releaseResponse = BerCodec.decodeSingle(any.value());
        assertEquals(P3Asn1GatewayProtocol.APDU_RELEASE_RESPONSE, releaseResponse.tagNumber());
    }

    @Test
    void unsupportedRtseTagReturnsRtorj() {
        StubSessionService sessionService = new StubSessionService();
        P3Asn1GatewayProtocol protocol = new P3Asn1GatewayProtocol(sessionService);

        byte[] response = protocol.handle(sessionService.newSession(), rtseEnvelope(20, new byte[0]));
        BerTlv rtse = BerCodec.decodeSingle(response);
        assertEquals(1, rtse.tagClass());
        assertEquals(18, rtse.tagNumber());
    }

    @Test
    void rtseGatewayMatcherRejectsUnrelatedConstructedContextPayload() {
        StubSessionService sessionService = new StubSessionService();
        P3Asn1GatewayProtocol protocol = new P3Asn1GatewayProtocol(sessionService);

        byte[] unrelatedField = BerCodec.encode(new BerTlv(2, true, 9, 0, utf8Primitive("x").length, utf8Primitive("x")));
        byte[] fakeGatewayBind = BerCodec.encode(new BerTlv(2, true, P3Asn1GatewayProtocol.APDU_BIND_REQUEST, 0, unrelatedField.length, unrelatedField));

        byte[] response = protocol.handle(sessionService.newSession(), rtseEnvelope(16, fakeGatewayBind));

        BerTlv rtse = BerCodec.decodeSingle(response);
        assertEquals(1, rtse.tagClass());
        assertEquals(17, rtse.tagNumber());

        BerTlv any = BerCodec.decodeSingle(rtse.value());
        BerTlv gatewayError = BerCodec.decodeSingle(any.value());
        assertEquals(P3Asn1GatewayProtocol.APDU_ERROR, gatewayError.tagNumber());
        assertEquals("unsupported-operation", decodeErrorField(gatewayError, 0));
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

    @Test
    void mapsRoseInvokeToReturnResult() {
        StubSessionService sessionService = new StubSessionService();
        P3Asn1GatewayProtocol protocol = new P3Asn1GatewayProtocol(sessionService);
        P3GatewaySessionService.SessionState session = sessionService.newSession();

        byte[] roseInvoke = roseInvoke(7, P3Asn1GatewayProtocol.APDU_BIND_REQUEST, bindPayload("amhsuser", "changeit", "/C=IT/ADMD=ICAO/PRMD=ENAV/O=ENAV/OU1=LIRR/CN=alice", "ATFM"));
        byte[] response = protocol.handle(session, roseInvoke);

        BerTlv responseTlv = BerCodec.decodeSingle(response);
        assertEquals(1, responseTlv.tagClass());
        assertEquals(2, responseTlv.tagNumber());

        BerTlv sequence = BerCodec.decodeSingle(responseTlv.value());
        assertEquals(16, sequence.tagNumber());
        var fields = BerCodec.decodeAll(sequence.value());
        assertEquals(2, fields.size());
        assertEquals(2, fields.get(0).tagNumber());
        assertEquals(7, fields.get(0).value()[0] & 0xFF);
        assertEquals(P3Asn1GatewayProtocol.APDU_BIND_RESPONSE, fields.get(1).tagNumber());
    }

    @Test
    void releaseReturnsGatewayErrorWhenAssociationIsNotBound() {
        StubSessionService sessionService = new StubSessionService() {
            @Override
            public String handleCommand(SessionState state, String rawCommand) {
                String op = rawCommand.split("\\s+", 2)[0].toUpperCase();
                if ("UNBIND".equals(op)) {
                    return "ERR code=association detail=Release received before bind";
                }
                return super.handleCommand(state, rawCommand);
            }
        };
        P3Asn1GatewayProtocol protocol = new P3Asn1GatewayProtocol(sessionService);

        byte[] release = BerCodec.encode(new BerTlv(2, true, P3Asn1GatewayProtocol.APDU_RELEASE_REQUEST, 0, 0, new byte[0]));
        byte[] response = protocol.handle(sessionService.newSession(), release);

        BerTlv responseTlv = BerCodec.decodeSingle(response);
        assertEquals(P3Asn1GatewayProtocol.APDU_ERROR, responseTlv.tagNumber());
    }

    @Test
    void roseReleaseReturnsReturnErrorWhenAssociationIsNotBound() {
        StubSessionService sessionService = new StubSessionService() {
            @Override
            public String handleCommand(SessionState state, String rawCommand) {
                String op = rawCommand.split("\\s+", 2)[0].toUpperCase();
                if ("UNBIND".equals(op)) {
                    return "ERR code=association detail=Release received before bind";
                }
                return super.handleCommand(state, rawCommand);
            }
        };
        P3Asn1GatewayProtocol protocol = new P3Asn1GatewayProtocol(sessionService);

        byte[] roseRelease = roseInvoke(11, P3Asn1GatewayProtocol.APDU_RELEASE_REQUEST, new byte[0]);
        byte[] response = protocol.handle(sessionService.newSession(), roseRelease);

        BerTlv responseTlv = BerCodec.decodeSingle(response);
        assertEquals(1, responseTlv.tagClass());
        assertEquals(3, responseTlv.tagNumber());
    }

    @Test
    void returnsRoseRejectForUnexpectedRoseReturnResultApdu() {
        StubSessionService sessionService = new StubSessionService();
        P3Asn1GatewayProtocol protocol = new P3Asn1GatewayProtocol(sessionService);

        byte[] unexpectedReturnResult = BerCodec.encode(new BerTlv(1, true, 2, 0, 0, new byte[0]));
        byte[] response = protocol.handle(sessionService.newSession(), unexpectedReturnResult);

        BerTlv responseTlv = BerCodec.decodeSingle(response);
        assertEquals(1, responseTlv.tagClass());
        assertEquals(4, responseTlv.tagNumber());
    }

    @Test
    void returnsRoseReturnErrorForResponseOperationCodeUsedAsInvoke() {
        StubSessionService sessionService = new StubSessionService();
        P3Asn1GatewayProtocol protocol = new P3Asn1GatewayProtocol(sessionService);

        byte[] roseInvoke = roseInvoke(6, P3Asn1GatewayProtocol.APDU_BIND_RESPONSE, new byte[0]);
        byte[] response = protocol.handle(sessionService.newSession(), roseInvoke);

        BerTlv responseTlv = BerCodec.decodeSingle(response);
        assertEquals(1, responseTlv.tagClass());
        assertEquals(3, responseTlv.tagNumber());

        BerTlv errorPayload = decodeRoseReturnErrorPayload(responseTlv);
        assertEquals(P3Asn1GatewayProtocol.APDU_ERROR, errorPayload.tagNumber());
        assertEquals("invalid-operation-role", decodeErrorField(errorPayload, 0));
    }


    @Test
    void infersBindFieldsFromNonGatewayAsn1Payload() {
        class CapturingSessionService extends StubSessionService {
            String lastCommand;

            @Override
            public String handleCommand(SessionState state, String rawCommand) {
                this.lastCommand = rawCommand;
                if (rawCommand.startsWith("BIND ")) {
                    return "OK code=bind-accepted sender=/C=IT/ADMD=ICAO/PRMD=ENAV/O=ENAV/OU1=LIRR/CN=alice";
                }
                return super.handleCommand(state, rawCommand);
            }
        }

        CapturingSessionService sessionService = new CapturingSessionService();
        P3Asn1GatewayProtocol protocol = new P3Asn1GatewayProtocol(sessionService);
        P3GatewaySessionService.SessionState session = sessionService.newSession();

        byte[] bindArgument = BerCodec.encode(new BerTlv(
            0,
            true,
            16,
            0,
            concat(
                utf8Primitive("amhsuser"),
                utf8Primitive("changeit"),
                utf8Primitive("/C=IT/ADMD=ICAO/PRMD=ENAV/O=ENAV/OU1=LIRR/CN=alice"),
                utf8Primitive("ATFM")
            ).length,
            concat(
                utf8Primitive("amhsuser"),
                utf8Primitive("changeit"),
                utf8Primitive("/C=IT/ADMD=ICAO/PRMD=ENAV/O=ENAV/OU1=LIRR/CN=alice"),
                utf8Primitive("ATFM")
            )
        ));

        byte[] bindRequest = BerCodec.encode(new BerTlv(2, true, P3Asn1GatewayProtocol.APDU_BIND_REQUEST, 0, bindArgument.length, bindArgument));
        byte[] response = protocol.handle(session, bindRequest);

        BerTlv responseTlv = BerCodec.decodeSingle(response);
        assertEquals(P3Asn1GatewayProtocol.APDU_BIND_RESPONSE, responseTlv.tagNumber());
        assertEquals(
            "BIND username=amhsuser;password=changeit;sender=/C=IT/ADMD=ICAO/PRMD=ENAV/O=ENAV/OU1=LIRR/CN=alice;channel=ATFM",
            sessionService.lastCommand
        );
    }

    @Test
    void decodesBindSenderFromNestedStructuredOrAddressField() {
        class CapturingSessionService extends StubSessionService {
            String lastCommand;

            @Override
            public String handleCommand(SessionState state, String rawCommand) {
                this.lastCommand = rawCommand;
                return super.handleCommand(state, rawCommand);
            }
        }

        CapturingSessionService sessionService = new CapturingSessionService();
        P3Asn1GatewayProtocol protocol = new P3Asn1GatewayProtocol(sessionService);
        P3GatewaySessionService.SessionState session = sessionService.newSession();

        byte[] senderSequence = BerCodec.encode(new BerTlv(
            0,
            true,
            16,
            0,
            concat(
                utf8Primitive("/C=IT"),
                utf8Primitive("ADMD=ICAO"),
                utf8Primitive("PRMD=ENAV"),
                utf8Primitive("O=ENAV"),
                utf8Primitive("OU1=LIRR"),
                utf8Primitive("CN=alice")
            ).length,
            concat(
                utf8Primitive("/C=IT"),
                utf8Primitive("ADMD=ICAO"),
                utf8Primitive("PRMD=ENAV"),
                utf8Primitive("O=ENAV"),
                utf8Primitive("OU1=LIRR"),
                utf8Primitive("CN=alice")
            )
        ));

        byte[] payload = concat(
            utf8Context(0, "amhsuser"),
            utf8Context(1, "changeit"),
            BerCodec.encode(new BerTlv(2, true, 2, 0, senderSequence.length, senderSequence)),
            utf8Context(3, "ATFM")
        );

        byte[] bindRequest = BerCodec.encode(new BerTlv(2, true, P3Asn1GatewayProtocol.APDU_BIND_REQUEST, 0, payload.length, payload));
        byte[] response = protocol.handle(session, bindRequest);

        BerTlv responseTlv = BerCodec.decodeSingle(response);
        assertEquals(P3Asn1GatewayProtocol.APDU_BIND_RESPONSE, responseTlv.tagNumber());
        assertEquals(
            "BIND username=amhsuser;password=changeit;sender=/C=IT/ADMD=ICAO/PRMD=ENAV/O=ENAV/OU1=LIRR/CN=alice;channel=ATFM",
            sessionService.lastCommand
        );
    }



    @Test
    void infersBindSenderFromDnStyleAddressAtom() {
        class CapturingSessionService extends StubSessionService {
            String lastCommand;

            @Override
            public String handleCommand(SessionState state, String rawCommand) {
                this.lastCommand = rawCommand;
                if (rawCommand.startsWith("BIND ")) {
                    return "OK code=bind-accepted sender=/C=IT/ADMD=ICAO/PRMD=ENAV/O=ENAV/OU1=LIRR/CN=alice";
                }
                return super.handleCommand(state, rawCommand);
            }
        }

        CapturingSessionService sessionService = new CapturingSessionService();
        P3Asn1GatewayProtocol protocol = new P3Asn1GatewayProtocol(sessionService);
        P3GatewaySessionService.SessionState session = sessionService.newSession();

        byte[] bindArgument = BerCodec.encode(new BerTlv(
            0,
            true,
            16,
            0,
            concat(
                utf8Primitive("amhsuser"),
                utf8Primitive("changeit"),
                utf8Primitive("CN=alice,OU1=LIRR,O=ENAV,PRMD=ENAV,ADMD=ICAO,C=IT"),
                utf8Primitive("ATFM")
            ).length,
            concat(
                utf8Primitive("amhsuser"),
                utf8Primitive("changeit"),
                utf8Primitive("CN=alice,OU1=LIRR,O=ENAV,PRMD=ENAV,ADMD=ICAO,C=IT"),
                utf8Primitive("ATFM")
            )
        ));

        byte[] bindRequest = BerCodec.encode(new BerTlv(2, true, P3Asn1GatewayProtocol.APDU_BIND_REQUEST, 0, bindArgument.length, bindArgument));
        byte[] response = protocol.handle(session, bindRequest);

        BerTlv responseTlv = BerCodec.decodeSingle(response);
        assertEquals(P3Asn1GatewayProtocol.APDU_BIND_RESPONSE, responseTlv.tagNumber());
        assertEquals(
            "BIND username=amhsuser;password=changeit;sender=/C=IT/ADMD=ICAO/PRMD=ENAV/O=ENAV/OU1=LIRR/CN=alice;channel=ATFM",
            sessionService.lastCommand
        );
    }

    @Test
    void doesNotChooseLongestAmbiguousConstructedFieldValue() {
        class CapturingSessionService extends StubSessionService {
            String lastCommand;

            @Override
            public String handleCommand(SessionState state, String rawCommand) {
                this.lastCommand = rawCommand;
                return super.handleCommand(state, rawCommand);
            }
        }

        CapturingSessionService sessionService = new CapturingSessionService();
        P3Asn1GatewayProtocol protocol = new P3Asn1GatewayProtocol(sessionService);
        P3GatewaySessionService.SessionState session = sessionService.newSession();

        byte[] ambiguousRecipient = BerCodec.encode(new BerTlv(
            2,
            true,
            0,
            0,
            concat(
                utf8Primitive("IGNORE-ME"),
                utf8Primitive("THIS-IS-A-LONG-UNRELATED-STRING")
            ).length,
            concat(
                utf8Primitive("IGNORE-ME"),
                utf8Primitive("THIS-IS-A-LONG-UNRELATED-STRING")
            )
        ));

        byte[] payload = concat(
            ambiguousRecipient,
            utf8Context(1, "subject"),
            utf8Context(2, "body")
        );
        byte[] submitRequest = BerCodec.encode(new BerTlv(2, true, P3Asn1GatewayProtocol.APDU_SUBMIT_REQUEST, 0, payload.length, payload));

        byte[] response = protocol.handle(session, submitRequest);

        BerTlv responseTlv = BerCodec.decodeSingle(response);
        assertEquals(P3Asn1GatewayProtocol.APDU_SUBMIT_RESPONSE, responseTlv.tagNumber());
        assertEquals("SUBMIT recipient=;subject=subject;body=body", sessionService.lastCommand);
    }

    @Test
    void returnsRoseReturnErrorForUnsupportedRoseOperation() {
        StubSessionService sessionService = new StubSessionService();
        P3Asn1GatewayProtocol protocol = new P3Asn1GatewayProtocol(sessionService);
        P3GatewaySessionService.SessionState session = sessionService.newSession();

        byte[] roseInvoke = roseInvoke(5, 99, utf8Context(0, "noop"));
        byte[] response = protocol.handle(session, roseInvoke);

        BerTlv responseTlv = BerCodec.decodeSingle(response);
        assertEquals(1, responseTlv.tagClass());
        assertEquals(3, responseTlv.tagNumber());
    }

    @Test
    void doesNotInferAmbiguousChannelNameFromNonGatewayAsn1Payload() {
        class CapturingSessionService extends StubSessionService {
            String lastCommand;

            @Override
            public String handleCommand(SessionState state, String rawCommand) {
                this.lastCommand = rawCommand;
                if (rawCommand.startsWith("BIND ")) {
                    return "OK code=bind-accepted sender=/C=IT/ADMD=ICAO/PRMD=ENAV/O=ENAV/OU1=LIRR/CN=alice";
                }
                return super.handleCommand(state, rawCommand);
            }
        }

        CapturingSessionService sessionService = new CapturingSessionService();
        P3Asn1GatewayProtocol protocol = new P3Asn1GatewayProtocol(sessionService);
        P3GatewaySessionService.SessionState session = sessionService.newSession();

        byte[] bindArgument = BerCodec.encode(new BerTlv(
            0,
            true,
            16,
            0,
            concat(
                utf8Primitive("amhsuser"),
                utf8Primitive("changeit"),
                utf8Primitive("/C=IT/ADMD=ICAO/PRMD=ENAV/O=ENAV/OU1=LIRR/CN=alice"),
                utf8Primitive("HELLO"),
                utf8Primitive("WORLD")
            ).length,
            concat(
                utf8Primitive("amhsuser"),
                utf8Primitive("changeit"),
                utf8Primitive("/C=IT/ADMD=ICAO/PRMD=ENAV/O=ENAV/OU1=LIRR/CN=alice"),
                utf8Primitive("HELLO"),
                utf8Primitive("WORLD")
            )
        ));

        byte[] bindRequest = BerCodec.encode(new BerTlv(2, true, P3Asn1GatewayProtocol.APDU_BIND_REQUEST, 0, bindArgument.length, bindArgument));
        byte[] response = protocol.handle(session, bindRequest);

        BerTlv responseTlv = BerCodec.decodeSingle(response);
        assertEquals(P3Asn1GatewayProtocol.APDU_BIND_RESPONSE, responseTlv.tagNumber());
        assertTrue(sessionService.lastCommand.contains(";channel="));
        assertTrue(sessionService.lastCommand.endsWith(";channel="));
    }

    @Test
    void returnsExplicitErrorWhenBindPayloadHasNoGatewayFieldsOrDecodableOrName() {
        StubSessionService sessionService = new StubSessionService();
        P3Asn1GatewayProtocol protocol = new P3Asn1GatewayProtocol(sessionService);

        byte[] opaque = BerCodec.encode(new BerTlv(0, false, 4, 0, 4, new byte[] { 0x00, (byte) 0xFF, 0x01, 0x02 }));
        byte[] bindRequest = BerCodec.encode(new BerTlv(2, true, P3Asn1GatewayProtocol.APDU_BIND_REQUEST, 0, opaque.length, opaque));
        byte[] response = protocol.handle(sessionService.newSession(), bindRequest);

        BerTlv responseTlv = BerCodec.decodeSingle(response);
        assertEquals(P3Asn1GatewayProtocol.APDU_ERROR, responseTlv.tagNumber());
        assertEquals("unsupported-native-p3-bind", decodeErrorField(responseTlv, 0));
    }

    private static BerTlv decodeRoseReturnErrorPayload(BerTlv roseReturnError) {
        var fields = BerCodec.decodeAll(roseReturnError.value());
        return fields.get(2);
    }

    private static String decodeErrorField(BerTlv errorApdu, int tagNumber) {
        for (BerTlv field : BerCodec.decodeAll(errorApdu.value())) {
            if (field.tagClass() == 2 && field.tagNumber() == tagNumber) {
                BerTlv value = BerCodec.decodeSingle(field.value());
                return new String(value.value(), StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    private static byte[] rtseEnvelope(int tagNumber, byte[] payload) {
        byte[] any = BerCodec.encode(new BerTlv(2, true, 0, 0, payload.length, payload));
        return BerCodec.encode(new BerTlv(1, true, tagNumber, 0, any.length, any));
    }

    private static byte[] roseInvoke(int invokeId, int operationCode, byte[] argumentApdu) {
        byte[] sequence = BerCodec.encode(new BerTlv(
            0,
            true,
            16,
            0,
            concat(
                new BerTlv(0, false, 2, 0, 1, new byte[] { (byte) invokeId }),
                new BerTlv(0, false, 2, 0, 1, new byte[] { (byte) operationCode }),
                new BerTlv(2, true, 2, 0, argumentApdu.length, argumentApdu)
            ).length,
            concat(
                new BerTlv(0, false, 2, 0, 1, new byte[] { (byte) invokeId }),
                new BerTlv(0, false, 2, 0, 1, new byte[] { (byte) operationCode }),
                new BerTlv(2, true, 2, 0, argumentApdu.length, argumentApdu)
            )
        ));
        return BerCodec.encode(new BerTlv(1, true, 1, 0, sequence.length, sequence));
    }

    private static byte[] bindPayload(String username, String password, String sender, String channel) {
        return concat(
            utf8Context(0, username),
            utf8Context(1, password),
            utf8Context(2, sender),
            utf8Context(3, channel)
        );
    }

    private static byte[] concat(BerTlv... tlvs) {
        byte[][] encoded = new byte[tlvs.length][];
        for (int i = 0; i < tlvs.length; i++) {
            encoded[i] = BerCodec.encode(tlvs[i]);
        }
        return concat(encoded);
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

    private static byte[] reportRequest(String recipient, int waitMs, int retryMs) {
        byte[] payload = concat(
            utf8Context(0, recipient),
            integerContext(1, waitMs),
            integerContext(2, retryMs)
        );
        return BerCodec.encode(new BerTlv(2, true, P3Asn1GatewayProtocol.APDU_REPORT_REQUEST, 0, payload.length, payload));
    }

    private static byte[] readRequest(String recipient, int waitMs, int retryMs) {
        byte[] payload = concat(
            utf8Context(0, recipient),
            integerContext(1, waitMs),
            integerContext(2, retryMs)
        );
        return BerCodec.encode(new BerTlv(2, true, P3Asn1GatewayProtocol.APDU_READ_REQUEST, 0, payload.length, payload));
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

    private static BerTlv utf8Primitive(String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        return new BerTlv(0, false, 12, 0, bytes.length, bytes);
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

}
