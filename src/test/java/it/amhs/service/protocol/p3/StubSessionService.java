package it.amhs.service.protocol.p3;

class StubSessionService extends P3GatewaySessionService {

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
            case "REPORT" -> "OK code=read report-id=7 message-id=sub-1 recipient=/C=IT/ADMD=ICAO/PRMD=ENAV/O=ENAV/OU1=LIRR/CN=alice report-type=DR dr-status=DELIVERED";
            case "UNBIND" -> {
                yield "OK code=release";
            }
            default -> "ERR code=unsupported-operation detail=Unsupported";
        };
    }
}
