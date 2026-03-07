# ISODE P3 client interoperability guide

This document explains how to run this AMHS server when your sender/reader code uses ISODE classes such as `P3BindSession`, `X400Msg.sendMsg(...)`, and `readMsg(...)`.

## 1) Important scope note

The P3 listener in this repository is a **gateway profile**, not a complete ICAO-certified end-to-end X.411/P3 stack.

- Supported on the P3 port:
  - legacy text commands (`BIND`, `SUBMIT`, `STATUS`, `UNBIND`)
  - BER APDU gateway profile (`bind/submit/status/release` APDUs)
  - RFC1006 COTP DT payloads carrying OSI Session/Presentation/ACSE envelopes when those envelopes contain gateway BER APDUs
- Not yet supported:
  - full native ISODE P3 mailbox/read protocol semantics as expected by `P3BindSession` + `ReceiveMsg/readMsg(...)`.

If your ISODE runtime expects full P3 wire compatibility, you need either:
1. a protocol adapter in front of this gateway, or
2. additional server implementation work for complete P3 operation set and semantics.

## 2) Runtime topology

Use separate endpoints:

- `rfc1006.server.port` (default 102): P1/RFC1006 listener
- `amhs.p3.gateway.port` (default 1988): P3 gateway listener

There is no automatic redirection from `:102` to the P3 gateway.

## 3) Minimal startup configuration

Set at least:

```properties
amhs.p3.gateway.enabled=true
amhs.p3.gateway.host=0.0.0.0
amhs.p3.gateway.port=1988
amhs.p3.gateway.tls.enabled=false
amhs.p3.gateway.text.welcome-enabled=false
amhs.p3.gateway.auth.required=true
amhs.p3.gateway.auth.username=amhsuser
amhs.p3.gateway.auth.password=changeit
```

Optional status tuning:

```properties
amhs.p3.gateway.status.wait-timeout-ms=10000
amhs.p3.gateway.status.retry-interval-ms=1000
```

Run with a non-privileged RFC1006 port if needed:

```bash
./gradlew bootRun --args='--rfc1006.server.port=1102 --amhs.p3.gateway.enabled=true --amhs.p3.gateway.port=1988'
```

### Note for line-oriented clients

- The gateway parses text commands line-by-line (`BIND`, `SUBMIT`, `STATUS`, `UNBIND`).
- Ensure each command is terminated with `\n` (or `\r\n`).
- By default the gateway does **not** send an initial welcome banner, so the first response read by the client corresponds to the first command sent.

## 4) How DR works in this gateway

For P3 gateway flows, DR status is exposed through `STATUS` using `submission-id` correlation.

- submit returns `submission-id`
- status polling returns fields such as:
  - `state`
  - `dr-status`
  - `ipn-status`

This is different from mailbox pull semantics used by many native ISODE `readMsg(...)` flows.

## 5) What to do with existing ISODE write/read code

Given code structured as:

- `P3BindSession.bind()`
- `X400Msg.sendMsg(...)`
- second session + `readMsg(...)` for DR

Recommended integration options:

1. **Short term (least invasive to server):**
   Use an adapter/gateway client translating ISODE operations to this server profile:
   - bind -> gateway bind
   - sendMsg -> gateway submit
   - readMsg DR wait -> gateway status polling

2. **Long term (native interop):**
   Extend server-side P3 implementation to full ISODE-compatible operation set.

## 6) Runtime verification checklist

After startup, verify logs include:

- P3 listener started (`AMHS P3 gateway ... listening`)
- Per connection protocol mode:
  - `protocol=text-command` or
  - `protocol=ber-apdu`
- Repeated immediate reconnects with logs like `protocol=ber-apdu` and no successful bind usually indicate protocol/profile mismatch (for example, sending RFC1006/P1 traffic to the P3 gateway port).

If your ISODE client connects but fails during bind/read semantics, this typically indicates expectation mismatch vs full native P3 behavior.
