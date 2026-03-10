# ISODE P3 client interoperability guide

This document explains how to run this AMHS server when your sender/reader code uses ISODE classes such as `P3BindSession`, `X400Msg.sendMsg(...)`, and `readMsg(...)`.

## 1) Important scope note

The P3 listener can be run in two profiles.

- `STANDARD_P3` (default): accepts only RFC1006/TPKT traffic for a standards-aligned external P3 exposure.
- `GATEWAY_MULTI_PROTOCOL`: legacy gateway mode that accepts raw BER APDUs and RFC1006/TPKT on the same endpoint (no line text command console).

The gateway semantics are aligned to the declared gateway P3 profile and now include profile-complete external RTSE/ROSE wrapping semantics and operation/error mapping coverage for bind/submit/status/report/read/release.

- Supported operations depend on profile:
  - `STANDARD_P3`: RFC1006 COTP DT payloads carrying OSI Session/Presentation/ACSE envelopes when those envelopes contain gateway BER APDUs
  - `GATEWAY_MULTI_PROTOCOL`: allows raw BER APDUs in addition to RFC1006/TPKT
- The gateway accepts ROSE `Invoke` wrappers for bind/submit/status/release and returns ROSE `returnResult`/`returnError` mapped to gateway APDU outcomes.
- The RTSE layer now enforces deterministic wrapper semantics for the supported transfer controls (`RTORQ`/`RTOAC`, `RTTD`/`RTTR`, `RTAB`, and explicit `RTORJ` handling for unsupported RTSE tags).
- Formal association handling is enforced for bind/release:
  - bind is allowed only once per association
  - release before bind is rejected
  - post-release operations are rejected with an explicit association-closed diagnostic

## 2) Runtime topology

Use separate endpoints:

- `rfc1006.server.port` (default 102): P1/RFC1006 listener
- `amhs.p3.gateway.port` (default 102): P3 gateway listener (RFC 1006 reserved TCP port)

There is no automatic redirection from `:102` to the P3 gateway.

## 3) Minimal startup configuration

Set at least:

```properties
amhs.p3.gateway.enabled=true
amhs.p3.gateway.host=0.0.0.0
amhs.p3.gateway.port=102
amhs.p3.gateway.tls.enabled=false
amhs.p3.gateway.listener-profile=STANDARD_P3
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
./gradlew bootRun --args='--rfc1006.server.port=1102 --amhs.p3.gateway.enabled=true --amhs.p3.gateway.port=1103'
```

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
  - `protocol=ber-apdu` or
  - `protocol=rfc1006-tpkt`
- Repeated immediate reconnects with logs like `protocol=ber-apdu` and no successful bind usually indicate protocol/profile mismatch (for example, sending RFC1006/P1 traffic to the P3 gateway port).

If your ISODE client connects but fails during bind/read semantics, this typically indicates expectation mismatch vs full native P3 behavior.
