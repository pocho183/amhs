# ISODE P3 client interoperability guide

This document explains how to run this AMHS server when your sender/reader code uses ISODE classes such as `P3BindSession`, `X400Msg.sendMsg(...)`, and `readMsg(...)`.

## 1) Important scope note

The P3 listener in this repository is a **gateway profile**, not a complete ICAO-certified end-to-end X.411/P3 stack.

- Supported on the P3 port:
  - legacy text commands (`BIND`, `SUBMIT`, `STATUS`, `READ`, `UNBIND`)
  - BER APDU gateway profile (`bind/submit/status/read/release` APDUs)
- Current compatibility level:
  - includes mailbox-style `READ` for delivery reports with timeout polling.
  - still not a complete ICAO-certified X.411/P3 implementation (extended operations and strict interoperability profiles may require extra work).

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


## 3.1) Mapping ISODE presentation address to AMHS gateway endpoint

Your ISODE constructor `new P3BindSession(m_strP3_channel_presentation_address, ...)` must resolve to the AMHS P3 TCP endpoint:

- host: AMHS server hostname/IP
- port: `amhs.p3.gateway.port` (default `1988`)

Practical check:

1. Print/log the exact runtime value of `m_strP3_channel_presentation_address`.
2. Confirm that value reaches `your-amhs-host:1988` in your ISODE stack/network trace.
3. Keep RFC1006/P1 (`:102` or configured) separate; no auto-forwarding to P3 gateway.

## 4) How DR works in this gateway

For P3 gateway flows, DR can be consumed in two ways:

- `STATUS` with `submission-id` correlation
- `READ` mailbox-style polling for recipient reports

`READ` returns report metadata (`report-id`, `message-id`, `report-type`, `dr-status`, optional diagnostic) and supports timeout/retry polling parameters.

## 5) What to do with existing ISODE write/read code

Given code structured as:

- `P3BindSession.bind()`
- `X400Msg.sendMsg(...)`
- second session + `readMsg(...)` for DR

Recommended integration options:

1. **Current built-in mapping:**
   - bind -> gateway bind
   - sendMsg -> gateway submit
   - `readMsg` DR wait -> gateway `READ` (or `STATUS` by submission-id)

2. **For strict/native profile parity:**
   Extend server-side P3 implementation for any additional ISODE-specific operations/encodings required by your deployment profile.

## 6) Runtime verification checklist

After startup, verify logs include:

- P3 listener started (`AMHS P3 gateway ... listening`)
- Per connection protocol mode:
  - `protocol=text-command` or
  - `protocol=ber-apdu`

If your ISODE client connects but fails during bind/read semantics, this typically indicates expectation mismatch vs full native P3 behavior.
