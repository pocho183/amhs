# Option B - Add a dedicated P3 access gateway in front of the existing AMHS P1 core

## Goal

Support **ISODE P3 clients** while preserving the existing **ICAO AMHS P1/RFC1006** behavior already implemented by this server.

## Current baseline in this repository

- Transport listener is RFC1006 (`rfc1006.server.port`) with optional TLS settings.
- Association handling is P1/ACSE first, then transfer PDU.
- Raw BER payloads without successful P1 association are rejected.

This means a direct `P3BindSession` to this listener is expected to fail.

## Target architecture

Introduce a new `P3GatewayService` boundary that:

1. Terminates P3 bind/submit/release on a dedicated endpoint.
2. Maps P3 attributes into internal AMHS canonical fields.
3. Persists/queues message through existing core services (`MTAService`).
4. Optionally generates delivery/report correlation state for P3 clients.

```
ISODE UA (P3) -> P3 Gateway -> Internal AMHS model -> Existing MTAService/P1 pipeline
```

## Phase plan

### Phase 1 - Minimal interoperability

- Add a P3 gateway endpoint (dedicated port/service process).
- Implement operations:
  - Bind (credential and addressing validation).
  - Submit (single-recipient initially).
  - Unbind.
- Map to existing `X400MessageService.storeFromP3(...)` pathway.
- Return deterministic submission-id to client.

### Phase 2 - ICAO alignment hardening

- Validate O/R addresses against expected ICAO profile constraints.
- Enforce authenticated identity ↔ caller address binding.
- Add channel policy/routing checks.
- Add audit logs for bind/submit/release and diagnostic reasons.

### Phase 3 - Delivery/report parity

- Keep submission correlation table (`submission-id` -> internal message-id).
- Surface DR/IPN status to P3 retrieval/report operation.
- Add retry/timeout semantics equivalent to client expectations.

## Configuration model (recommended)

Add a dedicated section to avoid overloading RFC1006/P1 settings:

- `amhs.p3.gateway.enabled`
- `amhs.p3.gateway.host`
- `amhs.p3.gateway.port`
- `amhs.p3.gateway.tls.enabled`
- `amhs.p3.gateway.auth.required`
- `amhs.p3.gateway.max-sessions`

## Validation checklist

1. ISODE P3 client can bind/unbind successfully.
2. Submit from P3 is stored with `AMHSProfile.P3` and valid O/R mappings.
3. Existing P1 listener interoperability tests still pass unchanged.
4. Negative cases return explicit protocol diagnostics (auth failure, invalid OR, unsupported operation).

## Operational recommendation

Run P3 gateway and P1 RFC1006 listener as separate interfaces (or ports) so profile-specific policy and telemetry remain clean and auditable.
