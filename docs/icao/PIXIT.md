# AMHS PIXIT (Protocol Implementation eXtra Information for Testing)

Document status: **working baseline**.

This PIXIT captures implementation-specific parameters required by a conformance/interoperability lab when executing test campaigns.

## 1. Product under test

- Product: `amhs` server
- Runtime: Java / Spring Boot non-web process
- Main protocol entrypoint: RFC1006 (transport selectable: clear or TLS)

## 2. Network and transport PIXIT values

- RFC1006 listener port: configured by `rfc1006.server.port` (default `102`)
- TLS server authentication: controlled by `rfc1006.tls.enabled`
- TLS client authentication: controlled by `rfc1006.tls.need-client-auth` (when TLS is enabled)
- Maximum accepted AMHS body size: `100000` bytes (application-level validation)
- Transport controls implemented:
  - TPKT framing validation
  - COTP class 0 handshake (CR/CC)
  - TPDU size negotiation
  - Segmentation/reassembly
  - DR/ER handling

## 3. Association and ACSE PIXIT values

- Expected ACSE flow: AARQ request followed by AARE response
- Application context: checked against configured/expected OID policy
- AE-title handling: parsed and compared with local policy
- P3 listener profile option: `amhs.p3.gateway.listener-profile`
  - `STANDARD_P3`: accepts only RFC1006/TPKT ingress (default for ICAO-facing exposure)
  - `GATEWAY_MULTI_PROTOCOL`: accepts RFC1006/TPKT plus raw BER APDU ingress for interoperability labs
- Formal association semantics on gateway APDUs:
  - Exactly one successful bind is permitted per association
  - Re-bind on a bound association returns an explicit association diagnostic
  - Release before successful bind returns an explicit association diagnostic
  - After successful release, all further operations return `association-closed`
- Peer certificate identity binding:
  - Optional channel-level `expectedCn`
  - Optional channel-level `expectedOu`
  - Sender O/R address ICAO unit binding against peer certificate CN/OU

## 4. Addressing PIXIT values

Accepted sender/recipient formats:

1. ICAO 8-char shorthand (e.g. `LIRRAAAA`)
2. Structured O/R address containing at minimum:
   - `C`
   - `ADMD=ICAO`
   - `PRMD`
   - `O`
   - at least one OU level (`OU1`)

Validation constraints:

- Country `C` must be ISO alpha-2 or numeric 3-digit
- OU hierarchy must not skip levels (`OU2` cannot exist without `OU1`, etc.)
- At least one ICAO 8-char unit must appear in OU/O/CN fields

## 5. Routing and store-and-forward PIXIT values

Outbound relay feature flags/properties:

- `amhs.relay.enabled`
- `amhs.relay.routing-table`
- `amhs.relay.max-attempts`
- `amhs.relay.scan-delay-ms`

Behavior:

- Route selected by O/R prefix mapping
- Alternate next-hop(s) supported
- Exponential backoff retries
- Dead-letter transition after max attempts
- Trace-based loop detection

## 6. Persistence and state PIXIT values

- Message states tracked in persistent storage (repository-backed)
- Delivery report entities persisted
- Channel policy (CN/OU/enabled) persisted

## 7. Test limitations to declare to lab

1. No formal claim of full X.411 ASN.1 module conformance.
2. No complete security label enforcement profile.
3. CRL/OCSP behavior not implemented as explicit AMHS policy module.
4. Full certified-node interoperability evidence not yet available.

## 8. Proposed lab execution profile

- Run baseline transport and ACSE compatibility suite first.
- Run negative BER/APDU robustness suite second.
- Run routing/retry/DR scenarios with controlled peer outages.
- Run security profile checks with mTLS + certificate policy mismatch cases.

