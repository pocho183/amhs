# AMHS PICS (Protocol Implementation Conformance Statement)

Document status: **gateway-profile baseline** for controlled interoperability, with an explicit closure plan toward ICAO-compliant AMHS server declarations for P1/P3 service areas.

## 1. Scope

This PICS describes the currently implemented behavior of this AMHS server for the following protocol areas:

- RFC1006 / TPKT / COTP transport handling
- ACSE association handling (X.227-oriented, profile-limited)
- P1/P3 gateway envelope/content processing (X.411-oriented subset)
- O/R Address and O/R Name validation constraints
- Routing, retry, and delivery-report persistence behavior

## 2. Claimed implementation class

- **Implementation type**: AMHS gateway-oriented server with inbound processing and outbound relay support.
- **Conformance claim level**: profile-limited implementation for controlled lab/integration usage; **not** a declared full external P3 endpoint conformance claim.

## 3. Capability matrix (PICS-style answers)

Legend:

- **Y**: implemented
- **N**: not implemented
- **P**: partially implemented

| Ref | Capability | Status | Notes |
|---|---|---|---|
| T-01 | TPKT version/length validation | Y | Rejects invalid framing. |
| T-02 | COTP CR/CC negotiation | Y | Class 0 association flow supported. |
| T-03 | TPDU size negotiation | Y | Negotiated and enforced with limits. |
| T-04 | COTP segmentation/reassembly | Y | Handles segmented payloads. |
| T-05 | COTP DR/ER handling | Y | Disconnect and error TPDUs handled. |
| T-06 | Idle timeout / frame size guard | Y | Idle and max-frame controls enforced. |
| A-01 | ACSE AARQ decoding and checks | Y | Application context and identity checks for supported gateway profile paths. |
| A-02 | ACSE AARE structured response | Y | Result + diagnostic container emitted for supported flows, including deterministic rejection diagnostics for invalid AARQ profile elements. |
| A-03 | Presentation context negotiation | P | Basic/controlled negotiation support; not a full profile-complete negotiation stack. |
| A-04 | ACSE user-information semantics | P | Supported through constrained EXTERNAL/OCTET STRING handling path. |
| A-05 | AP-title / AE-qualifier structures | P | Core structures supported; not a broad complete ACSE interoperability claim. |
| A-06 | Authentication-value semantics | P | Implemented for configured policy checks, not exhaustive profile-semantic coverage. |
| A-07 | P3 bind/re-bind/release error semantics | Y | Single-bind association policy, release-before-bind diagnostics, and post-release association-closed diagnostics are enforced. |
| U-01 | ROSE operation coverage for full P3 service set | P | Bind/submit/status/release/report operations are mapped with deterministic error envelopes, but complete profile-wide ROSE operation/error coverage is still pending. |
| U-02 | RTSE behavior coverage | Y | RTSE wrapper semantics are implemented for the declared gateway profile operations, including deterministic `RTORQ`/`RTOAC`, `RTTD`/`RTTR`, `RTAB`, and `RTORJ` rejection paths. |
| U-03 | Session semantics beyond wrapper preservation | P | Session/presentation envelopes are preserved/rewrapped in supported gateway paths. |
| U-04 | Complete X.411/P3 service behavior and error semantics | P | Gateway service now provides explicit bind/submit/status/report/release behavior with deterministic error semantics; full externally certifiable profile breadth remains pending. |
| P1-01 | BER parsing for P1-like envelope | Y | Structured BER/TLV support in parser. |
| P1-02 | Envelope/content separation | Y | Envelope and content are separated. |
| P1-03 | Per-recipient handling | Y | Per-recipient routing state supported. |
| P1-04 | Trace information handling | Y | Trace extraction/injection supported. |
| P1-05 | Unknown extension preservation | Y | Unknown extension containers retained. |
| P1-06 | Full X.411 ASN.1 module conformance | P | Runtime profile tag-table checks and DR/NDR BER evidence are implemented, but canonical module-level ASN.1 proof is still pending. |
| OR-01 | Structured O/R Address parsing | Y | Supports keyed O/R attribute model. |
| OR-02 | OU sequencing validation (OU1..OU4) | Y | Enforces non-skipping OU order. |
| OR-03 | ISO/Numeric country validation | Y | Country checks for C attribute. |
| OR-04 | Full ORName CHOICE coverage | Y | DirectoryName-only and ORAddress-only CHOICE paths are decoded and normalized into canonical O/R attributes with ICAO validation hooks, including strict 8-letter ICAO unit checks. |
| OR-05 | Teletex/DirectoryName compatibility | Y | Teletex, BMPString, UniversalString, IA5 and PrintableString variants are decoded for DirectoryName/legacy paths. |
| SEC-01 | TLS transport protection | Y | Server TLS supported; optional client auth. |
| SEC-02 | Certificate CN/OU channel policy | Y | Channel policy and sender binding checks. |
| SEC-03 | Full PKI path validation profile | P | Baseline checks present; full ATN PKI profile evidence package remains to be completed. |
| SEC-04 | CRL / OCSP runtime enforcement | P | Partial support may depend on runtime configuration; not asserted as complete profile enforcement. |
| SEC-05 | Security label enforcement (Doc 9880) | P | Classification ordering + compartment dominance semantics are enforced for gateway security labels; full external profile claim remains out of scope. |
| R-01 | Outbound relay routing table | Y | Prefix-based route selection implemented. |
| R-02 | Alternate route fallback | Y | Alternate next-hop path supported. |
| R-03 | Retry with exponential backoff | Y | Retry policy and dead-letter path supported. |
| R-04 | NDR/DR protocol-level correlation | Y | DR/NDR reports now persist `related_mts_identifier` and `correlation_token` for protocol-level message/report linkage. |
| D-01 | Negative diagnostic mapping completeness | Y | Dedicated X.411 diagnostic mapper covers timeout, routing, loop, security/auth and validation failure classes with explicit/fallback code selection. |
| O-01 | Operational HA/failover profile | P | Operational guidance exists; formal evidence pack for external oversight remains required. |

## 4. Protocol P3 section (profile declaration)

This implementation exposes a **gateway-oriented P3 profile** and does not currently claim full ICAO-certifiable end-to-end P3 conformance.

### 4.1 Supported P3 behaviors

- ACSE association establishment/release for the constrained gateway profile.
- Bind lifecycle guards:
  - single active bind per association,
  - re-bind rejection while bound,
  - explicit diagnostics for operations attempted before bind or after release.
- Submission-oriented message ingress mapped into the internal AMHS canonical message model.
- O/R Name and O/R Address normalization with ICAO-oriented validation hooks.
- Delivery/Non-delivery report persistence with protocol-level correlation fields (`related_mts_identifier`, `correlation_token`).

### 4.2 Declared limitations for P3

- ROSE operation/error mapping is implemented for the declared gateway operation subset (bind, submit, status, report, release), but full profile-wide operation coverage is still pending.
- RTSE wrapper behavior is implemented for the declared gateway operation subset; broader external profile breadth beyond the gateway declaration remains out of scope.
- Presentation/ACSE negotiation semantics are implemented for supported paths only, not as a universal full interoperability surface.
- Security label behavior now enforces Doc 9880-style classification ordering and compartment dominance for gateway labels, but full certifiable policy scope remains pending.

### 4.3 Interoperability posture

- Intended for controlled integration and gateway scenarios where peer expectations are aligned with the declared profile.
- External operational declaration as a fully conformant P3 endpoint requires closure of all items in Section 5.

## 5. Missing points for ICAO compliance closure

The following items are currently open and should be treated as mandatory closure points before claiming ICAO-oriented external compliance.

### 5.1 Standards/profile conformance evidence

1. Formal requirement-by-requirement mapping from applicable ICAO/ATN AMHS profiles to implementation/test evidence.
2. Full P3 service matrix with explicit supported/unsupported operation and error semantics, signed off for external declaration.
3. ASN.1 traceability package proving canonical X.411 module/tag alignment (beyond runtime profile-table checks).

### 5.2 Interoperability campaign evidence

4. Multi-peer interoperability campaign (including at least one certified AMHS implementation) with reproducible logs and pcaps.
5. Negative-scenario campaign pack (malformed TPDU, ACSE rejection vectors, unsupported P3 operations) with deterministic verdicts.
6. Evidence of behavior with legacy peer encodings for O/R and DirectoryName variants observed in operational networks.

### 5.3 Security and PKI compliance

7. ATN PKI profile statement with objective evidence for certificate path validation behavior.
8. CRL/OCSP enforcement tests and operational proof (including stale/unreachable responder handling).
9. Formal security-label policy treatment aligned with applicable Doc 9880 expectations (or formally approved non-claim/risk acceptance).

### 5.4 Operational assurance

10. Performance/resilience qualification under sustained load, including retry/fallback and recovery behavior.
11. Operational readiness package: SLOs, monitoring/alerting thresholds, failover drills, backup/restore verification.
12. Safety/security assessment records with residual-risk acceptance by accountable authority.

### 5.5 Governance and declaration artifacts

13. Completed PICS/PIXIT set tied to a specific release baseline and configuration fingerprint.
14. Conformance test matrix verdict completion with artifact references per row.
15. National oversight packaging (including any EU/Italy-specific authority expectations) with traceable approval records.

## 6. P1/P3 ICAO-compliance build plan (implementation-oriented)

This section translates open closure points into a concrete delivery plan for building an AMHS server profile that can be declared ICAO-compliant for P1/P3 scope once all evidence is complete.

### 6.1 Target declaration profile

- **P1 target**: externalized MTS relay/interpersonal handling profile aligned with X.411 module definitions and deterministic DR/NDR behavior.
- **P3 target**: externally declared P3 endpoint profile (beyond gateway-only posture) with full documented operation/error semantics.
- **Security target**: ATN PKI + Doc 9880-aligned operational evidence set suitable for oversight review.

### 6.2 Required technical closure for P1

1. Complete canonical ASN.1 module-level proof package for X.411, linked to runtime codec behavior and BER vectors.
2. Freeze and sign-off extension handling rules (known + unknown elements) with backward-compatibility checks.
3. Complete end-to-end DR/NDR interoperability traces proving correlation and semantic consistency across peers.

### 6.3 Required technical closure for P3

4. Expand ROSE operation/error coverage from the current declared subset to full profile-required semantics.
5. Complete ACSE/presentation negotiation behavior matrix for external interoperability declaration.
6. Produce reproducible multi-vendor bind/submit/status/report/release evidence with negative-path diagnostics.

### 6.4 Compliance packaging required before claim

7. Publish release-bound PICS + PIXIT with configuration fingerprint and feature flags.
8. Link each conformance matrix row to executable test artifacts/logs/pcaps.
9. Package authority-facing declaration dossier (technical evidence, security evidence, operational controls, residual-risk approvals).

## 7. Evidence pointers in this repository

- Transport and parser tests under `src/test/java/it/amhs/service/`.
- BER codec tests under `src/test/java/it/amhs/asn1/`.
- Compliance and address validation tests under `src/test/java/it/amhs/compliance/` and `src/test/java/it/amhs/service/ORAddressTest.java`.
