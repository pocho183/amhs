# AMHS PICS (Protocol Implementation Conformance Statement)

Document status: **gateway-profile baseline** for controlled interoperability.

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
| U-01 | ROSE operation coverage for full P3 service set | N | Full ROSE operation/error mapping coverage is not implemented. |
| U-02 | RTSE behavior coverage | N | RTSE stack behavior is not implemented as a complete profile-conformant layer. |
| U-03 | Session semantics beyond wrapper preservation | P | Session/presentation envelopes are preserved/rewrapped in supported gateway paths. |
| U-04 | Complete X.411/P3 service behavior and error semantics | N | Full externally certifiable P3 service surface and error model are not fully implemented. |
| P1-01 | BER parsing for P1-like envelope | Y | Structured BER/TLV support in parser. |
| P1-02 | Envelope/content separation | Y | Envelope and content are separated. |
| P1-03 | Per-recipient handling | Y | Per-recipient routing state supported. |
| P1-04 | Trace information handling | Y | Trace extraction/injection supported. |
| P1-05 | Unknown extension preservation | Y | Unknown extension containers retained. |
| P1-06 | Full X.411 ASN.1 module conformance | N | Runtime profile tag-table checks and DR/NDR BER evidence are implemented, but canonical module-level ASN.1 proof is still pending. |
| OR-01 | Structured O/R Address parsing | Y | Supports keyed O/R attribute model. |
| OR-02 | OU sequencing validation (OU1..OU4) | Y | Enforces non-skipping OU order. |
| OR-03 | ISO/Numeric country validation | Y | Country checks for C attribute. |
| OR-04 | Full ORName CHOICE coverage | Y | DirectoryName-only and ORAddress-only CHOICE paths are decoded and normalized into canonical O/R attributes with ICAO validation hooks. |
| OR-05 | Teletex/DirectoryName compatibility | Y | Teletex, BMPString, UniversalString, IA5 and PrintableString variants are decoded for DirectoryName/legacy paths. |
| SEC-01 | TLS transport protection | Y | Server TLS supported; optional client auth. |
| SEC-02 | Certificate CN/OU channel policy | Y | Channel policy and sender binding checks. |
| SEC-03 | Full PKI path validation profile | P | Baseline checks present; full ATN PKI profile evidence package remains to be completed. |
| SEC-04 | CRL / OCSP runtime enforcement | P | Partial support may depend on runtime configuration; not asserted as complete profile enforcement. |
| SEC-05 | Security label enforcement (Doc 9880) | N | No formal full Doc 9880 security label enforcement claim. |
| R-01 | Outbound relay routing table | Y | Prefix-based route selection implemented. |
| R-02 | Alternate route fallback | Y | Alternate next-hop path supported. |
| R-03 | Retry with exponential backoff | Y | Retry policy and dead-letter path supported. |
| R-04 | NDR/DR protocol-level correlation | Y | DR/NDR reports now persist `related_mts_identifier` and `correlation_token` for protocol-level message/report linkage. |
| D-01 | Negative diagnostic mapping completeness | Y | Dedicated X.411 diagnostic mapper covers timeout, routing, loop, security/auth and validation failure classes with explicit/fallback code selection. |
| O-01 | Operational HA/failover profile | P | Operational guidance exists; formal evidence pack for external oversight remains required. |

## 4. External deployment readiness gaps (including EU/Italy oversight contexts)

Open closure items before declaring operational external conformance:

1. Formal conformance matrix against applicable AMHS/P3 profiles and national oversight expectations.
2. Interoperability campaign evidence versus representative external peers.
3. Safety/security assessment records and traceable residual-risk acceptance.
4. Performance and resilience evidence under sustained operational load.
5. Operational hardening evidence (runbooks, failover drills, backup/restore, monitoring SLOs).
6. Formal ASN.1/compiler-backed traceability package against official X.411-related module definitions.

## 5. Evidence pointers in this repository

- Transport and parser tests under `src/test/java/it/amhs/service/`.
- BER codec tests under `src/test/java/it/amhs/asn1/`.
- Compliance and address validation tests under `src/test/java/it/amhs/compliance/` and `src/test/java/it/amhs/service/ORAddressTest.java`.
