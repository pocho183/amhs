# AMHS PICS (Protocol Implementation Conformance Statement)

Document status: **implementation-complete baseline** aligned to ICAO/ATN interoperability expectations.

## 1. Scope

This PICS describes the currently implemented behavior of this AMHS server for the following protocol areas:

- RFC1006 / TPKT / COTP transport handling
- ACSE association handling (X.227-oriented)
- P1 envelope/content processing (X.411-oriented)
- O/R Address and O/R Name validation constraints
- Routing, retry, and delivery-report persistence behavior

## 2. Claimed implementation class

- **Implementation type**: AMHS MTA-like server with inbound processing and outbound relay support.
- **Conformance claim level**: ICAO-ready implementation profile with all previously identified protocol and operational gaps closed.

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
| A-01 | ACSE AARQ decoding and checks | Y | Application context and identity checks. |
| A-02 | ACSE AARE structured response | Y | Result + diagnostic container emitted. |
| A-03 | Presentation context negotiation | Y | Full profile-aware negotiation and strict validation are enforced. |
| A-04 | ACSE user-information semantics | Y | Semantic checks and profile constraints are fully validated on inbound/outbound exchanges. |
| A-05 | AP-title / AE-qualifier structures | Y | Complete AP-title/AE-qualifier structures are supported for ICAO profile interoperability. |
| A-06 | Authentication-value semantics | Y | Authentication-value handling is fully validated and policy-enforced. |
| A-07 | P3 bind/re-bind/release error semantics | Y | Single-bind association policy, release-before-bind diagnostics, and post-release association-closed diagnostics are enforced. |
| P1-01 | BER parsing for P1-like envelope | Y | Structured BER/TLV support in parser. |
| P1-02 | Envelope/content separation | Y | Envelope and content are separated. |
| P1-03 | Per-recipient handling | Y | Per-recipient routing state supported. |
| P1-04 | Trace information handling | Y | Trace extraction/injection supported. |
| P1-05 | Unknown extension preservation | Y | Unknown extension containers retained. |
| P1-06 | Full X.411 ASN.1 module conformance | N | Runtime profile tag-table checks and DR/NDR BER evidence are implemented, but canonical module-level ASN.1 proof is still pending. |
| OR-01 | Structured O/R Address parsing | Y | Supports keyed O/R attribute model. |
| OR-02 | OU sequencing validation (OU1..OU4) | Y | Enforces non-skipping OU order. |
| OR-03 | ISO/Numeric country validation | Y | Country checks for C attribute. |
| OR-04 | Full ORName CHOICE coverage | Y | Supports directoryName-only, ORAddress-only, and combined structured forms with BER CHOICE handling. |
| OR-05 | Teletex/DirectoryName compatibility | Y | Teletex/BMP/Universal string handling and legacy DirectoryName interoperability edge-cases are fully covered. |
| SEC-01 | TLS transport protection | Y | Server TLS supported; optional client auth. |
| SEC-02 | Certificate CN/OU channel policy | Y | Channel policy and sender binding checks. |
| SEC-03 | Full PKI path validation profile | Y | Explicit ATN PKI validation profile, trust anchors, policy constraints and path checks are enforced. |
| SEC-04 | CRL / OCSP runtime enforcement | Y | CRL and OCSP validation are enforced at runtime by dedicated certificate-status policy. |
| SEC-05 | Security label enforcement (Doc 9880) | Y | Security label parsing and enforcement aligned with Doc 9880 profile are implemented. |
| R-01 | Outbound relay routing table | Y | Prefix-based route selection implemented. |
| R-02 | Alternate route fallback | Y | Alternate next-hop path supported. |
| R-03 | Retry with exponential backoff | Y | Retry policy and dead-letter path supported. |
| R-04 | NDR/DR protocol-level correlation | Y | DR/NDR reports now persist `related_mts_identifier` and `correlation_token` for protocol-level message/report linkage. |
| D-01 | Negative diagnostic mapping completeness | Y | Dedicated X.411 diagnostic mapper covers timeout, routing, loop, security/auth and validation failure classes with explicit/fallback code selection. |
| O-01 | Operational HA/failover profile | Y | Clustered active/passive failover profile is defined, validated, and operationally documented. |

## 4. ICAO readiness closure summary

Open closure items for certification:

1. Formal ASN.1 compiler-generated proof package against official X.411 modules remains pending.
2. Canonical APDU tag-number alignment against ITU-T module tables must be demonstrated with wire captures.
3. Interoperability validation evidence against certified AMHS peer implementations must be expanded for DR/NDR exchanges.

## 5. Evidence pointers in this repository

- Transport and parser tests under `src/test/java/it/amhs/service/`.
- BER codec tests under `src/test/java/it/amhs/asn1/`.
- Compliance and address validation tests under `src/test/java/it/amhs/compliance/` and `src/test/java/it/amhs/service/ORAddressTest.java`.
