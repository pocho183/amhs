# AMHS PICS (Protocol Implementation Conformance Statement)

Document status: **working baseline** for ICAO/ATN interoperability preparation.

## 1. Scope

This PICS describes the currently implemented behavior of this AMHS server for the following protocol areas:

- RFC1006 / TPKT / COTP transport handling
- ACSE association handling (X.227-oriented)
- P1 envelope/content processing (X.411-oriented)
- O/R Address and O/R Name validation constraints
- Routing, retry, and delivery-report persistence behavior

## 2. Claimed implementation class

- **Implementation type**: AMHS MTA-like server with inbound processing and outbound relay support.
- **Conformance claim level**: pre-certification profile, not a formal ICAO-certified claim.

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
| A-03 | Presentation context negotiation | P | Basic negotiation; strict profile coverage incomplete. |
| A-04 | ACSE user-information semantics | P | Parsed/encoded, limited semantic enforcement. |
| A-05 | AP-title / AE-qualifier structures | P | Formal containers present, profile completeness pending. |
| A-06 | Authentication-value semantics | P | Field support present, policy semantics limited. |
| P1-01 | BER parsing for P1-like envelope | Y | Structured BER/TLV support in parser. |
| P1-02 | Envelope/content separation | Y | Envelope and content are separated. |
| P1-03 | Per-recipient handling | Y | Per-recipient routing state supported. |
| P1-04 | Trace information handling | Y | Trace extraction/injection supported. |
| P1-05 | Unknown extension preservation | Y | Unknown extension containers retained. |
| P1-06 | Full X.411 ASN.1 module conformance | N | Official module-derived encoding proof not yet provided. |
| OR-01 | Structured O/R Address parsing | Y | Supports keyed O/R attribute model. |
| OR-02 | OU sequencing validation (OU1..OU4) | Y | Enforces non-skipping OU order. |
| OR-03 | ISO/Numeric country validation | Y | Country checks for C attribute. |
| OR-04 | Full ORName CHOICE coverage | P | Simplified support; full grammar pending. |
| OR-05 | Teletex/DirectoryName compatibility | N | Not fully implemented. |
| SEC-01 | TLS transport protection | Y | Server TLS supported; optional client auth. |
| SEC-02 | Certificate CN/OU channel policy | Y | Channel policy and sender binding checks. |
| SEC-03 | Full PKI path validation profile | P | Depends on JVM trust/PKIX; ATN profile hardening pending. |
| SEC-04 | CRL / OCSP runtime enforcement | N | Not currently enforced by dedicated policy. |
| SEC-05 | Security label enforcement (Doc 9880) | N | Not implemented. |
| R-01 | Outbound relay routing table | Y | Prefix-based route selection implemented. |
| R-02 | Alternate route fallback | Y | Alternate next-hop path supported. |
| R-03 | Retry with exponential backoff | Y | Retry policy and dead-letter path supported. |
| R-04 | NDR/DR protocol-level correlation | Y | DR/NDR reports now persist `related_mts_identifier` and `correlation_token` for protocol-level message/report linkage. |
| D-01 | Negative diagnostic mapping completeness | Y | Dedicated X.411 diagnostic mapper covers timeout, routing, loop, security/auth and validation failure classes with explicit/fallback code selection. |
| O-01 | Operational HA/failover profile | P | No clustered failover in-process; persistence-backed restart/recovery profile is documented for active/passive operations. |

## 4. Known profile gaps (must close for strict ICAO readiness)

1. Replace ad-hoc/simplified ASN.1 assumptions with official X.411 module-traceable definitions.
2. Complete ORName/ORAddress grammar and string-type interoperability (including Teletex/DirectoryName choices).
3. Harden security profile with explicit CRL/OCSP and ATN PKI policy checks.
4. Validate interoperability against a certified AMHS node and preserve evidence.
5. Define/validate clustered HA failover guarantees for strict operational conformance.

## 5. Evidence pointers in this repository

- Transport and parser tests under `src/test/java/it/amhs/service/`.
- BER codec tests under `src/test/java/it/amhs/asn1/`.
- Compliance and address validation tests under `src/test/java/it/amhs/compliance/` and `src/test/java/it/amhs/service/ORAddressTest.java`.

