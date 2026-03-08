# P3 Service External Declaration Matrix (R2026.03)

Document status: **mandatory external-claim closure artifact**.

## 1. Purpose

This matrix provides the full declared P3 service view with explicit support status and error semantics, suitable for external declaration governance.

## 2. Declaration boundary

- This matrix applies to release `R2026.03` and its fingerprint in `docs/icao/releases/R2026.03/CONFIGURATION_FINGERPRINT.txt`.
- Coverage is bound to the gateway-profile semantics declared in `docs/icao/releases/R2026.03/P3_INTERNAL_PROFILE_STATEMENT.md`.
- Unsupported operations are explicitly non-claimed and must produce deterministic reject behavior.

## 3. Service/operation matrix

| Service area | Operation | Support status | Positive semantics | Error/negative semantics | Evidence |
|---|---|---|---|---|---|
| Association control | Bind (`RT-BIND`) | Supported | Accepts first valid bind for association and initializes session context. | Duplicate bind on active association is rejected with deterministic diagnostic; invalid bind payloads are rejected. | `src/test/java/it/amhs/service/protocol/p3/P3GatewaySessionServiceTest.java`, `src/test/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocolTest.java` |
| Association control | Re-bind while active association exists | Unsupported (explicit) | N/A | Rejected deterministically per single-bind policy. | `src/test/java/it/amhs/service/protocol/p3/P3GatewaySessionServiceTest.java` |
| Association control | Release (`RT-RELEASE`) | Supported | Graceful release of bound association state. | Post-release invocations are rejected with association-closed semantics. | `src/test/java/it/amhs/service/protocol/p3/P3GatewaySessionServiceTest.java` |
| Message transfer | Submit operation | Supported | Accepts declared gateway submit request and emits deterministic response mapping. | Malformed or profile-invalid submit vectors are rejected with deterministic diagnostics. | `src/test/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocolTest.java`, `src/test/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocolNegativeVectorsTest.java` |
| Message transfer | Message status query | Supported | Returns status/report semantics for declared gateway profile behavior. | Unknown/invalid correlation or malformed payload is rejected deterministically. | `src/test/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocolTest.java`, `src/test/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocolNegativeVectorsTest.java` |
| Report handling | Delivery/non-delivery report retrieval/handling | Supported (gateway profile) | Supports deterministic report handling path aligned with declared gateway operations. | Unsupported report variants outside profile are rejected with explicit diagnostics. | `src/test/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocolTest.java`, `docs/icao/MULTI_VENDOR_BIND_SUBMIT_STATUS_REPORT_RELEASE_EVIDENCE.md` |
| ROSE protocol behavior | Invoke role/shape validation | Supported | Valid invoke operations are dispatched by operation mapping. | Request/response role mismatch and unexpected non-invoke APDUs are rejected with deterministic ROSE reject semantics. | `src/test/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocolNegativeVectorsTest.java`, `docs/icao/releases/R2026.03/P3_INTERNAL_PROFILE_STATEMENT.md` |
| RTSE transfer control | `RTORQ`/`RTOAC` handshake | Supported | Deterministic request/accept handshake in declared profile. | Invalid handshake state/payload rejected deterministically. | `src/test/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocolTest.java`, `docs/icao/releases/R2026.03/P3_INTERNAL_PROFILE_STATEMENT.md` |
| RTSE transfer control | `RTTD`/`RTTR` data transfer | Supported | Transfer data path supported for declared gateway operations. | Invalid transfer sequence/payload rejected deterministically. | `src/test/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocolTest.java`, `src/test/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocolNegativeVectorsTest.java` |
| RTSE abort/reject | `RTAB` / `RTORJ` | Supported | Deterministic abort/reject handling and mapping. | Invalid or out-of-sequence reject vectors handled deterministically. | `src/test/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocolNegativeVectorsTest.java` |
| Full profile-complete P3 endpoint breadth beyond declared gateway set | Additional/unspecified operations | Unsupported (non-claimed) | N/A | Deterministic explicit unsupported-operation rejection; no equivalence claim to full external profile-complete behavior. | `docs/icao/ICAO_EXTERNAL_P3_NONCLAIM_BOUNDARY_ACCEPTANCE.md`, `docs/icao/releases/R2026.03/P3_INTERNAL_PROFILE_STATEMENT.md` |

## 4. External declaration sign-off

| Role | Name | Decision | Date (UTC) |
|---|---|---|---|
| Engineering owner | _Pending_ | Pending | - |
| Compliance owner | _Pending_ | Pending | - |
| Security owner | _Pending_ | Pending | - |
| Accountable authority | _Pending_ | Pending | - |

## 5. Closure rule

This matrix is considered declaration-valid only when section 4 is fully signed and the linked evidence artifacts are present for the same release fingerprint.
