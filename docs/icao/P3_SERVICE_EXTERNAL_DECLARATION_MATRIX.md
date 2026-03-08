# P3 Service External Declaration Matrix (R2026.03)

Document status: **mandatory external-claim closure artifact**.

## 1. Purpose

This matrix publishes the declared external P3 endpoint behavior for the gateway profile, including a complete operation matrix and deterministic reject/error mapping for unsupported and malformed vectors.

## 2. Declaration boundary

- This matrix applies to release `R2026.03` and its fingerprint in `docs/icao/releases/R2026.03/CONFIGURATION_FINGERPRINT.txt`.
- Coverage is bound to the gateway-profile semantics declared in `docs/icao/releases/R2026.03/P3_INTERNAL_PROFILE_STATEMENT.md`.
- Operations outside this matrix are explicitly non-claimed and must produce deterministic reject/error behavior.

## 3. Complete declared operation matrix

| Family | Operation / APDU | Support status | Deterministic success semantics | Deterministic reject/error semantics | Implementation/test evidence |
|---|---|---|---|---|---|
| Association lifecycle | Bind (`RT-BIND`, gateway `bind-request[0]`) | Supported | First valid bind initializes association state and returns `bind-response[1]`. | Duplicate bind while bound is rejected with gateway error `code=association`; malformed bind inputs are rejected with stable gateway error payload. | `src/main/java/it/amhs/service/protocol/p3/P3GatewaySessionService.java`; `src/test/java/it/amhs/service/protocol/p3/P3GatewaySessionServiceTest.java`; `src/test/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocolTest.java` |
| Message transfer | Submit (`submit-request[2]`) | Supported | Accepted submit returns `submit-response[3]` containing stable key/value payload mapping. | Unsupported/invalid submit vectors return gateway `error[8]` with stable `code`/`detail` fields (retryability explicit). | `src/main/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocol.java`; `src/test/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocolTest.java`; `src/test/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocolNegativeVectorsTest.java` |
| Probe/query | Status (`status-request[4]`) | Supported | Returns `status-response[5]` for known submission correlation and wait/retry semantics. | Unknown correlation or malformed status payload returns deterministic gateway `error[8]` class. | `src/main/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocol.java`; `src/test/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocolTest.java` |
| Report handling | Report query/handling (`report-request[9]`) | Supported (declared gateway profile) | Returns `report-response[10]` carrying report/result key/value fields. | Unsupported report path variants outside declared profile return deterministic gateway `error[8]` with explicit reason fields. | `src/main/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocol.java`; `src/test/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocolTest.java`; `docs/icao/MULTI_VENDOR_BIND_SUBMIT_STATUS_REPORT_RELEASE_EVIDENCE.md` |
| Association lifecycle | Release (`release-request[6]` / `RT-RELEASE`) | Supported | Graceful unbind returns `release-response[7]` and closes association state. | Pre-bind release and post-release invocation attempts are rejected with stable association class diagnostics (`association` or `association-closed`). | `src/main/java/it/amhs/service/protocol/p3/P3GatewaySessionService.java`; `src/test/java/it/amhs/service/protocol/p3/P3GatewaySessionServiceTest.java`; `src/test/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocolTest.java` |
| Abort handling | RTSE abort (`RTAB[19]`) | Supported (profile-mapped) | Inbound `RTAB` is mapped to deterministic release handling and returns wrapper `RTAB[19]` carrying nested `release-response[7]` on success. | If release preconditions fail, nested gateway `error[8]` is returned deterministically in the `RTAB` wrapper. | `src/main/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocol.java`; `src/test/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocolTest.java` |
| ROSE invoke dispatch | ROSE `invoke[1]` carrying request opcodes | Supported | Valid request opcode invokes gateway mapping and returns `returnResult[2]` with response APDU payload. | Response-only opcodes used in invoke path return deterministic `returnError[3]` with nested gateway `error[8]` and `code=invalid-operation-role`. Unknown opcodes return deterministic `code=unsupported-operation`. | `src/main/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocol.java`; `src/test/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocolTest.java` |
| Reject/error classes | ROSE non-invoke inbound APDUs (`returnResult`,`returnError`,`reject`) | Unsupported inbound role | N/A | Deterministically rejected as ROSE `reject[4]` reason `unexpected-rose-apdu`. | `src/main/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocol.java`; `src/test/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocolTest.java` |
| Reject/error classes | Malformed ROSE invoke payload | Unsupported malformed form | N/A | Deterministically rejected as ROSE `reject[4]` reason `malformed-rose-invoke`. | `src/main/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocol.java`; `src/test/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocolNegativeVectorsTest.java` |
| RTSE transfer wrappers | `RTORQ[16]` / `RTTD[22]` | Supported | Deterministic wrapper mapping: `RTORQ→RTOAC[17]`, `RTTD→RTTR[21]`, carrying nested gateway/ROSE response. | Missing nested supported APDU returns wrapper response with nested `error[8]` `code=unsupported-operation`. | `src/main/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocol.java`; `src/test/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocolTest.java`; `src/test/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocolNegativeVectorsTest.java` |
| RTSE reject mapping | Unsupported/inbound response-side RTSE wrappers (`RTOAC`,`RTTR`,invalid tags) | Unsupported in request path | N/A | Deterministic RTSE reject mapping to `RTORJ[18]`; nested gateway diagnostics preserved where applicable. | `src/main/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocol.java`; `src/test/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocolTest.java` |
| Out-of-profile breadth | Additional/unspecified endpoint operations beyond matrix | Unsupported (explicit non-claim) | N/A | Deterministic unsupported-operation behavior only; no equivalence claim to profile-complete endpoint semantics. | `docs/icao/ICAO_EXTERNAL_P3_NONCLAIM_BOUNDARY_ACCEPTANCE.md`; `docs/icao/releases/R2026.03/P3_INTERNAL_PROFILE_STATEMENT.md` |

## 4. Deterministic reject reason and error-class mapping

| Incoming vector class | Required deterministic response class | Deterministic reason / code mapping |
|---|---|---|
| Unknown gateway context APDU tag | Gateway `error[8]` | `code=unsupported-operation`, detail includes unsupported APDU/tag number. |
| Primitive (non-constructed) context APDU where constructed form is required | Gateway `error[8]` | `code=invalid-apdu`, detail `Expected context-specific constructed APDU`. |
| ROSE invoke with response opcode (`1,3,5,7,8,10`) | ROSE `returnError[3]` + nested gateway `error[8]` | `code=invalid-operation-role`. |
| ROSE invoke with unknown opcode | ROSE `returnError[3]` + nested gateway `error[8]` | `code=unsupported-operation`. |
| Unexpected inbound ROSE non-invoke APDU | ROSE `reject[4]` | `reason=unexpected-rose-apdu`. |
| Malformed ROSE invoke (missing invoke-id/op-code or decode failure) | ROSE `reject[4]` | `reason=malformed-rose-invoke`. |
| RTSE wrapper with no nested supported gateway/ROSE APDU | RTSE response wrapper + nested gateway `error[8]` | `code=unsupported-operation`. |
| Unsupported inbound RTSE request-path wrapper/tag | RTSE `RTORJ[18]` | Deterministic RTSE wrapper reject class (`RTORJ`). |
| Association operation attempted in invalid lifecycle state | Gateway `error[8]` | `code=association` or `code=association-closed` by state transition. |

## 5. External declaration sign-off

| Role | Name | Decision | Date (UTC) |
|---|---|---|---|
| Engineering owner | _Pending_ | Pending | - |
| Compliance owner | _Pending_ | Pending | - |
| Security owner | _Pending_ | Pending | - |
| Accountable authority | _Pending_ | Pending | - |

## 6. Closure rule

This matrix is declaration-valid only when section 5 is fully signed and the linked evidence artifacts are present for the same release fingerprint.
