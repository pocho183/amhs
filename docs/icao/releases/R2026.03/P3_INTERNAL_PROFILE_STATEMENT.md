# P3 Internal Profile Statement (Release R2026.03)

## 1. Scope and baseline

This release-specific statement freezes the internal P3 gateway operation profile for `R2026.03` and defines the deterministic diagnostics expected for supported and unsupported P3 APDUs.

Configuration binding for this statement is locked to:

- `docs/icao/releases/R2026.03/CONFIGURATION_FINGERPRINT.txt`

## 2. Supported P3 operations (request side)

| APDU family | Code / wrapper | Status | Deterministic success behavior |
|---|---:|---|---|
| Gateway bind-request | context `[0]` | Supported | Returns bind-response `[1]` with key/value payload on successful authentication/policy checks. |
| Gateway submit-request | context `[2]` | Supported | Returns submit-response `[3]` with submission metadata. |
| Gateway status-request | context `[4]` | Supported | Returns status-response `[5]` with queue/status fields. |
| Gateway report-request | context `[9]` | Supported | Returns report-response `[10]` with delivery/report fields. |
| Gateway release-request | context `[6]` | Supported | Returns release-response `[7]` when association lifecycle allows release. |
| ROSE invoke | application/context `invoke[1]` | Supported (request opcodes only) | Returns ROSE returnResult `[2]` wrapping the gateway response APDU. |
| RTSE transfer wrappers | `RTORQ[16]` and `RTTD[22]` | Supported | Wrapper response tag mapping is deterministic: `RTORQ->RTOAC[17]`, `RTTD->RTTR[21]`, carrying nested gateway/ROSE response. |
| RTSE abort wrapper used as release | `RTAB[19]` | Supported | Mapped to gateway `UNBIND`, returns `RTAB[19]` with nested release-response `[7]` on success. |

## 3. Unsupported operations and negative diagnostics

| Vector | Expected diagnostic/result |
|---|---|
| Unknown context APDU tag | Gateway `error[8]` with `code=unsupported-operation`. |
| Primitive/non-constructed context APDU for gateway path | Gateway `error[8]` with `code=invalid-apdu` and detail `Expected context-specific constructed APDU`. |
| ROSE invoke using response-only opcodes (`1,3,5,7,8,10`) | ROSE `returnError[3]` wrapping gateway `error[8]` with `code=invalid-operation-role`. |
| ROSE invoke with unknown opcode | ROSE `returnError[3]` wrapping gateway `error[8]` with `code=unsupported-operation`. |
| Unexpected non-invoke ROSE APDU (`returnResult`, `returnError`, `reject`) received inbound | ROSE `reject[4]` with reason `unexpected-rose-apdu`. |
| Malformed ROSE invoke (missing invoke-id/operation-code, decode failure) | ROSE `reject[4]` with reason `malformed-rose-invoke`. |
| RTSE wrapper without nested supported gateway/ROSE APDU | RTSE wrapper response with nested gateway `error[8]` and `code=unsupported-operation`. |
| Unsupported RTSE wrapper tag (e.g. inbound `RTOAC`/invalid path) | RTSE `RTORJ[18]` deterministic rejection mapping. |
| Association release before bind or operation after release | Gateway `error[8]` family from session service, including `code=association` or `code=association-closed` depending on state. |

## 4. Regression evidence (malformed/negative vectors)

The release carries an automated negative vector run and publication script:

- Script: `scripts/evidence/p3_negative_apdu_regression.sh`
- Published release artifact root: `docs/icao/releases/R2026.03/evidence/p3-negative-apdu/`
- Preserved artifacts per execution:
  - timestamped run log
  - JUnit XML for `P3Asn1GatewayProtocolNegativeVectorsTest`
  - JUnit XML for `P3Asn1GatewayProtocolTest`
  - timestamped manifest with SHA-256 checksums (`latest-manifest.txt` updated to last run)

