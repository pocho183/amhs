# Reproducible multi-vendor bind/submit/status/report/release evidence

This campaign packages reproducible evidence for the P3 gateway operation set with both positive and negative paths.

## Scope

Operations covered:

- bind
- submit
- status
- report
- release

Wire/vendor surfaces covered:

- context-specific BER APDU gateway clients
- ROSE invoke/return-result/return-error clients
- RTSE wrapped (`RTORQ`/`RTOAC`, `RTTD`/`RTTR`, `RTAB`) clients

## Reproducible execution

Run:

```bash
scripts/evidence/p3_multi_vendor_evidence.sh
```

The script executes deterministic JUnit evidence suites and stores artifacts in:

- `build/evidence/p3-multi-vendor-evidence.log`
- `build/test-results/test` (JUnit XML)
- `build/reports/tests/test/index.html` (HTML report)

## Evidence mapping

| Evidence area | Reproducible test coverage |
|---|---|
| BER APDU bind/submit/status/report lifecycle | `P3Asn1GatewayProtocolTest.mapsBindAndSubmitAndStatusToSessionService` |
| RTSE bind/submit style wrapping | `P3Asn1GatewayProtocolTest.unwrapsRtseRtorqAndReturnsRtoacWithGatewayPayload`, `P3Asn1GatewayProtocolTest.unwrapsRtseRttdAndReturnsRttrWithRosePayload` |
| RTSE release mapping | `P3Asn1GatewayProtocolTest.mapsRtabToReleaseResponse` |
| Association bind/submit/release deterministic lifecycle | `P3GatewaySessionServiceTest.bindSubmitAndUnbindFlowReturnsDeterministicSubmissionId` |
| Status/report behavior and correlation diagnostics | `P3GatewaySessionServiceTest` status/report scenarios in the same suite |

## Negative-path diagnostics included

| Scenario | Expected diagnostic family |
|---|---|
| release before bind | `ERR code=association detail=Release received before bind` |
| submit before bind | `ERR code=association detail=Submit received before bind` |
| operation after release | `ERR code=association-closed detail=Association already released` |
| duplicate bind on same association | `ERR code=association detail=Bind received on already bound association` |
| invalid ROSE role (response opcode used as invoke) | ROSE `returnError` with gateway payload `invalid-operation-role` |
| unsupported ROSE operation | ROSE `returnError` with gateway payload `unsupported-operation` |
| unsupported RTSE wrapper tag | RTSE `RTORJ` |

## Notes

- This campaign is intentionally transport/profile focused and does not claim full native mailbox semantics of full ISODE P3 stacks.
- The evidence command is safe to re-run in CI and local environments.
