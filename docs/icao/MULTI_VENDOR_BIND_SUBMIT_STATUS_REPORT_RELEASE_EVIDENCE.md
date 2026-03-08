# Reproducible multi-vendor bind/submit/status/report/release evidence

This campaign provides release-bound and reproducible closure evidence for the P3 gateway operation set, including positive-path interoperability and negative-path diagnostics.

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

Run for the active release label (example: `R2026.03`):

```bash
scripts/evidence/p3_multi_vendor_evidence.sh R2026.03
```

The command publishes immutable artifacts and checksums under:

- `docs/icao/releases/R2026.03/evidence/p3-multi-vendor/`
- `latest-manifest.txt` (pointer to last successful campaign)
- `<timestamp>-manifest.txt` (artifact list + SHA-256)
- `<timestamp>-signed-campaign-report.md` (signed report with replay instructions + artifact manifest)
- `<timestamp>-verdict-ledger.md` (campaign verdict ledger by peer profile)
- `<timestamp>-decoded-trace.txt` (decoded packet-level trace derived from deterministic pcap)
- `<timestamp>-multi-vendor.pcap.sha256` (pcap checksum, binary pcap retained locally when `AMHS_EVIDENCE_KEEP_PCAP=1`)

## Evidence mapping

| Evidence area | Reproducible test coverage |
|---|---|
| BER APDU bind/submit/status/report lifecycle | `P3Asn1GatewayProtocolTest.mapsBindAndSubmitAndStatusToSessionService` |
| RTSE bind/submit style wrapping | `P3Asn1GatewayProtocolTest.unwrapsRtseRtorqAndReturnsRtoacWithGatewayPayload`, `P3Asn1GatewayProtocolTest.unwrapsRtseRttdAndReturnsRttrWithRosePayload` |
| RTSE release mapping | `P3Asn1GatewayProtocolTest.mapsRtabToReleaseResponse` |
| Association bind/submit/release deterministic lifecycle | `P3GatewaySessionServiceTest.bindSubmitAndUnbindFlowReturnsDeterministicSubmissionId` |
| Status/report behavior and correlation diagnostics | `P3GatewaySessionServiceTest` status/report scenarios in the same suite |
| ROSE and malformed APDU negative vectors | `P3Asn1GatewayProtocolNegativeVectorsTest` |

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

The campaign writes `*-diagnostics-summary.txt` for quick inspection and keeps full raw logs in `*-run.log`.

## Notes

- This campaign is intentionally transport/profile focused and does not claim full native mailbox semantics of complete ISODE P3 stacks.
- The evidence command is deterministic and CI-safe for repeated execution.


## Signed campaign report and replay

Each run emits a signed campaign report and ledger to satisfy PICS §7.1.2 work package 3 requirements:

- signed report includes deterministic replay instructions, sign-off record references, and artifact manifest linkage;
- verdict ledger records certified and heterogeneous stack verdicts for bind/submit/status/report/release;
- decoded trace provides human-readable packet transcript generated from deterministic campaign pcap.
