# P1 DR/NDR interoperability trace ledger (20260308T195506Z)

This ledger captures deterministic cross-peer DR/NDR evidence chain semantics bound to release R2026.03.

## Correlation invariants

- related_mts_identifier and correlation_token are persisted for every DR/NDR report.
- Correlation token is deterministic: <message-id>::<mts-id> when both are present, otherwise MSG::<message-id> / MTS::<mts-id>.
- NDR APDUs are BER-encoded with X.411 application tag identity validation.

## Cross-peer trace matrix

| Peer profile | Trigger vector | Expected report | Correlation proof | Semantic proof |
|---|---|---|---|---|
| ENAV-OPS | Accepted relay transfer | DR / DELIVERED | MSG-1::MTS-1 stable linkage | createsCorrelatedDeliveryReport |
| MIL-NET | Peer unreachable transfer path | NDR / FAILED | MSG::MSG-2 fallback linkage | mapsTransferFailureDiagnosticsForNdr (X411:22) |
| CERTIFIED-AMHS-LAB | Mixed recipients (failed + deferred + delivered) | NDR per failing/deferred recipient | Shared message correlation over per-recipient reports | createsPerRecipientReportsForMixedOutcome |
| METEO-LEGACY | Legacy IA5 + textual status encoding | NDR decode parity preserved | MTS identifier recovery from legacy form | decodesLegacyIa5AndStatusNameFormatForBackwardCompatibility |

## End-to-end chain coverage

1. Ingress/transfer outcome is converted to DR/NDR semantic status.
2. Correlation fields are written on persisted report entities.
3. NDR BER payload is encoded and profile-validated (tag class/number).
4. Decoding path accepts both canonical and legacy peer encodings.

## Executed suites

- it.amhs.service.AMHSDeliveryReportServiceTest
- it.amhs.service.X411DeliveryReportApduCodecTest
- it.amhs.service.P1AssociationProtocolTest
- it.amhs.service.Rfc1006OutboundP1ClientTest
