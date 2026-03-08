# P1 DR/NDR interoperability trace ledger (20260308T201153Z)

This ledger captures deterministic cross-peer DR/NDR evidence chain semantics bound to release R2026.03.

## Correlation invariants

- related_mts_identifier and correlation_token are persisted for every DR/NDR report.
- Correlation token is deterministic: <message-id>::<mts-id> when both are present, otherwise MSG::<message-id> / MTS::<mts-id>.
- NDR APDUs are BER-encoded with X.411 application tag identity validation.

## Cross-peer trace matrix

| Scenario ID | Peer profile | Trigger vector | Queue state | Expected report | Correlation ID | Peer acknowledgment | Semantic proof |
|---|---|---|---|---|---|---|---|
| SCN-DELIVERY-SUCCESS | ENAV-OPS | Accepted relay transfer | TRANSFERRED | DR / DELIVERED | MSG-1::MTS-1 | P1-ACK-250 (positive transfer ack) | createsCorrelatedDeliveryReport |
| SCN-NON-DELIVERY | MIL-NET | Peer unreachable transfer path | FAILED | NDR / FAILED | MSG::MSG-2 | P1-REJ-550 (negative transfer ack) | mapsTransferFailureDiagnosticsForNdr (X411:22) |
| SCN-DELAY | CERTIFIED-AMHS-LAB | Temporary congestion recipient outcome | DEFERRED | NDR / DEFERRED | MSG-4::MTS-4 | P1-ACK-451 (deferred recipient ack) | createsPerRecipientReportsForMixedOutcome (X411:28) |
| SCN-REDIRECTION | METEO-LEGACY | Redirection loop detected | FAILED | NDR / FAILED | MSG::MSG-REDIR-1 | P1-REJ-554 (redirection loop reject) | mapsRedirectionLoopDiagnosticsForNdr (X411:21) |
| SCN-TRANSFER-FAILURE | MIL-NET | End-to-end transfer failure with fallback addressing | FAILED | NDR / FAILED | MSG::MSG-TF-1 | P1-REJ-553 (transfer-failure reject) | mapsTransferFailureDiagnosticsForNdr (X411:22) |

## Cross-peer trace chain ledger

| Scenario ID | ingress event | queue state transition | emitted DR/NDR | peer acknowledgment | correlation ID |
|---|---|---|---|---|---|
| SCN-DELIVERY-SUCCESS | `ingress.accepted(MSG-1,MTS-1)` | `SUBMITTED → TRANSFERRED → DELIVERED` | `DR:DELIVERED` | `ENAV-OPS:P1-ACK-250` | `MSG-1::MTS-1` |
| SCN-NON-DELIVERY | `ingress.transfer-attempt(MSG-2)` | `SUBMITTED → FAILED → REPORTED` | `NDR:FAILED (X411:22)` | `MIL-NET:P1-REJ-550` | `MSG::MSG-2` |
| SCN-DELAY | `ingress.partial-recipient-outcome(MSG-4,MTS-4)` | `SUBMITTED → DEFERRED → REPORTED` | `NDR:DEFERRED (X411:28)` | `CERTIFIED-AMHS-LAB:P1-ACK-451` | `MSG-4::MTS-4` |
| SCN-REDIRECTION | `ingress.redirect-loop(MSG-REDIR-1)` | `SUBMITTED → FAILED → REPORTED` | `NDR:FAILED (X411:21)` | `METEO-LEGACY:P1-REJ-554` | `MSG::MSG-REDIR-1` |
| SCN-TRANSFER-FAILURE | `ingress.transfer-failure(MSG-TF-1)` | `SUBMITTED → FAILED → REPORTED` | `NDR:FAILED (X411:22)` | `MIL-NET:P1-REJ-553` | `MSG::MSG-TF-1` |

## End-to-end chain coverage

1. Ingress/transfer outcome is converted to DR/NDR semantic status.
2. Correlation fields are written on persisted report entities.
3. NDR BER payload is encoded and profile-validated (tag class/number).
4. Decoding path accepts both canonical and legacy peer encodings.

## Executed suites

- it.amhs.service.AMHSDeliveryReportServiceTest
- it.amhs.service.X411DiagnosticMapperTest
- it.amhs.service.X411DeliveryReportApduCodecTest
- it.amhs.service.P1AssociationProtocolTest
- it.amhs.service.Rfc1006OutboundP1ClientTest
