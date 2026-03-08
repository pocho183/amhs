# P1 Internal Profile Statement (`R2026.03`)

This release-specific statement freezes the declared P1 relay/interpersonal association subset for `R2026.03` and defines deterministic diagnostics for out-of-subset APDUs.

## 1. Scope and profile boundary

- Scope: inbound P1 association handling on the RFC1006 relay surface.
- Canonical module baseline: `docs/icao/X411_CANONICAL_ASN1_MODULE_PROOF.md`.
- Behavioral contract binding: `docs/icao/contracts/R2026.03/DECLARATION_BEHAVIOR_CONTRACT.md`.

## 2. Supported inbound association APDU subset

| APDU tag | APDU semantic | Inbound support in relay/interpersonal profile |
|---|---|---|
| `[0]` | `bind` | Supported |
| `[1]` | `transfer` | Supported (requires successful bind) |
| `[2]` | `release` | Supported |
| `[3]` | `abort` | Supported |
| `[4]` | `error` | Supported (peer-originated notification) |

## 3. Explicitly unsupported inbound association APDUs

The following canonical APDUs are decoded as known X.411 module members but are unsupported on inbound relay/interpersonal association traffic for this release. They return stable error semantics:

- error code: `unsupported-operation`
- diagnostic string starts with `unsupported-operation:` and includes APDU-specific reason.

| APDU tag | APDU semantic | Stable diagnostic detail |
|---|---|---|
| `[10]` | `bindResult` | `unsupported-operation: bind-result APDU is responder-only in the declared P1 relay/interpersonal profile` |
| `[11]` | `releaseResult` | `unsupported-operation: release-result APDU is responder-only in the declared P1 relay/interpersonal profile` |
| `[12]` | `transferResult` | `unsupported-operation: transfer-result APDU is responder-only in the declared P1 relay/interpersonal profile` |
| `[13]` | `nonDeliveryReport` | `unsupported-operation: non-delivery-report APDU is not accepted on inbound relay association traffic` |
| `[14]` | `deliveryReport` | `unsupported-operation: delivery-report APDU is not accepted on inbound relay association traffic` |

## 4. Release-bound implementation evidence

- Runtime mapping and deterministic diagnostic source:
  - `src/main/java/it/amhs/service/protocol/p1/P1AssociationProtocol.java`
  - `src/main/java/it/amhs/service/protocol/rfc1006/RFC1006Service.java`
- Regression checks:
  - `src/test/java/it/amhs/service/P1AssociationProtocolTest.java`

Any change to this subset or diagnostic text requires a new contract/profile revision for declaration claims.
