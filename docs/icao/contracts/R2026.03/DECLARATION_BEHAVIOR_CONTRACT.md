# Declaration Profile Behavior Contract (`R2026.03`)

## 1. Contract status and scope

This document is the normative behavior contract for declaration-profile runtime semantics in release `R2026.03`.

Scope covered by this contract:
- DR/NDR deterministic behavior.
- ACSE reject-path deterministic behavior.
- Unsupported-operation deterministic semantics on P3 gateway surfaces.

A runtime implementation that diverges from the statements below is **non-compliant for release declaration** and must be treated as a **release-blocking compliance defect**.

## 2. Versioning model

- Contract identifier: `DECL-BEHAVIOR-R2026.03`.
- Release binding: `R2026.03` only.
- Change policy:
  - Any semantic change to codes/reasons/diagnostic mappings requires a **new contract version**.
  - Backport-only editorial updates do not change contract semantics.

## 3. Normative behavior contracts

### 3.1 DR/NDR deterministic contract

1. For a given message lifecycle outcome and recipient outcome tuple, DR/NDR report classification and persistence fields must be deterministic.
2. NDR evidence must include protocol correlation material:
   - `related_mts_identifier`
   - `correlation_token`
3. NDR BER/APDU structural metadata (`tag class`, `tag number`) must be persisted when NDR APDU is generated.

## 3.2 ACSE reject-path deterministic contract

1. AARQ rejection paths must emit structured AARE diagnostics.
2. Result-source-diagnostic mapping must be deterministic for a fixed rejection reason string.
3. Presentation-context negotiation failures and authentication failures must map to stable source/diagnostic pairs for this release.

## 3.3 Unsupported-operation deterministic contract

1. Unsupported gateway APDUs and unsupported ROSE operation codes must produce deterministic `unsupported-operation` semantics.
2. Non-invoke ROSE APDUs in invoke-required contexts must produce deterministic ROSE reject behavior.
3. Unsupported RTSE-wrapper payloads must produce deterministic error semantics under the RTSE response wrapper.

## 4. Release gate requirements

Release declaration for `R2026.03` is allowed only when all of the following are true:

1. Contract-linked automated regression tests are passing.
2. Negative-vector campaign artifacts for ACSE reject and unsupported-operation semantics are published in the release evidence manifest.
3. DR/NDR trace chain artifacts prove deterministic correlation behavior for representative success/failure scenarios.

Failure of any gate above is release-blocking for declaration claims.

## 5. Implementation references

The following repository artifacts provide implementation-level and evidence-level traceability for this contract version:

- `src/main/java/it/amhs/service/report/AMHSDeliveryReportService.java`
- `src/main/java/it/amhs/service/protocol/rfc1006/RFC1006Service.java`
- `src/main/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocol.java`
- `src/test/java/it/amhs/service/protocol/rfc1006/RFC1006ServiceAcseDiagnosticsTest.java`
- `src/test/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocolNegativeVectorsTest.java`
- `docs/icao/releases/R2026.03/evidence/p3-negative-apdu/`
- `docs/icao/releases/R2026.03/evidence/p1-dr-ndr-interop/`
