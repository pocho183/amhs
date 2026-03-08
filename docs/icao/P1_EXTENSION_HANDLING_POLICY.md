# P1 Extension Handling Policy (Known + Unknown Elements)

Document status: **frozen for `R2026.03` technical closure**.

## 1. Scope

This policy freezes how the AMHS gateway handles extensibility in P1 association and X.411 transfer-envelope structures for the declared release profile.

## 2. Normative handling rules

### 2.1 Association bind elements (`P1AssociationProtocol.decodeBind`)

- **Known context-specific bind tags** (`0..7` as mapped in `X411TagMap`) are accepted and decoded.
- **Unknown context-specific bind tags** are rejected deterministically with:
  - `IllegalArgumentException("Unsupported P1 bind field tag [<tag>]")`
- **Non-context bind elements** are ignored for backward compatibility and do not alter decoded profile semantics.

### 2.2 Transfer-envelope elements (`P1BerMessageParser.parseTransferEnvelope`)

- **Known context-specific envelope tags** (`0..6` as mapped in `X411TagMap`) are accepted as profile-known fields.
- **Unknown context-specific tags greater than extension anchor (`tag > 6`)** are preserved in `unknownExtensions` for forward compatibility.
- **Non-context envelope elements** are ignored for backward compatibility.

### 2.3 Criticality model

- In this profile, no explicit criticality bit is modeled for unknown P1/X.411 extension containers.
- Unknown-extension payload substructures (including peer-defined criticality indicators) are treated as opaque bytes and are not reinterpreted by this release profile.
- Safety posture:
  - association-level unknown context tags => reject (fail-fast on control-plane uncertainty)
  - envelope unknown extension tags (`>6`) => preserve (data-plane forward compatibility)

## 3. Backward-compatibility checks (release-bound)

The following regression checks are mandatory for `R2026.03` and later unless superseded by a signed policy change. Operational legacy vectors are catalogued in `docs/icao/P1_LEGACY_ENCODING_REGRESSION_VECTORS.md` and are part of this freeze baseline:

1. Bind decoding tolerates legacy non-context elements without altering accepted profile fields.
2. Bind decoding rejects unknown context-specific tags deterministically.
3. Envelope parsing preserves unknown extension tags (`>6`) in `unknownExtensions`.
4. Envelope parsing ignores legacy non-context envelope elements.
5. Envelope parsing accepts extension-anchor-only legacy encodings and still preserves true unknown extensions.
6. Envelope parsing preserves high-tag-number unknown extensions (`>=31`) without payload mutation.
7. Envelope parsing keeps peer-defined unknown-extension criticality markers opaque and byte-preserved.


## 4. Governance freeze controls

- Freeze baseline for `R2026.03` includes:
  - normative behavior in this policy,
  - executable compatibility checks in `P1AssociationProtocolTest` and `P1BerMessageParserTest`,
  - operational vector catalogue in `docs/icao/P1_LEGACY_ENCODING_REGRESSION_VECTORS.md`.
- Any change to known/unknown handling semantics or criticality posture requires:
  1. policy diff in this file,
  2. vector catalogue update,
  3. traceability map refresh,
  4. signed release governance approval.

## 5. Evidence links

- Runtime implementation:
  - `src/main/java/it/amhs/service/protocol/p1/P1AssociationProtocol.java`
  - `src/main/java/it/amhs/service/protocol/p1/P1BerMessageParser.java`
  - `src/main/java/it/amhs/service/protocol/p1/X411TagMap.java`
- Regression tests:
  - `src/test/java/it/amhs/service/P1AssociationProtocolTest.java`
  - `src/test/java/it/amhs/service/P1BerMessageParserTest.java`
- Traceability baseline:
  - `docs/icao/X411_MODULE_TRACEABILITY.md`
  - `docs/icao/ICAO_ATN_PROFILE_REQUIREMENT_TRACEABILITY.md`
  - `docs/icao/P1_LEGACY_ENCODING_REGRESSION_VECTORS.md`

## 6. Sign-off

| Role | Name | Decision | Date (UTC) |
|---|---|---|---|
| Engineering owner | AMHS Core Team | Approved | 2026-03-08 |
| Compliance owner | AMHS Compliance Team | Approved | 2026-03-08 |
| Security owner | AMHS Security Team | Approved | 2026-03-08 |

Policy changes after `R2026.03` require a versioned update to this file and a new sign-off row per release.
