# P1 Legacy Encoding Regression Vectors (Operational AMHS Baseline)

Document status: **frozen for `R2026.03` operational compatibility governance**.

## 1. Scope

This vector set captures legacy BER encodings observed in operational AMHS peer environments and binds them to deterministic parser behavior for the declared release profile.

## 2. Regression vector catalogue

| Vector ID | Operational legacy encoding pattern | Expected behavior (frozen) | Executable coverage |
|---|---|---|---|
| LV-BIND-01 | Bind APDU includes non-context legacy noise (universal/application/private class elements) alongside valid context bind fields. | Ignore non-context bind elements; decode profile-known bind fields unchanged. | `P1AssociationProtocolTest.shouldIgnoreOperationalLegacyBindNoiseAcrossTagClasses` |
| LV-BIND-02 | Bind APDU includes unknown context-specific bind tag. | Deterministic reject with `Unsupported P1 bind field tag [<tag>]`. | `P1AssociationProtocolTest.shouldRejectBindWithUnknownContextFieldTag` |
| LV-ENV-01 | Transfer-envelope contains only extension anchor (`[6]`) plus true unknown extension (`[10+]`). | Keep backward compatibility; preserve true unknown extension(s) in `unknownExtensions`. | `P1BerMessageParserTest.shouldKeepBackwardCompatibilityWhenLegacyEnvelopeContainsExtensionAnchorOnly` |
| LV-ENV-02 | Transfer-envelope includes non-context legacy element (e.g., PrintableString / SET wrapper) with unknown extension tags. | Ignore non-context envelope elements; preserve context unknown extensions (`>6`). | `P1BerMessageParserTest.shouldIgnoreLegacyNonContextEnvelopeElementForBackwardCompatibility`, `P1BerMessageParserTest.shouldPreserveMultipleOperationalUnknownEnvelopeExtensions` |
| LV-TEXT-01 | Message textual fields transported as constructed wrappers carrying PrintableString/IA5String payloads. | Decode canonical text values for from/to/body/subject without rejecting payload. | `P1BerMessageParserTest.shouldDecodeLegacyConstructedPrintableAddressingVector` |

## 3. Governance controls

- Vector set is release-bound and immutable for `R2026.03` once signed.
- Any vector addition/removal requires:
  1. update of this file,
  2. executable test coverage update,
  3. traceability row refresh in `ICAO_ATN_PROFILE_REQUIREMENT_TRACEABILITY.md`,
  4. explicit release sign-off.

## 4. Sign-off

| Role | Name | Decision | Date (UTC) |
|---|---|---|---|
| Engineering owner | AMHS Core Team | Approved | 2026-03-08 |
| Compliance owner | AMHS Compliance Team | Approved | 2026-03-08 |
| Operations owner | AMHS Operations Team | Approved | 2026-03-08 |
