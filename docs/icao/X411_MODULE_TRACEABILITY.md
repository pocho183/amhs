# X.411 Module Traceability Baseline

This document provides a **module-traceability baseline** for the current AMHS implementation, linking runtime tag maps and parser checks to X.411-oriented APDU/envelope structures used by the stack.

> Scope note: this is a pragmatic implementation traceability artifact and not a replacement for a full formal ASN.1-generated conformance package.
> Certification note: current runtime APDU identifiers are **context-specific profile tags** used by this stack and are not claimed to be the canonical ITU-T X.411 APPLICATION-tag assignment.

## 1) Association APDU tags

Runtime source of truth: `src/main/java/it/amhs/service/X411TagMap.java`.

| Runtime constant | Tag | Meaning in implementation profile |
|---|---:|---|
| `APDU_BIND` | 0 | Bind request APDU |
| `APDU_TRANSFER` | 1 | Transfer APDU |
| `APDU_RELEASE` | 2 | Release APDU |
| `APDU_ABORT` | 3 | Abort APDU |
| `APDU_ERROR` | 4 | Error APDU |
| `APDU_BIND_RESULT` | 10 | Bind result APDU |
| `APDU_RELEASE_RESULT` | 11 | Release result APDU |
| `APDU_TRANSFER_RESULT` | 12 | Transfer result APDU |

Validation hooks:
- `X411TagMap.validateAssociationApduTag(int)`
- `P1AssociationProtocol.decode(...)`

## 2) Bind field tags

Runtime source of truth: `X411TagMap` + `P1AssociationProtocol.decodeBind(...)`.

| Runtime constant | Tag | Field |
|---|---:|---|
| `BIND_CALLING_MTA` | 0 | Calling MTA |
| `BIND_CALLED_MTA` | 1 | Called MTA |
| `BIND_ABSTRACT_SYNTAX` | 2 | Abstract syntax OID |
| `BIND_PROTOCOL_VERSION` | 3 | Protocol version |
| `BIND_AUTHENTICATION` | 4 | Authentication parameters |
| `BIND_SECURITY` | 5 | Security parameters |
| `BIND_MTS_APDU` | 6 | MTS APDU container presence |
| `BIND_PRESENTATION_CONTEXT` | 7 | Presentation context presence |

Hardening now in place:
- Unknown context-specific bind field tags are rejected.

## 3) Transfer envelope field tags

Runtime source of truth: `X411TagMap` + `P1BerMessageParser.parseTransferEnvelope(...)`.

| Runtime constant | Tag | Field |
|---|---:|---|
| `ENVELOPE_MTS_IDENTIFIER` | 0 | MTS identifier |
| `ENVELOPE_PER_RECIPIENT` | 1 | Per-recipient fields |
| `ENVELOPE_TRACE` | 2 | Trace information |
| `ENVELOPE_CONTENT_TYPE` | 3 | Content type OID |
| `ENVELOPE_ORIGINATOR` | 4 | Originator ORName |
| `ENVELOPE_SECURITY_PARAMETERS` | 5 | Security parameters |
| `ENVELOPE_EXTENSIONS` | 6 | Extension anchor |

Hardening now in place:
- Known envelope tags are recognized explicitly.
- Context tags greater than extension anchor are captured as unknown extensions.
- Unsupported non-extension context tags are rejected.


## 4) ORName and DirectoryName CHOICE coverage

Runtime source of truth: `src/main/java/it/amhs/service/ORNameMapper.java`.

Implemented CHOICE/runtime behaviors:
- `ORName ::= [0] DirectoryName` (directoryName-only): decoded and mapped to canonical textual directory form; parser provides CN fallback for internal O/R representation.
- `ORName ::= [1] ORAddress` (or-address-only): decoded from structured or legacy IA5 forms.
- Combined structured container carrying both directoryName and ORAddress: decoded with precedence on explicit ORAddress attributes.

Directory string interoperability now handled:
- TeletexString (T.61 approximation), BMPString, and UniversalString decoding.
- X.500-style DistinguishedName parsing (`SEQUENCE OF SET OF SEQUENCE { type OID, value }`) with common attribute OID mapping (`CN`, `C`, `O`, `OU`, ...).

Evidence tests:
- `src/test/java/it/amhs/service/ORNameMapperTest.java`


## 5) DR/NDR BER evidence hooks

Runtime source of truth: `X411DeliveryReportApduCodec` + `AMHSDeliveryReportService` + `AMHSDeliveryReport`.

Implemented evidence controls:
- NDR APDU bytes are encoded once and stored as raw BER hex (`ndr_apdu_raw_ber`) with tag class/number metadata.
- Encoded NDR APDU is validated before persistence (`validateEncodedNonDeliveryReport`) for required profile fields and APDU tag identity.
- Persisted metadata can be exported during conformance campaigns as wire-evidence artifacts.

Boundary note:
- This does **not** by itself prove canonical X.411 ASN.1 module numbering; it proves deterministic conformance to the stack profile table in this document.

## 6) Current conformance posture

- Tag-level mapping traceability: **implemented**.
- Runtime guardrails for unknown APDU/bind/envelope tags: **implemented**.
- Extension-handling freeze (known/unknown rules + backward-compatibility checks): **implemented** (`docs/icao/P1_EXTENSION_HANDLING_POLICY.md`).
- ORName CHOICE and DirectoryName string-family decoding baseline: **implemented**.
- Canonical module-level ASN.1 proof pack for the declared gateway profile: **implemented** (`docs/icao/X411_CANONICAL_ASN1_MODULE_PROOF.md` + executable lock-step tests).
