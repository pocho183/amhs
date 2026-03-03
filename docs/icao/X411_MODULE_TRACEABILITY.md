# X.411 Module Traceability Baseline

This document provides a **module-traceability baseline** for the current AMHS implementation, linking runtime tag maps and parser checks to X.411-oriented APDU/envelope structures used by the stack.

> Scope note: this is a pragmatic implementation traceability artifact and not a replacement for a full formal ASN.1-generated conformance package.

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

## 4) Current conformance posture

- Tag-level mapping traceability: **implemented**.
- Runtime guardrails for unknown APDU/bind/envelope tags: **implemented**.
- Formal ASN.1 compiler-generated proof package against official X.411 modules: **pending**.

