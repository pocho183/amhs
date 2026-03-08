# Negotiation and error semantics closure evidence (P3/ACSE)

Timestamp (UTC): `2026-03-08T21:05:00Z`
Release: `R2026.03`

## 1) Packet-level evidence vectors

Source of deterministic vectors: `it.amhs.service.protocol.p3.P3Asn1GatewayProtocolEvidenceTest`.

- Successful bind request APDU (BER hex):
  - `a04f800c616d687375736572810a6368616e6765697482322f433d49542f41444d443d4943414f2f50524d443d454e41562f4f3d454e41562f4f55313d4c4952522f434e3d616c69636583064154464d`
- Successful bind response APDU envelope tag:
  - `a1...` (`[CONTEXT 1]` = `bind-response`)
- Negative invalid APDU vector (primitive context tag):
  - `a000`
- Negative response APDU envelope tag:
  - `a8...` (`[CONTEXT 8]` = `error`)

## 2) Log-level evidence vectors

Source of deterministic log assertions: `it.amhs.service.protocol.p3.P3Asn1GatewayProtocolEvidenceTest`.

Mandatory evidence lines asserted:

- `P3 ASN.1 incoming APDU ... tagNumber=0 ...`
- `P3 ASN.1 bind request fields username=amhsuser ...`
- `P3 ASN.1 bind gateway-response=OK ...`

## 3) ACSE selector/context/authentication matrix closure references

Source of deterministic matrix assertions: `it.amhs.service.protocol.rfc1006.RFC1006ServiceAcseNegotiationMatrixTest`.

Covered vectors:

- `ACSE-MAT-01` valid selector/context/auth (accept)
- `ACSE-MAT-02` context-name mismatch (reject)
- `ACSE-MAT-03` missing AMHS abstract syntax in presentation list (reject)
- `ACSE-MAT-04` selector required when certificate identity present (reject)
- `ACSE-MAT-05` selector/certificate mismatch (reject)
- `ACSE-MAT-06` auth required + missing value (reject)
- `ACSE-MAT-07` auth mismatch (reject)
- `ACSE-MAT-08` missing user-information association payload (reject)
- `ACSE-MAT-09` selector bound to certificate CN (accept)
- `ACSE-MAT-10` selector bound to certificate OU (accept)
- `ACSE-MAT-11` missing presentation context list (reject)
- `ACSE-MAT-12` empty presentation-context OID entry (reject)
- `ACSE-MAT-13` zero-length authentication value (reject)
- `ACSE-MAT-14` authentication required with valid value present (accept)
- `ACSE-MAT-15` expected authentication value exact match (accept)

## 4) Rejection semantics evidence (diagnostic stability)

Source of deterministic diagnostic assertions: `it.amhs.service.protocol.rfc1006.RFC1006ServiceAcseDiagnosticsTest`.

- Rejection with presentation mismatch maps to provider diagnostic pair `(source=1, diagnostic=2)`.
- Rejection with authentication mismatch maps to requestor diagnostic pair `(source=2, diagnostic=1)`.
- Rejected `AARE` envelopes contain both `diagnostic` and `result-source-diagnostic` structures for packet/log correlation.


## 5) Reproducible execution + artifact publication path

Execution script: `scripts/evidence/p3_negative_apdu_regression.sh R2026.03`.

The script now publishes release-bound JUnit XML attachments for:

- `P3Asn1GatewayProtocolEvidenceTest` (packet-level + log-level evidence assertions)
- `P3Asn1GatewayProtocolNegativeVectorsTest` (negative APDU paths)
- `P3Asn1GatewayProtocolTest` (positive/negative gateway protocol semantics)
- `RFC1006ServiceAcseNegotiationMatrixTest` (ACSE-MAT-01..15 selector/context/auth permutations)
- `RFC1006ServiceAcseDiagnosticsTest` (diagnostic source/code stability)
- `CotpConnectionTpduTest` (malformed TPDU vectors)

Artifact index pointer: `docs/icao/releases/R2026.03/evidence/p3-negative-apdu/latest-manifest.txt`.
