# Authority-Facing Declaration Dossier (`R2026.03`)

Document status: **release package index for authority submission**.

## 1. Purpose

This dossier packages the release `R2026.03` declaration evidence into authority-facing sections required before any external conformance claim:

1. Technical evidence
2. Security evidence
3. Operational controls
4. Residual-risk approvals

## 2. Release binding

- Release: `R2026.03`
- Configuration fingerprint: `docs/icao/releases/R2026.03/CONFIGURATION_FINGERPRINT.txt`
- Declaration artifact manifest: `docs/icao/releases/R2026.03/DECLARATION_ARTIFACT_MANIFEST.txt`
- Release-bound PICS: `docs/icao/releases/R2026.03/PICS_R2026.03.md`
- Release-bound PIXIT: `docs/icao/releases/R2026.03/PIXIT_R2026.03.md`

## 3. Technical evidence package

- `docs/icao/CONFORMANCE_TEST_MATRIX.md`
- `docs/icao/ICAO_ATN_PROFILE_REQUIREMENT_TRACEABILITY.md`
- `docs/icao/X411_MODULE_TRACEABILITY.md`
- `docs/icao/releases/R2026.03/evidence/p3-negative-apdu/latest-manifest.txt`
- `docs/icao/releases/R2026.03/evidence/p1-dr-ndr-interop/latest-manifest.txt`
- `docs/icao/releases/R2026.03/evidence/italy-national-interop/latest-manifest.txt`

## 4. Security evidence package

- `docs/icao/ATN_PKI_SECURITY_LABEL_EVIDENCE.md`
- `docs/icao/ATN_PKI_RUNTIME_ENFORCEMENT_ASSURANCE.md`
- `docs/icao/ACSE_PRESENTATION_NEGOTIATION_MATRIX.md`
- `docs/icao/releases/R2026.03/evidence/security-pki-label/README.md`
- `docs/icao/releases/R2026.03/evidence/atn-pki-runtime-enforcement/latest-manifest.txt`

## 5. Operational controls package

- `OPERATIONS_GUIDE.md`
- `docs/icao/OPERATIONAL_HA_FAILOVER_EVIDENCE_PACK.md`
- `docs/icao/releases/R2026.03/evidence/operational-assurance/latest-manifest.txt`
- `docs/icao/releases/R2026.03/evidence/operational-assurance/20260308T141500Z-slo-declaration.md`
- `docs/icao/releases/R2026.03/evidence/operational-assurance/20260308T141500Z-monitoring-export-summary.md`

## 6. Residual-risk approvals and governance

- `docs/icao/releases/R2026.03/evidence/italy-national-interop/20260308T150500Z-approval-register.md`
- `docs/icao/releases/R2026.03/evidence/operational-assurance/20260308T141500Z-safety-security-residual-risk-acceptance.md`
- `docs/icao/ICAO_EXTERNAL_P3_NONCLAIM_BOUNDARY_ACCEPTANCE.md`
- `docs/icao/AUTHORITY_READY_DOSSIER_R2026.03.md`

## 7. Submission gate checklist

- [x] Release-bound PICS/PIXIT published and linked to configuration fingerprint.
- [x] Declaration package is pinned to release tag `R2026.03`, immutable commit SHA, runtime profile hash, and declaration artifact manifest digest.
- [x] Release CI gate (`scripts/release/verify_declaration_gate.sh`) blocks declaration publication when required artifact manifests are missing.
- [x] Conformance matrix rows linked to executable tests/scripts and evidence artifacts.
- [x] Technical, security, and operational evidence sections assembled for authority review.
- [x] Residual-risk approvals and governance acceptance records linked.
