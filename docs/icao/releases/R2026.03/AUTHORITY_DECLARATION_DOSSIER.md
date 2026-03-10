# Authority-Facing Declaration Dossier (`R2026.03`)

Document status: **release package index for authority submission (transition-governed profile-complete claim scope)**.

## 1. Purpose

This dossier packages the release `R2026.03` declaration evidence into authority-facing sections required for the external **profile-complete claim**, subject to the governance transition gate defined in `docs/icao/PICS.md` §5.5 and `docs/icao/ICAO_EXTERNAL_P3_NONCLAIM_BOUNDARY_ACCEPTANCE.md`:

1. Technical evidence
2. Security evidence
3. Operational controls
4. Residual-risk approvals

## 2. Release binding and claim scope wording

- Release: `R2026.03`
- Configuration fingerprint: `docs/icao/releases/R2026.03/CONFIGURATION_FINGERPRINT.txt`
- Declaration artifact manifest: `docs/icao/releases/R2026.03/DECLARATION_ARTIFACT_MANIFEST.txt`
- Release-bound PICS: `docs/icao/releases/R2026.03/PICS_R2026.03.md`
- Release-bound PIXIT: `docs/icao/releases/R2026.03/PIXIT_R2026.03.md`
- Claim scope statement: release `R2026.03` is governed by a transition from declared baseline + external non-claim boundary to profile-complete external claim wording, with release-bound campaign evidence required before retirement/narrowing of the external non-claim control.

## 2.1 Governance transition gate for profile-complete declaration wording

- Transition gate: retain the external non-claim boundary as the governing declaration control until ACSE/presentation breadth, full X.411/P3 external semantics, and ASN.1 runtime breadth hardening are fully implemented and objectively evidenced in a release-bound dossier.
- Retire or narrow the current external non-claim boundary only after the above technical breadth is implemented and evidenced.
- Re-issue declaration matrices and this authority dossier with explicit profile-complete scope wording and associated campaign evidence when the gate closes.

## 3. Technical evidence package

- `docs/icao/CONFORMANCE_TEST_MATRIX.md`
- `docs/icao/ICAO_ATN_PROFILE_REQUIREMENT_TRACEABILITY.md`
- `docs/icao/X411_MODULE_TRACEABILITY.md`
- `docs/icao/releases/R2026.03/evidence/p3-negative-apdu/latest-manifest.txt`
- `docs/icao/releases/R2026.03/evidence/p1-dr-ndr-interop/latest-manifest.txt`
- `docs/icao/releases/R2026.03/evidence/italy-national-interop/latest-manifest.txt`
- `docs/icao/releases/R2026.03/evidence/p3-multi-vendor/latest-manifest.txt`
- `docs/icao/releases/R2026.03/evidence/p3-multi-vendor/20260308T203149Z-signed-campaign-report.md`

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
- `docs/icao/AUTHORITY_READY_DOSSIER_R2026.03.md`
- `docs/icao/P3_SERVICE_EXTERNAL_DECLARATION_MATRIX.md`
- `docs/icao/ACSE_PRESENTATION_NEGOTIATION_MATRIX.md`

## 7. Submission gate checklist

- [x] Release-bound PICS/PIXIT published and linked to configuration fingerprint.
- [x] Single-source conformance map rows link every declaration statement to executable artifacts and governing document sections.
- [x] Technical, security, and operational evidence sections assembled for authority review.
- [x] Residual-risk approvals and governance acceptance records linked.
- [x] Governance transition gate from non-claim boundary to profile-complete declaration wording is explicitly documented.
- [x] Associated multi-vendor and negative-vector campaign evidence is bound to the release package.
