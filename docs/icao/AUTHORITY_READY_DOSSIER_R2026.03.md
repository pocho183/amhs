# Authority-Ready Oversight Dossier (R2026.03)

Document status: **submission-ready oversight dossier index** for release `R2026.03`.

## 1. Dossier objective

This dossier assembles the authority-facing work packages into one indexable release bundle so oversight teams can review conformance, assurance evidence, and approvals without cross-document hunting.

Included work packages:

1. Technical conformance evidence.
2. Operational assurance pack.
3. Security assurance pack.
4. Governance approvals.
5. Change-impact delta from prior declared release for revalidation scope.

## 2. Release and revalidation metadata

| Field | Value |
|---|---|
| Declared release | `R2026.03` |
| Configuration fingerprint anchor | `docs/icao/releases/R2026.03/CONFIGURATION_FINGERPRINT.txt` |
| Authority declaration dossier package | `docs/icao/releases/R2026.03/AUTHORITY_DECLARATION_DOSSIER.md` |
| Prior declared release in this repository | `NONE (initial declared oversight baseline)` |
| Revalidation mode | `full baseline revalidation (no prior declared delta source available)` |
| Dossier owner | Operations + Security + Engineering joint declaration |

## 3. Indexable evidence register

| Package ID | Work package | Authority question answered | Indexed artifacts |
|---|---|---|---|
| TC-01 | Technical conformance evidence | Is implementation/profile conformance declared, traceable, and reproducibly tested? | `docs/icao/PICS.md`; `docs/icao/PIXIT.md`; `docs/icao/releases/R2026.03/PICS_R2026.03.md`; `docs/icao/releases/R2026.03/PIXIT_R2026.03.md`; `docs/icao/CONFORMANCE_TEST_MATRIX.md`; `docs/icao/ICAO_ATN_PROFILE_REQUIREMENT_TRACEABILITY.md`; `docs/icao/X411_MODULE_TRACEABILITY.md`; `docs/icao/ICAO_INTEROPERABILITY_CLOSURE_EVIDENCE.md`; `docs/icao/releases/R2026.03/P3_INTERNAL_PROFILE_STATEMENT.md`; `docs/icao/releases/R2026.03/evidence/p3-negative-apdu/latest-manifest.txt`; `docs/icao/releases/R2026.03/evidence/italy-national-interop/latest-manifest.txt`. |
| OA-01 | Operational assurance pack | Is service operation resilient, measured, and runbook-governed for release use? | `docs/icao/OPERATIONAL_HA_FAILOVER_EVIDENCE_PACK.md`; `OPERATIONS_GUIDE.md`; `docs/icao/releases/R2026.03/evidence/operational-assurance/README.md`; `docs/icao/releases/R2026.03/evidence/operational-assurance/latest-manifest.txt`; failover/SLO/backup/performance artifacts under `docs/icao/releases/R2026.03/evidence/operational-assurance/`. |
| SA-01 | Security assurance pack | Are PKI, labels, negotiation, and security boundary controls declared with evidence? | `docs/icao/ATN_PKI_SECURITY_LABEL_EVIDENCE.md`; `docs/icao/ACSE_PRESENTATION_NEGOTIATION_MATRIX.md`; `docs/icao/ICAO_EXTERNAL_P3_NONCLAIM_BOUNDARY_ACCEPTANCE.md`; `docs/icao/releases/R2026.03/evidence/security-pki-label/README.md`. |
| GOV-01 | Governance approvals | Is accountable approval recorded for authority submission and residual risk acceptance? | `docs/icao/ITALY_NATIONAL_DECLARATION_PACKAGE.md`; `docs/icao/releases/R2026.03/evidence/italy-national-interop/20260308T150500Z-approval-register.md`; `docs/icao/releases/R2026.03/evidence/operational-assurance/20260308T141500Z-safety-security-residual-risk-acceptance.md`. |

## 4. Work package assembly checklist (submission gate)

- [x] All package references resolve to release-bound artifacts.
- [x] Technical conformance section includes declaration + reproducible regression evidence manifests.
- [x] Operational assurance section includes failover, resilience, and restore verification outputs.
- [x] Security assurance section includes PKI/security-label and protocol-boundary declarations.
- [x] Governance section includes authority-facing approvals and residual-risk acceptance record.
- [x] Configuration fingerprint anchor is present for immutable release binding.

## 5. Change-impact delta for oversight revalidation

## 5.1 Delta baseline statement

Because this repository contains a single declared release (`R2026.03`), there is no prior declared release package to compute an incremental artifact-by-artifact delta. Therefore, this dossier declares **baseline/full impact** and requires complete oversight revalidation for this submission.

## 5.2 Impact delta table (prior declared release -> R2026.03)

| Domain | Prior declared release state | R2026.03 state | Change impact | Oversight revalidation implication |
|---|---|---|---|---|
| Conformance declaration corpus | Not previously declared | PICS/PIXIT/traceability/matrices published and cross-referenced | High (new declared baseline) | Review full conformance declaration set end-to-end. |
| Interoperability and negative-vector evidence | Not previously declared | Deterministic interop + negative APDU manifests published | High (new declared baseline) | Revalidate reproducibility, logs, and verdict determinism. |
| Operational assurance artifacts | Not previously declared | Failover drill, monitoring, SLO, restore and resilience artifacts published | High (new declared baseline) | Revalidate operational readiness and continuity controls. |
| Security assurance declaration | Not previously declared | PKI/security-label and boundary/negotiation evidence declared | High (new declared baseline) | Revalidate trust, revocation, and security-boundary controls. |
| Governance/approval records | Not previously declared | Signed approval register and risk acceptance captured | High (new declared baseline) | Revalidate sign-off chain and accountable authority acceptance. |

## 5.3 Delta method for next release

For the next declared release (`R_next`), publish an explicit prior-to-current delta annex containing:

1. Added/removed/modified artifacts by package ID (`TC`, `OA`, `SA`, `GOV`).
2. Configuration fingerprint change summary.
3. New/retired claims and affected control owners.
4. Risk posture delta with revalidation scope recommendation (`full` vs `targeted`).

## 6. Authority submission statement

Release `R2026.03` is packaged as one indexable oversight dossier through this document and its referenced evidence artifacts. The declared scope is submission-ready as a baseline release with full revalidation expected due to absence of a prior declared release baseline in repository history.
