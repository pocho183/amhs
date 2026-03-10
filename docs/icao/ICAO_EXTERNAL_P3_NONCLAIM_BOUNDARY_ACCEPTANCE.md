# ICAO External P3 Non-Claim Boundary and Authority Acceptance Record

Document status: **external-claim boundary closure baseline** for release `R2026.03`.

## 1. Purpose

This document closes the PICS `§5.3` item 7 action by formalizing, for ICAO external-claim posture, the non-claim boundaries for P3 semantics and the required authority acceptance workflow.

Closure mode for this release is:

- **non-claim boundary formalization + authority acceptance**,
- not a declaration of profile-complete external P3 semantics.

## 2. Scope and release binding

This boundary record applies only to the release baseline bound to:

- `docs/icao/releases/R2026.03/CONFIGURATION_FINGERPRINT.txt`
- `docs/icao/releases/R2026.03/P3_INTERNAL_PROFILE_STATEMENT.md`
- `docs/icao/PIXIT.md`
- `docs/icao/PICS.md`

Any release/fingerprint change requires re-approval and a new boundary record revision.

## 3. External P3 semantics claim boundary

## 3.1 What is positively claimed for external declaration posture

1. Deterministic gateway semantics for bind/submit/status/report/release operation set.
2. Deterministic negative diagnostics for unsupported or malformed gateway/ROSE/RTSE vectors in the declared gateway profile.
3. Deterministic association lifecycle semantics (single-bind policy, release-state behavior).

## 3.2 What is explicitly not claimed as external profile-complete P3 conformance

1. Full profile-complete external P3 endpoint semantics beyond the declared gateway operation set.
2. Exhaustive ACSE/presentation/session interoperability semantics for all peer profile permutations.
3. Any external claim that unsupported operations are implemented through equivalent behavior.

## 3.3 Boundary handling rule for declaration text

All authority-facing ICAO external declaration artifacts for this release must include this normative sentence (or stricter equivalent):

> "Release `R2026.03` declares deterministic gateway-profile P3 semantics only for the supported bind/submit/status/report/release operation set; profile-complete external P3 endpoint semantics are not claimed in this declaration."

## 4. Authority acceptance package requirements

A boundary is considered accepted only when all records below are completed for the same release/fingerprint:

1. Operations owner sign-off that operational procedures match the declared boundary.
2. Security owner sign-off that security controls/risk treatment match boundary scope.
3. Engineering owner sign-off that implemented behavior and evidence match declared claim limits.
4. Accountable authority sign-off explicitly accepting the non-claim boundary and residual risk.

## 5. Acceptance register (release-bound)

| Release | Fingerprint ref | Boundary document ref | Operations | Security | Engineering | Accountable authority | Date (UTC) | Result |
|---|---|---|---|---|---|---|---|---|
| R2026.03 | `docs/icao/releases/R2026.03/CONFIGURATION_FINGERPRINT.txt` | `docs/icao/ICAO_EXTERNAL_P3_NONCLAIM_BOUNDARY_ACCEPTANCE.md` | Pending | Pending | Pending | Pending | - | Draft baseline |

## 6. Objective evidence pointers supporting boundary integrity

- P3 supported/unsupported operation semantics and deterministic diagnostics: `docs/icao/releases/R2026.03/P3_INTERNAL_PROFILE_STATEMENT.md`.
- ACSE/presentation negotiated behavior matrix for declaration vectors: `docs/icao/ACSE_PRESENTATION_NEGOTIATION_MATRIX.md`.
- Multi-vendor bind/submit/status/report/release evidence pack: `docs/icao/MULTI_VENDOR_BIND_SUBMIT_STATUS_REPORT_RELEASE_EVIDENCE.md`.
- Conformance matrix rows and verdict links: `docs/icao/CONFORMANCE_TEST_MATRIX.md`.

## 7. Closure statement

PICS `§5.3` item 7 ("Complete profile-complete P3 semantics evidence (or formalize non-claim boundaries with authority acceptance)") is **closed for release `R2026.03` by the non-claim path** through this document and the required authority acceptance register workflow.

## 8. Maintenance rule

For each subsequent release:

1. Revalidate claim/non-claim boundary against implementation and evidence.
2. Update release/fingerprint references.
3. Update acceptance register with completed approvals.
4. Keep PICS/PIXIT wording aligned with this boundary record.

## 9. Governance transition guardrail

Retirement or narrowing of this external non-claim boundary is permitted only after profile-complete technical breadth is implemented and objectively evidenced, specifically including ACSE/presentation breadth completion, full X.411/P3 external semantics completion, and runtime ASN.1 breadth hardening as tracked in `docs/icao/PICS.md` §5.5.

Until that condition is met, this boundary remains the normative control for authority-facing external declaration scope.
