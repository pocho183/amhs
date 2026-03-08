# Italy National-Use Declaration Package (Authority-Facing Baseline)

Document status: **national declaration dossier baseline** for Italy national-use AMHS operations (`R2026.03`).

## 1. Purpose

This package closes the Italy national-use declaration action by providing a single authority-facing dossier that consolidates:

- operational responsibilities and accountable roles,
- security controls (including PKI revocation behavior),
- incident response and failover procedures,
- approval and sign-off records expected by oversight authorities.

This declaration package is release-bound and must be issued with:

- `docs/icao/PICS.md`,
- `docs/icao/PIXIT.md`,
- `docs/icao/ITALY_NATIONAL_USE_REQUIREMENT_MAP.md`,
- `docs/icao/NATIONAL_INTEROP_CAMPAIGN_ITALY.md`,
- `docs/icao/OPERATIONAL_HA_FAILOVER_EVIDENCE_PACK.md`,
- `docs/icao/releases/R2026.03/CONFIGURATION_FINGERPRINT.txt`.

## 2. Operational responsibilities

## 2.1 Responsibility model (RACI-style baseline)

| Domain | Operations Owner | Security Owner | Engineering Owner | Accountable Authority |
|---|---|---|---|---|
| Service availability and continuity | A/R | C | R | I |
| PKI truststore/revocation lifecycle | C | A/R | R | I |
| Incident handling and escalation | R | R | C | A/I |
| Release declaration package publication | R | R | R | A |
| National authority submission | C | C | I | A/R |

Legend: `A` = accountable, `R` = responsible, `C` = consulted, `I` = informed.

## 2.2 Operational minimum obligations

1. Keep a release-bound runbook aligned with `OPERATIONS_GUIDE.md`.
2. Maintain on-call ownership and incident escalation matrix with 24x7 contactability.
3. Preserve audit evidence for at least 24 months (or stricter authority retention rule).
4. Ensure every declaration references an immutable release fingerprint and artifact manifest.

## 3. Security controls declaration (including PKI revocation)

## 3.1 Baseline controls

- TLS/mTLS controls and channel identity policy are enforced by implementation and compliance checks.
- Sender/channel policy constraints remain part of release declarations.
- Security-label enforcement is declared at gateway policy boundary with profile limitations noted in PICS/PIXIT.

## 3.2 PKI revocation behavior declaration

The national-use deployment declares the following revocation behavior baseline:

1. **Trust anchors and intermediate CAs** are managed under change control, release-tagged, and traceable to deployment configuration.
2. **CRL/OCSP checks** are enabled according to environment policy and validated in pre-release verification windows.
3. **Fail-safe handling rule**:
   - revoked certificate verdict => association rejected,
   - explicit revocation responder failure/unreachable/stale status => handled according to declared local policy (`hard-fail` or `controlled soft-fail`) and recorded in risk acceptance.
4. **Responder freshness controls** (CRL nextUpdate / OCSP validity window) must be monitored with alerting and incident triggers.
5. **Revocation exceptions** (temporary override) require time-bounded approval by security owner and accountable authority.

## 3.3 Mandatory PKI evidence set per release

- Truststore fingerprint and CA inventory list.
- Revocation test logs (valid, revoked, stale/unreachable responder scenarios).
- Exception register (if any) with owner, rationale, expiry, and closure status.

## 4. Incident and failover procedures

## 4.1 Incident classes and escalation

| Severity | Trigger examples | Initial response SLA | Escalation path |
|---|---|---|---|
| SEV-1 | Service outage, data-integrity risk, security compromise | 15 minutes | On-call -> Operations owner -> Security owner -> Accountable authority |
| SEV-2 | Partial degradation, delayed routing/reporting | 30 minutes | On-call -> Operations owner |
| SEV-3 | Non-critical anomaly, no operational impact | 1 business day | Ticket queue + weekly governance review |

## 4.2 Failover procedure baseline

Failover execution is governed by the operational HA pack and must include:

1. fault detection timestamp and authorization reference,
2. runbook-driven passive node promotion/restart,
3. post-failover service validation (`bind/submit/status/report` + DR/NDR continuity),
4. measured RTO/RPO and anomaly register,
5. formal post-incident review with CAPA actions.

## 4.3 Incident artifact minimum

Each major incident/failover event must archive:

- UTC timeline,
- service and database logs,
- DR/NDR continuity checks,
- operator actions and approvals,
- closure and corrective-action tracking.

## 5. Authority-facing approvals package

## 5.1 Required approval records

A declaration package is submission-ready only when the following approvals are present for the exact release identifier:

1. Operations owner sign-off.
2. Security owner sign-off (including PKI/revocation policy confirmation).
3. Engineering owner sign-off for implementation/evidence consistency.
4. Accountable authority approval for national-use declaration and residual-risk acceptance.

## 5.2 Approval register template

| Release | Artifact manifest ref | Operations | Security | Engineering | Accountable authority | Date (UTC) | Result |
|---|---|---|---|---|---|---|---|
| R2026.03 | `docs/icao/releases/R2026.03/evidence/italy-national-interop/latest-manifest.txt` | Approved (`OPS-IT-001`) | Approved (`SEC-IT-002`) | Approved (`ENG-IT-003`) | Approved (`AUTH-IT-004`) | 2026-03-08T15:05:00Z | Approved with declared environment warning |

## 5.3 Submission bundle checklist

- [x] PICS + PIXIT bound to same release fingerprint.
- [x] Requirement map + interoperability campaign evidence attached.
- [x] Security controls sheet with PKI revocation behavior and exception statement.
- [x] Incident/failover readiness pack and latest drill report.
- [x] Signed approval register row for the release (`docs/icao/releases/R2026.03/evidence/italy-national-interop/20260308T150500Z-approval-register.md`).

## 6. Closure statement (PICS §5.2 item 6)

PICS §5.2 item 6 (“Produce a national declaration package: operational responsibilities, security controls (PKI revocation behavior included), incident/failover procedures, and authority-facing approvals.”) is **closed** for baseline release `R2026.03` by this document.

## 7. Maintenance rule

For each future release:

1. Duplicate/update this declaration with release-specific references.
2. Update approval register row and signatures.
3. Link new evidence manifests and failover drill outputs.
4. Update PICS/requirement map closure status if declaration scope changes.
