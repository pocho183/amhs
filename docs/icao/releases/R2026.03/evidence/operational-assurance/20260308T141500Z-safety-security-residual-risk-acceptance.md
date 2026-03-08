# Safety/Security Assessment and Residual-Risk Acceptance (R2026.03)

- Release baseline: `R2026.03`
- Assessment scope: AMHS P1/RFC1006 service, gateway-profile P3 ingress/egress, operational control plane
- Assessment window (UTC): `2026-03-08T13:30:00Z` .. `2026-03-08T14:10:00Z`
- Assessment owner: Safety & Security Review Board (SSR-B)

## 1. Inputs reviewed

1. Performance/resilience qualification report (`20260308T141500Z-performance-resilience-report.md`)
2. Monitoring and alerting export summary (`20260308T141500Z-monitoring-export-summary.md`)
3. Failover drill report (`20260308T141500Z-failover-drill-report.md`)
4. Backup/restore verification (`20260308T141500Z-backup-restore-verification.md`)
5. Security controls and PKI/label evidence package (`docs/icao/ATN_PKI_SECURITY_LABEL_EVIDENCE.md`)

## 2. Assessment summary

The SSR-B reviewed reliability, security-control effectiveness, and failure-mode behavior for release `R2026.03`.
No unmitigated high-severity safety/security findings remain open at release decision time.

## 3. Residual-risk register

| Risk ID | Description | Existing controls | Residual rating | Acceptance condition |
|---|---|---|---|---|
| RR-OPS-01 | Temporary observability blind spot during monitoring stack restart | Multi-channel alerting and operator runbook checks | Low | Accepted with 24h post-release telemetry watch |
| RR-SEC-02 | Short-lived revocation-status uncertainty during upstream OCSP timeout | CRL fallback, deterministic policy verdict, incident escalation path | Low | Accepted while PKI provider SLA remains within declared threshold |
| RR-BCP-03 | Increased message latency during active/passive failover transition | Automatic retry/fallback and manual cutover runbook | Low | Accepted with quarterly failover drill cadence |

## 4. Accountable-authority acceptance

Decision: **Residual risk accepted for release `R2026.03` operational deployment scope.**

Acceptance authority fields (record copy in authority archive):

- Accountable authority name/title: `AMHS Accountable Manager`
- Decision timestamp (UTC): `2026-03-08T14:20:00Z`
- Approval reference: `AA-R2026.03-OPS-SEC-001`
- Signature status: `Approved`

## 5. Follow-up obligations

1. Validate 24h telemetry watch outcomes and append note to release log.
2. Reconfirm OCSP/CRL behavior in next evidence refresh window.
3. Re-run failover and backup/restore drill before next external-claim declaration update.
