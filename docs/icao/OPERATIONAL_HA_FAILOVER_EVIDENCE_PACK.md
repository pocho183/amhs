# Operational HA/Failover Evidence Pack (External Oversight Baseline)

Document status: **formal oversight package baseline** for operational high-availability (HA), failover, and recovery assurance.

## 1. Purpose and applicability

This document provides the formal evidence structure requested by external oversight for the AMHS operational HA/failover profile.

It is release-bound and intended to be attached to authority-facing readiness dossiers together with:

- `docs/icao/PICS.md`
- `docs/icao/PIXIT.md`
- `docs/icao/CONFORMANCE_TEST_MATRIX.md`

## 2. Declared operational profile

### 2.1 Topology

- **Mode**: active/passive service deployment.
- **Data tier**: shared PostgreSQL persistence (single authoritative state store).
- **Service continuity model**: passive node restart/promotion with external orchestration/runbook control.

### 2.2 State continuity claims

The following data and workflow state are persisted and recoverable after node failover/restart:

- inbound/outbound AMHS message records,
- relay attempt counters and retry schedule metadata,
- DR/NDR records and protocol-level correlation identifiers,
- trace/audit-relevant processing history retained in persistence.

### 2.3 Explicit limitations

- No in-process distributed quorum/leader-election control is implemented.
- Zero-loss or zero-interruption failover is **not** claimed without external orchestrator guarantees.
- This package demonstrates controlled operational recoverability, not continuous-active clustering.

## 3. Operational control objectives

External oversight evidence is organized against these objectives:

1. **Availability governance**: target SLOs, alerting thresholds, on-call ownership.
2. **Failover execution**: repeatable drills with measured RTO/RPO outcomes.
3. **Data safety**: backup/restore verification and integrity checks.
4. **Incident traceability**: retained logs/artifacts and post-incident review records.

## 4. SLO/RTO/RPO baseline (to be bound per deployment)

The deployment authority should instantiate explicit values per environment and keep them under change control.

| Metric | Baseline declaration rule | Evidence artifact |
|---|---|---|
| Availability SLO | Monthly target defined by authority (e.g., >=99.9%) | Signed SLO sheet + monitoring export |
| RTO | Maximum failover restoration time | Drill timeline + service restoration logs |
| RPO | Maximum acceptable data loss window | DB write/replay validation output |
| Alerting latency | Time from fault to operator notification | Alert platform event trail |

## 5. Required evidence artifacts

For each campaign/drill window, collect and archive:

1. **Runbook version** used for failover and rollback.
2. **Change ticket / exercise authorization** ID.
3. **UTC timeline** (fault injection start, detection, failover trigger, service restored).
4. **Node/service logs** from active and passive nodes.
5. **Database evidence** proving message/report continuity.
6. **Client perspective proof** (submission/status/report behavior before/during/after event).
7. **Post-drill report** with measured RTO/RPO and corrective actions.

## 6. Test and verification mapping

| Verification domain | Baseline source in repository | Oversight usage |
|---|---|---|
| Relay retry/fallback semantics | `src/test/java/it/amhs/service/OutboundRelayEngineTest.java`, `src/test/java/it/amhs/service/RelayRoutingServiceTest.java` | Demonstrates deterministic recovery/retry behavior at service logic level |
| DR/NDR persistence/correlation | `src/test/java/it/amhs/service/AMHSDeliveryReportServiceTest.java` | Demonstrates report continuity and correlation integrity |
| P3 gateway session handling | `src/test/java/it/amhs/service/protocol/p3/P3GatewaySessionServiceTest.java` | Demonstrates session lifecycle resilience/guard behavior |
| Operational procedures | `OPERATIONS_GUIDE.md` | Defines field runbook expectations and configuration controls |

## 7. Drill execution template (minimum)

### 7.1 Preconditions

- Both nodes healthy; passive node synchronized and standby-ready.
- Monitoring and alerting pipeline enabled.
- Test traffic plan approved (submission + status/report checks).

### 7.2 Steps

1. Start timestamped synthetic AMHS traffic.
2. Inject active-node failure (service stop or host isolation, as authorized).
3. Execute failover runbook to promote/restart passive service path.
4. Verify end-to-end submission, status, and DR/NDR continuity.
5. Restore original topology and confirm stable steady-state operation.

### 7.3 Mandatory outputs

- RTO measurement,
- RPO measurement,
- failed/queued/replayed message counts,
- unresolved anomalies and owner/target-date.

## 8. Oversight packaging checklist

A package is ready for external review when all below are present:

- [x] Release identifier and configuration fingerprint (`R2026.03`; `docs/icao/releases/R2026.03/CONFIGURATION_FINGERPRINT.txt`).
- [x] Signed SLO/RTO/RPO declaration sheet (`docs/icao/releases/R2026.03/evidence/operational-assurance/20260308T141500Z-slo-declaration.md`).
- [x] Most recent failover drill report with raw artifacts attached (`docs/icao/releases/R2026.03/evidence/operational-assurance/20260308T141500Z-failover-drill-report.md`; `docs/icao/releases/R2026.03/evidence/operational-assurance/20260308T141500Z-manifest.txt`).
- [x] Backup/restore verification report for the same release window (`docs/icao/releases/R2026.03/evidence/operational-assurance/20260308T141500Z-backup-restore-verification.md`).
- [x] CAPA (corrective/preventive action) status for open findings (`docs/icao/releases/R2026.03/evidence/operational-assurance/20260308T141500Z-performance-resilience-report.md` indicates no blocking corrective action; failover drill shows zero open anomalies).
- [x] Approval signatures (operations owner, security owner, accountable manager) recorded (`docs/icao/releases/R2026.03/evidence/operational-assurance/20260308T141500Z-safety-security-residual-risk-acceptance.md`; `docs/icao/releases/R2026.03/evidence/italy-national-interop/20260308T150500Z-approval-register.md`).

## 9. Governance cadence

- **Failover drill frequency**: at least quarterly, and after major architecture/configuration change.
- **Backup/restore validation**: at least monthly for restore test, daily for backup success monitoring.
- **Evidence retention**: minimum 24 months (or stricter national authority requirement).

## 10. Residual risk statement

Given the declared active/passive model and external orchestration dependency, residual risk remains for:

- short availability interruption during failover,
- orchestrator/operator execution error,
- data-loss exposure limited by validated RPO controls.

Residual risks must be explicitly accepted by accountable authority per release baseline.


## 11. R2026.03 baseline attachment pointers

For release `R2026.03`, the operational-assurance execution artifacts are published in:

- `docs/icao/releases/R2026.03/evidence/operational-assurance/20260308T141500Z-performance-resilience-report.md`
- `docs/icao/releases/R2026.03/evidence/operational-assurance/20260308T141500Z-slo-declaration.md`
- `docs/icao/releases/R2026.03/evidence/operational-assurance/20260308T141500Z-monitoring-export-summary.md`
- `docs/icao/releases/R2026.03/evidence/operational-assurance/20260308T141500Z-failover-drill-report.md`
- `docs/icao/releases/R2026.03/evidence/operational-assurance/20260308T141500Z-backup-restore-verification.md`
- `docs/icao/releases/R2026.03/evidence/operational-assurance/20260308T141500Z-manifest.txt`
