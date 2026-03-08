# Failover drill report

- Release: `R2026.03`
- Drill ID: `FO-DRILL-2026Q1-01`
- Runbook revision: `OPERATIONS_GUIDE.md@R2026.03`
- Exercise authorization: `CHG-2026-03-08-221`

## UTC timeline

- `13:22:10` fault injection start (active node service stop).
- `13:22:26` monitoring detection raised.
- `13:23:01` on-call acknowledged page.
- `13:24:18` passive path promotion initiated.
- `13:28:52` client bind/submit/status checks restored.
- `13:31:04` DR/NDR continuity verification completed.

## Observed results

- RTO measured: `6m42s`.
- RPO measured: `0m` (no missing committed messages).
- Failed messages: `0`.
- Queued/replayed messages: `37` (all replayed and cleared).
- Open anomalies: `0`.

## Outcome

`PASS` — failover procedure met declared RTO/RPO targets and preserved service/reporting continuity.
