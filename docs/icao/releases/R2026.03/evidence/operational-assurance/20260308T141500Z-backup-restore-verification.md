# Backup/restore verification report

- Release: `R2026.03`
- Verification ID: `BRV-2026Q1-02`
- Backup snapshot timestamp (UTC): `2026-03-08T12:45:00Z`
- Restore verification timestamp (UTC): `2026-03-08T14:05:00Z`

## Verification steps

1. Restored PostgreSQL backup to isolated verification instance.
2. Ran schema integrity checks and migration-state validation.
3. Executed record-count and checksum comparisons for message, relay-attempt, and DR/NDR tables.
4. Ran targeted continuity queries for correlation IDs across restored dataset.

## Results

- Backup artifact integrity: `PASS`.
- Schema compatibility: `PASS`.
- Data consistency checks: `PASS`.
- Message/report continuity checks: `PASS`.

## Outcome

`PASS` — restore verification confirms backup recoverability for release `R2026.03`.
