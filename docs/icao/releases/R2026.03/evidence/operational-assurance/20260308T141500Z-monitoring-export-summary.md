# Monitoring/alerting export summary

- Release: `R2026.03`
- Export window (UTC): `2026-03-08T13:00:00Z` .. `2026-03-08T14:30:00Z`
- Source systems: service metrics pipeline, alert manager event stream

## Summary

- Alert policy set loaded: `amhs-prod-core-v4`.
- Critical events observed during drill: `1` (primary node unavailable).
- Warning events observed during drill: `2` (queue depth transient high-water mark).
- Unacknowledged critical alerts at end of exercise: `0`.

## Key points

1. Detection-to-page latency remained below declared 2-minute threshold.
2. Queue depth and retry counters returned to nominal values after failover completion.
3. No silent-failure intervals observed in telemetry path.
