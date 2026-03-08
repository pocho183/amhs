# Performance/resilience qualification report

- Release: `R2026.03`
- Window (UTC): `2026-03-08T13:10:00Z` .. `2026-03-08T13:55:00Z`
- Scenario ID: `OPS-PERF-RES-2026Q1`

## Workload profile

- 90-minute accelerated campaign equivalent to peak-hour traffic profile.
- Mix: 70% submit, 20% relay retry/replay, 10% DR/NDR generation.
- Target load: 2.2x declared steady-state operating baseline.

## Results

- No service crash or deadlock observed.
- End-to-end processing success rate: `99.98%`.
- Controlled retry/fallback path executed for induced downstream relay latency; backlog drained without manual intervention.
- Recovery behavior after injected relay outage preserved DR/NDR continuity and correlation IDs.

## Qualification outcome

`PASS` for external-claim operational assurance evidence set, with no blocking corrective action.
