# P1 DR/NDR interoperability trace artifacts (R2026.03)

This folder stores release-preserved evidence for end-to-end P1 DR/NDR correlation and semantic consistency across peer profiles.

Artifacts are produced by:

- `scripts/evidence/p1_dr_ndr_interop_traces.sh R2026.03`

For each run, the script publishes:

- `<timestamp>-run.log`
- `<timestamp>-manifest.txt`
- `<timestamp>-dr-ndr-trace-ledger.md`

`latest-manifest.txt` points to the most recent timestamped manifest.

Peer profiles covered in the trace ledger:

- `ENAV-OPS`
- `MIL-NET`
- `CERTIFIED-AMHS-LAB`
- `METEO-LEGACY`
