# P3 negative APDU regression artifacts (R2026.03)

This folder stores release-preserved execution artifacts produced by:

- `scripts/evidence/p3_negative_apdu_regression.sh R2026.03`

For each run, the script publishes:

- `<timestamp>-run.log`
- `<timestamp>-manifest.txt`
- optional `<timestamp>-TEST-*.xml` JUnit files when Gradle test execution reaches test phase

`latest-manifest.txt` is a stable pointer to the most recent timestamped execution manifest.


Coverage includes deterministic vectors for unsupported P3 operations, ACSE rejection diagnostics, and malformed COTP/TPDU parsing paths (via release-bound JUnit XML artifacts when produced).
