# P3 negative APDU regression artifacts (R2026.03)

This folder stores release-preserved execution artifacts produced by:

- `scripts/evidence/p3_negative_apdu_regression.sh R2026.03`

For each run, the script publishes:

- `<timestamp>-run.log`
- `<timestamp>-manifest.txt`
- optional `<timestamp>-TEST-*.xml` JUnit files when Gradle test execution reaches test phase

`latest-manifest.txt` is a stable pointer to the most recent timestamped execution manifest.


Coverage includes deterministic vectors for packet-level/log-level P3 bind negotiation evidence, unsupported P3 operations, ACSE selector/context/authentication matrix validation, ACSE rejection diagnostics, and malformed COTP/TPDU parsing paths (via release-bound JUnit XML artifacts when produced).


Additional closure artifact:

- `20260308T210500Z-negotiation-error-semantics-closure.md` (packet-level + log-level evidence pointers for ACSE/P3 negotiation/error semantics closure).

Primary test sources collected by `p3_negative_apdu_regression.sh` include:

- `it.amhs.service.protocol.p3.P3Asn1GatewayProtocolEvidenceTest`
- `it.amhs.service.protocol.p3.P3Asn1GatewayProtocolNegativeVectorsTest`
- `it.amhs.service.protocol.p3.P3Asn1GatewayProtocolTest`
- `it.amhs.service.protocol.rfc1006.RFC1006ServiceAcseNegotiationMatrixTest`
- `it.amhs.service.protocol.rfc1006.RFC1006ServiceAcseDiagnosticsTest`
- `it.amhs.service.CotpConnectionTpduTest`
