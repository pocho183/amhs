# Security PKI / CRL-OCSP / Doc 9880 label evidence artifacts (R2026.03)

Artifacts in this folder are produced by:

```bash
scripts/evidence/security_pki_label_evidence.sh R2026.03
```

For each run, the script publishes:

- `<timestamp>-run.log`
- `<timestamp>-manifest.txt`
- `<timestamp>-TEST-it.amhs.security.TLSContextFactoryTest.xml`
- `<timestamp>-TEST-it.amhs.compliance.SecurityLabelPolicyTest.xml`
- `<timestamp>-TEST-it.amhs.compliance.AMHSComplianceValidatorTest.xml`

`latest-manifest.txt` points to the latest timestamped manifest.
