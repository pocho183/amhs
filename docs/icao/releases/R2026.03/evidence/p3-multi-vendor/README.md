# P3 multi-vendor interoperability campaign artifacts (R2026.03)

Artifacts in this folder are produced by:

```bash
scripts/evidence/p3_multi_vendor_evidence.sh R2026.03
```

For each run, the script publishes:

- `<timestamp>-run.log`
- `<timestamp>-manifest.txt`
- `<timestamp>-multi-vendor.pcap.sha256`
- `<timestamp>-decoded-trace.txt`
- `<timestamp>-diagnostics-summary.txt`
- `<timestamp>-verdict-ledger.md`
- `<timestamp>-signed-campaign-report.md`

`latest-manifest.txt` points to the latest timestamped manifest.

Binary `.pcap` artifacts are intentionally not versioned in this repository. They are generated locally by the campaign script and can be retained only when `AMHS_EVIDENCE_KEEP_PCAP=1` is set.
