# Italy national interoperability campaign artifacts (R2026.03)

Artifacts in this folder are produced by:

```bash
scripts/evidence/italy_national_interop_campaign.sh R2026.03
```

For each run, the script publishes:

- `<timestamp>-run.log`
- `<timestamp>-manifest.txt`
- `<timestamp>-peer-diversity.pcap.sha256`

`latest-manifest.txt` points to the latest timestamped manifest.


Binary `.pcap` artifacts are intentionally not versioned in this repository. They are generated locally by the campaign script and can be retained only when `AMHS_EVIDENCE_KEEP_PCAP=1` is set.


Peer diversity profile in manifest includes `ENAV-OPS`, `MIL-NET`, `CERTIFIED-AMHS-LAB`, and `METEO-LEGACY`.
