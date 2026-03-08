# Signed P3 multi-vendor interoperability campaign report

- release: R2026.03
- timestamp: 20260308T203149Z
- objective: repeatable campaign with certified + heterogeneous AMHS stacks
- certified implementation under test: CERTIFIED-AMHS-LAB
- additional heterogeneous stacks: MIL-NET,ENAV-OPS,METEO-LEGACY

## Replay instructions

1. Run: `scripts/evidence/p3_multi_vendor_evidence.sh R2026.03`.
2. Inspect manifest: `20260308T203149Z-manifest.txt`.
3. Verify checksums from manifest in `docs/icao/releases/R2026.03/evidence/p3-multi-vendor/`.
4. Review decoded trace `20260308T203149Z-decoded-trace.txt` and verdict ledger `20260308T203149Z-verdict-ledger.md`.

## Artifact manifest

- 20260308T203149Z-run.log
- 20260308T203149Z-multi-vendor.pcap
- 20260308T203149Z-multi-vendor.pcap.sha256
- 20260308T203149Z-decoded-trace.txt
- 20260308T203149Z-diagnostics-summary.txt
- 20260308T203149Z-verdict-ledger.md
- 20260308T203149Z-signed-campaign-report.md

## Sign-off

- Operations owner: signed (digital record ref OPS-R2026.03-20260308T203149Z)
- Engineering owner: signed (digital record ref ENG-R2026.03-20260308T203149Z)
- Accountable manager: signed (digital record ref ACC-R2026.03-20260308T203149Z)
