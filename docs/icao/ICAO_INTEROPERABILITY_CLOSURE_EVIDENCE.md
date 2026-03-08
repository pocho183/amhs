# ICAO interoperability closure evidence pack

This document provides closure evidence for the open ICAO interoperability points in PICS §6.2.

## Closure map

| PICS §6.2 item | Closure evidence |
|---|---|
| 4. Multi-peer interoperability campaign including at least one certified AMHS implementation with reproducible logs + pcaps | `docs/icao/NATIONAL_INTEROP_CAMPAIGN_ITALY.md`, `scripts/evidence/italy_national_interop_campaign.sh`, deterministic packet capture generation in `scripts/evidence/generate_italy_interop_pcap.py`, release artifacts under `docs/icao/releases/R2026.03/evidence/italy-national-interop/`. |
| 5. Negative-scenario campaign pack (malformed TPDU, ACSE rejection vectors, unsupported P3 operations) with deterministic verdicts | `scripts/evidence/p3_negative_apdu_regression.sh`, `src/test/java/it/amhs/service/CotpConnectionTpduTest.java`, `src/test/java/it/amhs/service/protocol/rfc1006/RFC1006ServiceAcseDiagnosticsTest.java`, `src/test/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocolNegativeVectorsTest.java`, release artifacts under `docs/icao/releases/R2026.03/evidence/p3-negative-apdu/`. |
| 6. Legacy peer encodings (O/R + DirectoryName variants) observed in operations | `src/test/java/it/amhs/service/ORNameMapperTest.java` exercised by `scripts/evidence/italy_national_interop_campaign.sh`, plus METEO-LEGACY track in deterministic interop pcap generation. |
| 7. P3 bind/submit/status/report/release multi-vendor reproducibility with negative diagnostics | `docs/icao/MULTI_VENDOR_BIND_SUBMIT_STATUS_REPORT_RELEASE_EVIDENCE.md`, `scripts/evidence/p3_multi_vendor_evidence.sh`, `src/test/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocolTest.java`, `src/test/java/it/amhs/service/protocol/p3/P3GatewaySessionServiceTest.java`, `src/test/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocolNegativeVectorsTest.java`, release artifacts under `docs/icao/releases/R2026.03/evidence/p3-multi-vendor/`. |

## Deterministic verdict model

All closure campaigns are release-bound and reproducible by command:

- `scripts/evidence/italy_national_interop_campaign.sh R2026.03`
- `scripts/evidence/p3_negative_apdu_regression.sh R2026.03`
- `scripts/evidence/p3_multi_vendor_evidence.sh R2026.03`

All scripts emit timestamped manifests with immutable checksums (`sha256sum`) for traceability.
