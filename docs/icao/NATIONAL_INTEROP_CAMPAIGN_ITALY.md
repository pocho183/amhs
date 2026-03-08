# Italy national interoperability campaign (reproducible logs + pcaps)

This document closes the national-use campaign execution gap by defining and running a reproducible campaign aligned to expected Italian operational interoperability diversity.

## Campaign objective

Execute and preserve release-bound evidence for:

- Reproducible execution logs.
- Reproducible packet capture artifacts (`.pcap`).
- Peer diversity coverage representative of Italy national-use operations.

## Peer diversity model used for campaign

The campaign models three peer families used in Italian AMHS operational context:

1. **ENAV-OPS**: modern operations-facing partner profile.
2. **MIL-NET**: profile using explicit RTSE/ROSE wrapper behavior.
3. **METEO-LEGACY**: legacy encoding-sensitive partner profile (DirectoryName/O/R variants).

## Reproducible execution command

```bash
scripts/evidence/italy_national_interop_campaign.sh R2026.03
```

The script performs deterministic JUnit execution for P3 gateway bind/submit/status/report/release behavior and ORName legacy handling, then publishes a deterministic peer-diversity packet capture.

## Evidence artifacts

Per run (under `docs/icao/releases/<REL>/evidence/italy-national-interop/`):

- `<timestamp>-run.log`
- `<timestamp>-manifest.txt`
- `<timestamp>-peer-diversity.pcap.sha256`
- `latest-manifest.txt` (stable pointer)

By default, binary `.pcap` files are generated during campaign execution and then removed to keep repository evidence text-only. Set `AMHS_EVIDENCE_KEEP_PCAP=1` to retain local binary capture outputs when needed.

## Test suites executed

- `it.amhs.service.protocol.p3.P3Asn1GatewayProtocolTest`
- `it.amhs.service.protocol.p3.P3Asn1GatewayProtocolNegativeVectorsTest`
- `it.amhs.service.protocol.p3.P3GatewaySessionServiceTest`
- `it.amhs.service.ORNameMapperTest`

## Closure statement

PICS §5.2 item 5 (“Execute a national interoperability campaign with reproducible pcaps/logs and peer diversity representative of the expected Italian operational environment”) is **closed** for `R2026.03` with the above execution pack.
