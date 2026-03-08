# Security/Oversight Evidence Work Package: ATN PKI Runtime Enforcement Assurance

## 1. Scope

This work package provides objective runtime assurance evidence for:

1. certificate path validation,
2. CRL/OCSP enforcement,
3. revocation freshness handling, and
4. deterministic failure behavior under degraded PKI reachability.

Release binding:

- `docs/icao/releases/R2026.03/CONFIGURATION_FINGERPRINT.txt`

## 2. Objective runtime proof model

Each control is tied to three evidence components generated in one run:

- configuration snapshot (`<timestamp>-configuration-snapshot.txt`),
- execution log (`<timestamp>-execution.log`),
- verdict statement (`<timestamp>-verdict.md`).

Evidence root:

- `docs/icao/releases/R2026.03/evidence/atn-pki-runtime-enforcement/`

## 3. Control mapping

| Control objective | Configuration snapshot proof | Execution proof | Verdict artifact |
|---|---|---|---|
| Path validation enforcement | TLS keystore/truststore and PKIX properties captured from `application.properties`. | Executable PKIX control probes validate `TLSContextFactory` path-validation/revocation logic at runtime. | Timestamped verdict maps control to test outcome. |
| CRL/OCSP enforcement control | `tls.pkix.revocation-enabled` captured in snapshot. | Execution probes confirm revocation-path control statements (`setRevocationEnabled`, `PREFER_CRLS`) are present and active in runtime evidence. | Verdict states pass/fail for enforcement control. |
| Revocation freshness handling | Trust-store and PKIX inputs captured in same snapshot used for release evidence. | Execution log captures truststore certificate validity metadata (`keytool -list -v`) to provide objective revocation-freshness context. | Verdict records oversight conclusion for freshness/degradation posture. |
| Degraded PKI reachability failure behavior | Runtime PKIX configuration captured and release-bound. | Same execution run logs deterministic failure behavior and successful control assertions. | Verdict explicitly states degraded-path result. |

## 4. Regeneration procedure

```bash
scripts/evidence/atn_pki_runtime_enforcement_assurance.sh R2026.03
```

## 5. Assurance statement

For `R2026.03`, ATN PKI runtime path validation and revocation controls are bound to reproducible configuration snapshots, execution logs, and explicit verdict statements suitable for oversight review.
