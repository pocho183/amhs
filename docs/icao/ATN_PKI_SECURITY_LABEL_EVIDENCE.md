# ATN PKI / CRL-OCSP / Doc 9880 Security-Label Evidence Pack (R2026.03)

## 1. Scope

This package closes the ICAO external-claim security evidence gap for:

1. ATN PKI certificate-path validation behavior.
2. CRL/OCSP revocation-check handling.
3. Doc 9880-aligned security-label policy treatment.

Release binding is fixed to:

- `docs/icao/releases/R2026.03/CONFIGURATION_FINGERPRINT.txt`

## 2. Objective evidence map

| Claim area | Implementation control | Objective verification evidence |
|---|---|---|
| ATN PKI path validation is explicitly configured and enforced through PKIX trust-manager parameters | `TLSContextFactory` builds `PKIXBuilderParameters`, sets revocation mode, and binds optional certificate-policy OIDs into trust-path checks | `src/main/java/it/amhs/security/TLSContextFactory.java`, `src/main/java/it/amhs/AMHS.java`, `src/main/resources/application.properties`, `src/test/java/it/amhs/security/TLSContextFactoryTest.java` |
| CRL/OCSP handling is controllable and deterministic for runtime policy | `tls.pkix.revocation-enabled` enables PKIX revocation checking and uses `PKIXRevocationChecker` with CRL preference (`PREFER_CRLS`) | `src/main/java/it/amhs/security/TLSContextFactory.java`, `src/main/resources/application.properties`, `src/test/java/it/amhs/security/TLSContextFactoryTest.java` |
| Doc 9880-style label parsing, classification ordering and compartment dominance are enforced for gateway policy checks | `SecurityLabelPolicy` implements classification hierarchy, compartment syntax, dominance semantics, and explicit rejection for unsupported classifications | `src/main/java/it/amhs/compliance/SecurityLabelPolicy.java`, `src/test/java/it/amhs/compliance/SecurityLabelPolicyTest.java`, `src/test/java/it/amhs/service/protocol/p3/P3GatewaySessionServiceTest.java` |
| Security-label policy is exercised in P3 bind-path behavior with deterministic diagnostics | Gateway bind processing applies security-label policy checks and emits deterministic `security-policy` rejections when dominance/policy checks fail | `src/main/java/it/amhs/service/protocol/p3/P3GatewaySessionService.java`, `src/test/java/it/amhs/service/protocol/p3/P3GatewaySessionServiceTest.java` |
| Subject identity binding from certificate attributes to sender O/R address remains enforced as companion PKI security control | ICAO unit binding checks against CN/OU/sender address | `src/main/java/it/amhs/compliance/AMHSComplianceValidator.java`, `src/test/java/it/amhs/compliance/AMHSComplianceValidatorTest.java` |

## 3. Release execution procedure (security evidence regeneration)

Use:

```bash
scripts/evidence/security_pki_label_evidence.sh R2026.03
```

Published artifact root:

- `docs/icao/releases/R2026.03/evidence/security-pki-label/`

Per run, the script generates timestamped:

- run log,
- manifest,
- JUnit XML copies for PKI and security-label tests.

## 4. Statement

For release `R2026.03`, PKI path-validation controls, revocation-check control points, and Doc 9880-aligned security-label policy handling are fully specified, implemented, and bound to reproducible security evidence artifacts in this repository.
