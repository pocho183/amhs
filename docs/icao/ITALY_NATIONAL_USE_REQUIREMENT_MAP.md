# Italy National-Use AMHS Requirement Traceability Map

## 1. Purpose

This document closes the PICS national-use (Italy) action item to provide a **traceable requirement map** from the adopted AMHS profile obligations to implementation, automated verification, and reproducible evidence artifacts.

Baseline context:

- PICS national-use closure list: `docs/icao/PICS.md` §5.2.
- Release baseline and declared P3 operation profile: `docs/icao/releases/R2026.03/P3_INTERNAL_PROFILE_STATEMENT.md`.

## 2. Adopted obligation set (Italy national-use baseline)

The obligations below represent the implementation profile currently adopted for Italy national-use deployment readiness (gateway posture, release `R2026.03`).

Legend:

- **Impl**: runtime implementation artifacts.
- **Tests**: automated test suites validating behavior.
- **Evidence**: release/campaign artifacts, scripts, and published logs/manifests.
- **Status**: `Closed` (mapped and evidenced) or `Open` (mapped but pending campaign completion).

| Req ID | Adopted obligation (national-use baseline) | Impl | Tests | Evidence | Status |
|---|---|---|---|---|---|
| IT-NU-01 | RFC1006/TPKT/COTP transport guardrails are deterministic (framing validation, segmentation, disconnect/error handling). | `src/main/java/it/amhs/service/protocol/rfc1006/RFC1006Service.java`, `src/main/java/it/amhs/service/protocol/rfc1006/CotpConnectionTpdu.java` | `src/test/java/it/amhs/service/RFC1006ServiceTest.java`, `src/test/java/it/amhs/service/CotpConnectionTpduTest.java`, `src/test/java/it/amhs/network/RFC1006ServerTest.java` | `docs/icao/PICS.md` (T-01..T-06), `docs/icao/CONFORMANCE_TEST_MATRIX.md` | Closed |
| IT-NU-02 | ACSE/presentation negotiation behavior is declared and deterministic for the supported gateway profile boundary. | `src/main/java/it/amhs/service/protocol/acse/AcseAssociationProtocol.java`, `src/main/java/it/amhs/service/protocol/acse/PresentationContext.java`, `src/main/java/it/amhs/service/protocol/rfc1006/RFC1006Service.java` | `src/test/java/it/amhs/service/AcseAssociationProtocolTest.java`, `src/test/java/it/amhs/service/PresentationContextTest.java`, `src/test/java/it/amhs/service/protocol/rfc1006/RFC1006ServiceAcseDiagnosticsTest.java` | `docs/icao/ACSE_PRESENTATION_NEGOTIATION_MATRIX.md`, `docs/icao/PIXIT.md` | Closed |
| IT-NU-03 | Adopted P3 gateway operation set (bind/submit/status/report/release + deterministic negative diagnostics) is fixed per release. | `src/main/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocol.java`, `src/main/java/it/amhs/service/protocol/p3/P3GatewaySessionService.java` | `src/test/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocolTest.java`, `src/test/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocolNegativeVectorsTest.java`, `src/test/java/it/amhs/service/protocol/p3/P3GatewaySessionServiceTest.java` | `docs/icao/releases/R2026.03/P3_INTERNAL_PROFILE_STATEMENT.md`, `scripts/evidence/p3_negative_apdu_regression.sh`, `docs/icao/releases/R2026.03/evidence/p3-negative-apdu/` | Closed |
| IT-NU-04 | O/R address and ORName handling enforce ICAO/AMHS constraints used by national operations (including C=IT addressing patterns). | `src/main/java/it/amhs/service/address/ORAddress.java`, `src/main/java/it/amhs/service/address/ORNameMapper.java`, `src/main/java/it/amhs/compliance/AMHSComplianceValidator.java` | `src/test/java/it/amhs/service/ORAddressTest.java`, `src/test/java/it/amhs/service/ORNameMapperTest.java`, `src/test/java/it/amhs/compliance/AMHSComplianceValidatorTest.java` | `docs/icao/PICS.md` (OR-01..OR-05), `docs/icao/X411_MODULE_TRACEABILITY.md` | Closed |
| IT-NU-05 | TLS + mTLS identity binding (CN/OU/channel policy) are enforced for controlled inter-domain trust. | `src/main/java/it/amhs/security/TLSContextFactory.java`, `src/main/java/it/amhs/compliance/AMHSComplianceValidator.java` | `src/test/java/it/amhs/compliance/AMHSComplianceValidatorTest.java`, `src/test/java/it/amhs/service/X400MessageServiceTest.java` | `docs/icao/PICS.md` (SEC-01, SEC-02), `docs/icao/PIXIT.md` | Closed |
| IT-NU-06 | Security labels are enforced at gateway-policy level (classification + compartments), with explicit profile limitation. | `src/main/java/it/amhs/compliance/SecurityLabelPolicy.java`, `src/main/java/it/amhs/service/protocol/p3/P3GatewaySessionService.java` | `src/test/java/it/amhs/compliance/SecurityLabelPolicyTest.java`, `src/test/java/it/amhs/service/protocol/p3/P3GatewaySessionServiceTest.java` | `docs/icao/PICS.md` (SEC-05), `docs/icao/PIXIT.md` limitation notes | Closed |
| IT-NU-07 | DR/NDR report persistence and protocol-level correlation remain traceable for audits and incident analysis. | `src/main/java/it/amhs/service/report/AMHSDeliveryReportService.java`, `src/main/java/it/amhs/service/report/X411DeliveryReportApduCodec.java`, `src/main/java/it/amhs/domain/AMHSDeliveryReport.java` | `src/test/java/it/amhs/service/AMHSDeliveryReportServiceTest.java`, `src/test/java/it/amhs/service/X411DeliveryReportApduCodecTest.java` | `docs/icao/X411_MODULE_TRACEABILITY.md` (DR/NDR evidence hooks), `docs/icao/PICS.md` (R-04) | Closed |
| IT-NU-08 | Reproducible evidence publication is release-bound (config fingerprint + manifests + deterministic scripts). | `scripts/evidence/p3_negative_apdu_regression.sh`, `scripts/evidence/p3_multi_vendor_evidence.sh` | Script-driven execution of `P3Asn1GatewayProtocol*` and `P3GatewaySessionServiceTest` suites | `docs/icao/releases/R2026.03/CONFIGURATION_FINGERPRINT.txt`, `docs/icao/releases/R2026.03/evidence/p3-negative-apdu/latest-manifest.txt`, `docs/icao/MULTI_VENDOR_BIND_SUBMIT_STATUS_REPORT_RELEASE_EVIDENCE.md` | Closed |
| IT-NU-09 | National operational assurance package includes failover/HA procedures, declaration responsibilities, security controls (including PKI revocation behavior), and authority-facing approvals. | Operational runbooks and controls (`OPERATIONS_GUIDE.md`) | Procedure verification entries in release operations campaigns | `docs/icao/OPERATIONAL_HA_FAILOVER_EVIDENCE_PACK.md`, `docs/icao/ITALY_NATIONAL_DECLARATION_PACKAGE.md` | Closed (recurring per-release evidence/approval refresh required) |

## 3. Gap-closure outcome for PICS §5.2 item 4

PICS §5.2 item 4 (“Build a traceable requirement map from adopted AMHS profile obligations to implementation/tests/evidence artifacts”) is now closed by this document for the `R2026.03` baseline.

All `§5.2` national-use baseline items (4..6) are closed for `R2026.03`; declaration artifacts remain subject to recurring per-release refresh.

## 4. Maintenance rule

For each release, update this map together with:

1. `docs/icao/releases/<REL>/CONFIGURATION_FINGERPRINT.txt`
2. Evidence manifests/logs under `docs/icao/releases/<REL>/evidence/`
3. PICS/PIXIT statements if any adopted obligation semantics change

This keeps national-use declarations auditable and reproducible.
