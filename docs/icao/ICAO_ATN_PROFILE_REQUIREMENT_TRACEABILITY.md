# ICAO/ATN AMHS Profile Requirement Traceability (R2026.03)

Document status: **mandatory external-claim closure artifact** for release `R2026.03`.

## 1. Purpose

This document provides a formal requirement-by-requirement mapping from the applicable ICAO/ATN AMHS profile expectations used by this project to concrete implementation and objective test evidence.

## 2. Applicable profile sources

- ICAO Doc 9880 (AMHS SARPs/technical requirements as profiled for implementation claims).
- ATN/AMHS protocol stack requirements applied through this repository's declared PICS/PIXIT baseline.
- Release baseline controls:
  - `docs/icao/PICS.md`
  - `docs/icao/PIXIT.md`
  - `docs/icao/releases/R2026.03/CONFIGURATION_FINGERPRINT.txt`

## 3. Requirement-to-evidence mapping

| Requirement ID | Profile requirement statement | Implementation reference | Verification evidence | Verdict (`R2026.03`) |
|---|---|---|---|---|
| ATN-AMHS-TRN-01 | RFC1006/TPKT/COTP framing and Class 0 association handling shall be deterministic and reject malformed transport frames. | `src/main/java/it/amhs/service/protocol/rfc1006/RFC1006Service.java`, `src/main/java/it/amhs/service/protocol/rfc1006/CotpConnectionTpdu.java` | `src/test/java/it/amhs/service/CotpConnectionTpduTest.java`, `src/test/java/it/amhs/service/RFC1006ServiceTest.java` | Pass |
| ATN-AMHS-ACSE-01 | ACSE AARQ/AARE negotiation shall provide deterministic result/diagnostic behavior for declared profile paths. | `src/main/java/it/amhs/service/protocol/acse/AcseAssociationProtocol.java`, `src/main/java/it/amhs/service/protocol/acse/PresentationContext.java` | `src/test/java/it/amhs/service/AcseAssociationProtocolTest.java`, `src/test/java/it/amhs/service/PresentationContextTest.java`, `src/test/java/it/amhs/service/protocol/rfc1006/RFC1006ServiceAcseDiagnosticsTest.java`, `docs/icao/ACSE_PRESENTATION_NEGOTIATION_MATRIX.md` | Pass |
| ATN-AMHS-P3-01 | Declared P3 gateway operation set (bind/submit/status/report/release) shall be deterministic, including negative/error semantics for unsupported vectors. | `src/main/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocol.java`, `src/main/java/it/amhs/service/protocol/p3/P3GatewaySessionService.java` | `src/test/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocolTest.java`, `src/test/java/it/amhs/service/protocol/p3/P3Asn1GatewayProtocolNegativeVectorsTest.java`, `src/test/java/it/amhs/service/protocol/p3/P3GatewaySessionServiceTest.java`, `docs/icao/releases/R2026.03/P3_INTERNAL_PROFILE_STATEMENT.md`, `docs/icao/P3_SERVICE_EXTERNAL_DECLARATION_MATRIX.md` | Pass |
| ATN-AMHS-P1-01 | X.411 envelope/content processing shall preserve gateway-required P1 semantics for routing and reporting. | `src/main/java/it/amhs/service/protocol/p1/P1AssociationProtocol.java`, `src/main/java/it/amhs/service/protocol/p1/P1BerMessageParser.java`, `src/main/java/it/amhs/service/report/X411DeliveryReportApduCodec.java` | `src/test/java/it/amhs/service/P1AssociationProtocolTest.java`, `src/test/java/it/amhs/service/P1BerMessageParserTest.java`, `src/test/java/it/amhs/service/X411DeliveryReportApduCodecTest.java` | Pass |
| ATN-AMHS-P1-EXT-01 | P1 extension handling shall be frozen with deterministic known/unknown behavior and backward-compatibility checks. | `src/main/java/it/amhs/service/protocol/p1/P1AssociationProtocol.java`, `src/main/java/it/amhs/service/protocol/p1/P1BerMessageParser.java`, `src/main/java/it/amhs/service/protocol/p1/X411TagMap.java` | `src/test/java/it/amhs/service/P1AssociationProtocolTest.java`, `src/test/java/it/amhs/service/P1BerMessageParserTest.java`, `docs/icao/P1_EXTENSION_HANDLING_POLICY.md` | Pass |
| ATN-AMHS-ASN1-01 | ASN.1/X.411 module usage shall be traceable from canonical module tags to runtime BER handling. | `src/main/java/it/amhs/service/protocol/p1/X411TagMap.java`, `src/main/java/it/amhs/asn1/BerCodec.java` | `src/test/java/it/amhs/service/X411CanonicalModuleConformanceTest.java`, `docs/icao/X411_CANONICAL_ASN1_MODULE_PROOF.md`, `docs/icao/X411_MODULE_TRACEABILITY.md` | Pass |
| ATN-AMHS-ADR-01 | O/R Address and ORName handling shall enforce profile validation constraints for declared policy controls. | `src/main/java/it/amhs/service/address/ORAddress.java`, `src/main/java/it/amhs/service/address/ORNameMapper.java`, `src/main/java/it/amhs/compliance/AMHSComplianceValidator.java` | `src/test/java/it/amhs/service/ORAddressTest.java`, `src/test/java/it/amhs/service/ORNameMapperTest.java`, `src/test/java/it/amhs/compliance/AMHSComplianceValidatorTest.java` | Pass |
| ATN-AMHS-SEC-01 | TLS identity binding and security-label policy checks shall be enforced for configured channels. | `src/main/java/it/amhs/compliance/SecurityLabelPolicy.java`, `src/main/java/it/amhs/security/TLSContextFactory.java` | `src/test/java/it/amhs/compliance/SecurityLabelPolicyTest.java`, `docs/icao/PIXIT.md` | Pass (profile-limited) |
| ATN-AMHS-OPS-01 | Operational resilience and failover controls shall be evidenced for release declaration posture. | `OPERATIONS_GUIDE.md`, operational runtime configuration | `docs/icao/releases/R2026.03/evidence/operational-assurance/20260308T141500Z-performance-resilience-report.md`, `docs/icao/releases/R2026.03/evidence/operational-assurance/20260308T141500Z-failover-drill-report.md`, `docs/icao/releases/R2026.03/evidence/operational-assurance/20260308T141500Z-backup-restore-verification.md` | Pass |

## 4. Sign-off record for external declaration

| Role | Name | Decision | Date (UTC) |
|---|---|---|---|
| Engineering owner | _Pending_ | Pending | - |
| Compliance owner | _Pending_ | Pending | - |
| Security owner | _Pending_ | Pending | - |
| Accountable authority | _Pending_ | Pending | - |

## 5. Closure rule

External ICAO-oriented declaration is only claimable when all rows in section 3 are `Pass` for the declared release baseline **and** the sign-off record in section 4 is completed.
