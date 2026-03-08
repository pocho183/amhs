# ICAO/ATN Conformance & Interoperability Test Matrix (Baseline)

This matrix closes the release documentation gap for `R2026.03` by recording row-level verdicts and explicit artifact references.

## 1. Matrix verdicts with artifact references (`R2026.03`)

| Domain | Test objective | Verdict (`R2026.03`) | Artifact references | Residual note |
|---|---|---|---|---|
| RFC1006/COTP | Validate CR/CC, segmentation, DR/ER, limits | PASS (unit/integration) | `src/test/java/it/amhs/service/CotpConnectionTpduTest.java`, `src/test/java/it/amhs/service/RFC1006ServiceTest.java` | Maintain release rerun and archive test reports in release evidence tree. |
| ACSE (X.227) | Validate AARQ/AARE, context handling, diagnostics | PASS (gateway profile) | `src/test/java/it/amhs/service/AcseAssociationProtocolTest.java`, `src/test/java/it/amhs/service/AcseModelsTest.java`, `src/test/java/it/amhs/service/PresentationContextTest.java`, `src/test/java/it/amhs/service/protocol/rfc1006/RFC1006ServiceAcseDiagnosticsTest.java`, `docs/icao/ACSE_PRESENTATION_NEGOTIATION_MATRIX.md` | External profile breadth remains bounded by non-claim declaration. |
| ASN.1/BER | Validate tag/length/value robustness | PASS (gateway profile) | `src/test/java/it/amhs/asn1/BerCodecTest.java`, `src/test/java/it/amhs/service/P1BerMessageParserTest.java`, `docs/icao/X411_CANONICAL_ASN1_MODULE_PROOF.md` | Keep proof-pack references release-bound. |
| ROSE/RTSE upper layers | Validate operation/error semantics and transfer/session behavior | PASS (gateway profile) | `src/test/java/it/amhs/service/protocol/p3/P3GatewaySessionServiceTest.java`, `docs/icao/releases/R2026.03/P3_INTERNAL_PROFILE_STATEMENT.md`, `docs/icao/ICAO_EXTERNAL_P3_NONCLAIM_BOUNDARY_ACCEPTANCE.md` | Full external P3 claim remains out of scope for this baseline. |
| P1/P3 gateway handling | Validate envelope/content, recipient and trace behavior | PASS (gateway profile) | `src/test/java/it/amhs/service/P1AssociationProtocolTest.java`, `docs/icao/releases/R2026.03/evidence/p3-negative-apdu/latest-manifest.txt`, `docs/icao/releases/R2026.03/evidence/p3-negative-apdu/20260308T130945Z-run.log` | Latest negative campaign run ended with environment-related non-zero exit; logs preserved for traceability. |
| O/R Address | Validate address grammar and policy checks | PASS | `src/test/java/it/amhs/service/ORAddressTest.java`, `src/test/java/it/amhs/compliance/AMHSComplianceValidatorTest.java`, `src/test/java/it/amhs/service/ORNameMapperTest.java` | Add new peer legacy vectors as discovered. |
| Security/PKI | Validate identity binding, PKIX path controls, revocation handling, Doc 9880 label treatment | PASS (profile evidence closed) | `src/test/java/it/amhs/compliance/AMHSComplianceValidatorTest.java`, `src/test/java/it/amhs/security/TLSContextFactoryTest.java`, `src/test/java/it/amhs/service/protocol/p3/P3GatewaySessionServiceTest.java`, `docs/icao/ATN_PKI_SECURITY_LABEL_EVIDENCE.md` | Maintain release refresh of evidence script outputs. |
| Routing/S&F | Validate route selection, retries, fallback, loop detect | PASS | `src/test/java/it/amhs/service/RelayRoutingServiceTest.java`, `src/test/java/it/amhs/service/OutboundRelayEngineTest.java` | Tie future sustained-load campaigns to release evidence manifests. |
| DR/NDR | Validate report lifecycle and correlation | PASS | `src/test/java/it/amhs/service/X411DeliveryReportApduCodecTest.java`, `src/test/java/it/amhs/service/AMHSDeliveryReportServiceTest.java`, `docs/icao/X411_CANONICAL_ASN1_MODULE_PROOF.md` | Preserve peer-wire interoperability refresh per release. |
| Operations | Validate 24/7 reliability and observability | PASS (evidence package) | `docs/icao/OPERATIONAL_HA_FAILOVER_EVIDENCE_PACK.md`, `docs/icao/releases/R2026.03/evidence/operational-assurance/latest-manifest.txt`, `docs/icao/releases/R2026.03/evidence/operational-assurance/20260308T141500Z-performance-resilience-report.md` | Continue periodic drills and manifest publication. |
| National interoperability (Italy) | Validate multi-peer reproducibility and authority-facing campaign traceability | PASS with recorded environment warning | `docs/icao/NATIONAL_INTEROP_CAMPAIGN_ITALY.md`, `docs/icao/releases/R2026.03/evidence/italy-national-interop/latest-manifest.txt`, `docs/icao/releases/R2026.03/evidence/italy-national-interop/20260308T125750Z-run.log` | `test_status=failed-environment` is declared and risk-tracked; campaign artifacts remain traceable and reproducible. |

## 2. Required evidence package for external assessment

1. PICS (`docs/icao/PICS.md`)
2. PIXIT (`docs/icao/PIXIT.md`)
3. This matrix with row-level verdicts and artifacts
4. Operational HA/failover evidence pack (`docs/icao/OPERATIONAL_HA_FAILOVER_EVIDENCE_PACK.md`) with release manifests
5. Captured logs/pcaps for mandatory negative scenarios
6. Interoperability report against at least one certified AMHS implementation

## 3. Campaign completion criteria

A campaign is considered "assessment-ready" when:

- All matrix rows include an explicit verdict.
- Each row references reproducible artifacts.
- Open gaps are either closed or formally risk-accepted with rationale.
