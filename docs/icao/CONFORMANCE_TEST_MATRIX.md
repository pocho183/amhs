# ICAO/ATN Conformance & Interoperability Test Matrix (Baseline)

This matrix is intended to close the "documentation layer" gap by mapping expected test domains to concrete evidence artifacts.

## 1. Matrix

| Domain | Test objective | Current evidence | Gap to close |
|---|---|---|---|
| RFC1006/COTP | Validate CR/CC, segmentation, DR/ER, limits | `CotpConnectionTpduTest`, `RFC1006ServiceTest` | Add high-volume soak + malformed TPDU corpus results |
| ACSE (X.227) | Validate AARQ/AARE, context handling, diagnostics | `AcseAssociationProtocolTest`, `AcseModelsTest`, `PresentationContextTest`, `RFC1006ServiceAcseDiagnosticsTest`, `docs/icao/ACSE_PRESENTATION_NEGOTIATION_MATRIX.md` | Add strict ATN ACSE profile campaign vectors with executed verdict columns/log artifacts for each declared behavior vector |
| ASN.1/BER | Validate tag/length/value robustness | `BerCodecTest`, `P1BerMessageParserTest` | ✅ Closed (`R2026.03`): official gateway-profile X.411 module tag traceability table/proof pack published in `docs/icao/X411_CANONICAL_ASN1_MODULE_PROOF.md` |
| ROSE/RTSE upper layers | Validate full operation/error semantics and transfer/session behavior | Gateway-focused APDU/session tests | Implement full profile-complete ROSE/RTSE coverage or maintain explicit non-claim |
| P1/P3 gateway handling | Validate envelope/content, recipient and trace behaviors in gateway profile | `P1AssociationProtocolTest`, parser tests | Add interoperability captures against certified MTA and evidence of unsupported full P3 service semantics |
| O/R Address | Validate address grammar and policy checks | `ORAddressTest`, `AMHSComplianceValidatorTest`, `ORNameMapperTest` | Maintain interoperability vectors for additional peer-specific legacy encodings |
| Security/PKI | Validate identity binding, PKIX path controls, revocation handling, and Doc 9880 label treatment | `AMHSComplianceValidatorTest`, `TLSContextFactoryTest`, `SecurityLabelPolicyTest`, `P3GatewaySessionServiceTest`, `docs/icao/ATN_PKI_SECURITY_LABEL_EVIDENCE.md` | ✅ Closed (`R2026.03`): release-bound objective security evidence package and reproducible artifact-generation script published. |
| Routing/S&F | Validate route selection, retries, fallback, loop detect | `RelayRoutingServiceTest`, `OutboundRelayEngineTest` | Add sustained-load and recovery tests |
| DR/NDR | Validate report lifecycle and correlation | `AMHSDeliveryReportService` + repository/domain model | Maintain peer-wire campaign refresh per release; canonical gateway-profile ASN.1 module proof is published in `docs/icao/X411_CANONICAL_ASN1_MODULE_PROOF.md` |
| Operations | Validate 24/7 reliability and observability | `OPERATIONS_GUIDE.md` operational notes, `docs/icao/OPERATIONAL_HA_FAILOVER_EVIDENCE_PACK.md`, `docs/icao/releases/R2026.03/evidence/operational-assurance/` | ✅ Closed (`R2026.03`): executed artifacts attached (performance/resilience report, SLO sheet, monitoring export summary, failover timeline/report, backup/restore verification) |

## 2. Required evidence package for external assessment

1. PICS (`docs/icao/PICS.md`)
2. PIXIT (`docs/icao/PIXIT.md`)
3. This test matrix + filled verdict columns per campaign run
4. Operational HA/failover evidence pack (`docs/icao/OPERATIONAL_HA_FAILOVER_EVIDENCE_PACK.md`) with signed release attachments
5. Captured logs/pcaps for each mandatory negative scenario
6. Interoperability report against at least one certified AMHS implementation

## 3. Campaign completion criteria

A campaign is considered "assessment-ready" when:

- All matrix rows have executed test IDs.
- Each row includes pass/fail verdict and reproducible artifacts.
- All open gaps are either closed or risk-accepted with formal rationale.
