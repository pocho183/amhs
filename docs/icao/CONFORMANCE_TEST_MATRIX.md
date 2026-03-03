# ICAO/ATN Conformance & Interoperability Test Matrix (Baseline)

This matrix is intended to close the "documentation layer" gap by mapping expected test domains to concrete evidence artifacts.

## 1. Matrix

| Domain | Test objective | Current evidence | Gap to close |
|---|---|---|---|
| RFC1006/COTP | Validate CR/CC, segmentation, DR/ER, limits | `CotpConnectionTpduTest`, `RFC1006ServiceTest` | Add high-volume soak + malformed TPDU corpus results |
| ACSE (X.227) | Validate AARQ/AARE, context handling, diagnostics | `AcseAssociationProtocolTest`, `AcseModelsTest`, `PresentationContextTest` | Add strict ATN ACSE profile vectors and negative diagnostics matrix |
| ASN.1/BER | Validate tag/length/value robustness | `BerCodecTest`, `P1BerMessageParserTest` | Add official X.411 module tag traceability table |
| P1 handling | Validate envelope/content, recipient and trace behaviors | `P1AssociationProtocolTest`, parser tests | Add interoperability captures against certified MTA |
| O/R Address | Validate address grammar and policy checks | `ORAddressTest`, `AMHSComplianceValidatorTest` | Expand to full ORName CHOICE and legacy string variants |
| Security/PKI | Validate identity binding and TLS behavior | `AMHSComplianceValidatorTest`, TLS runtime config | Add CRL/OCSP tests and ATN PKI profile statement |
| Routing/S&F | Validate route selection, retries, fallback, loop detect | `RelayRoutingServiceTest`, `OutboundRelayEngineTest` | Add sustained-load and recovery tests |
| DR/NDR | Validate report lifecycle and correlation | `AMHSDeliveryReportService` + repository/domain model | Add protocol-level DR/NDR correlation campaign with peer fixtures |
| Operations | Validate 24/7 reliability and observability | `OPERATIONS_GUIDE.md` operational notes | Add SLOs, failover drills, backup/restore evidence |

## 2. Required evidence package for external assessment

1. PICS (`docs/icao/PICS.md`)
2. PIXIT (`docs/icao/PIXIT.md`)
3. This test matrix + filled verdict columns per campaign run
4. Captured logs/pcaps for each mandatory negative scenario
5. Interoperability report against at least one certified AMHS implementation

## 3. Campaign completion criteria

A campaign is considered "assessment-ready" when:

- All matrix rows have executed test IDs.
- Each row includes pass/fail verdict and reproducible artifacts.
- All open gaps are either closed or risk-accepted with formal rationale.

