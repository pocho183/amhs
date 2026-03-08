# ICAO/ATN AMHS Declaration Profile Conformance Map (R2026.03)

Document status: **single-source requirement-to-evidence conformance map** for release `R2026.03`.

## 1. Purpose

This document is the authoritative declaration profile map for `R2026.03`.
It consolidates declaration statements across **P1**, **P3**, **security**, and **operational controls** into one requirement-to-evidence matrix.

## 2. Governing rule for declaration statements

A declaration statement is valid only when its matrix row contains:

1. **At least one executable evidence artifact** (`./gradlew test ...` command, script execution log, or pcap output), and
2. **At least one governing document section** (release-bound section anchor or control section that defines the declaration boundary).

Rows that do not satisfy both conditions are out-of-policy for external declaration.

This rule is mandatory for **every declaration row** in section 4 and applies uniformly across **P1**, **P3**, **security**, and **operational controls**.

## 3. Applicable profile/governance sources

- ICAO Doc 9880 AMHS requirements as profiled for this implementation.
- Baseline controls and claim boundaries:
  - `docs/icao/PICS.md` §5
  - `docs/icao/PIXIT.md` §3
  - `docs/icao/P3_SERVICE_EXTERNAL_DECLARATION_MATRIX.md` §3
  - `docs/icao/OPERATIONAL_HA_FAILOVER_EVIDENCE_PACK.md` §4-§6
- Release binding:
  - `docs/icao/releases/R2026.03/PICS_R2026.03.md` §4
  - `docs/icao/releases/R2026.03/PIXIT_R2026.03.md` §3-§4
  - `docs/icao/releases/R2026.03/CONFIGURATION_FINGERPRINT.txt`

## 4. Single-source requirement-to-evidence matrix (`R2026.03`)

| Requirement ID | Control family | Declaration statement | Governing document section(s) | Executable evidence artifact(s) | Verdict (`R2026.03`) |
|---|---|---|---|---|---|
| ATN-AMHS-P1-01 | P1 protocol handling | X.411/P1 association and transfer-envelope decoding shall be deterministic for declared gateway routing/report semantics. | `docs/icao/releases/R2026.03/PICS_R2026.03.md` §4; `docs/icao/P1_EXTENSION_HANDLING_POLICY.md` §2 | `./gradlew test --tests it.amhs.service.P1AssociationProtocolTest --tests it.amhs.service.P1BerMessageParserTest --tests it.amhs.service.X411DeliveryReportApduCodecTest --tests it.amhs.service.AMHSDeliveryReportDeterminismEvidenceTest`; `docs/icao/releases/R2026.03/evidence/p1-dr-ndr-interop/20260308T195506Z-run.log`; `docs/icao/releases/R2026.03/evidence/p1-dr-ndr-interop/20260308T195506Z-dr-ndr-trace-ledger.md` | Pass |
| ATN-AMHS-P1-EXT-01 | P1 extension policy | Known/unknown P1 extension elements shall follow frozen deterministic handling rules for release-profile compatibility. | `docs/icao/P1_EXTENSION_HANDLING_POLICY.md` §2.1-§2.3; `docs/icao/releases/R2026.03/PICS_R2026.03.md` §4 | `./gradlew test --tests it.amhs.service.P1AssociationProtocolTest --tests it.amhs.service.P1BerMessageParserTest`; `docs/icao/releases/R2026.03/evidence/p1-dr-ndr-interop/latest-manifest.txt` | Pass |
| ATN-AMHS-P3-01 | P3 gateway services | Declared P3 gateway operations (bind/submit/status/report/release) shall be deterministic with explicit reject semantics for unsupported vectors. | `docs/icao/P3_SERVICE_EXTERNAL_DECLARATION_MATRIX.md` §3; `docs/icao/releases/R2026.03/P3_INTERNAL_PROFILE_STATEMENT.md` §2-§4 | `./gradlew test --tests it.amhs.service.protocol.p3.P3Asn1GatewayProtocolTest --tests it.amhs.service.protocol.p3.P3Asn1GatewayProtocolNegativeVectorsTest --tests it.amhs.service.protocol.p3.P3GatewaySessionServiceTest`; `docs/icao/releases/R2026.03/evidence/p3-negative-apdu/20260308T130945Z-run.log`; `docs/icao/releases/R2026.03/evidence/p3-negative-apdu/latest-manifest.txt` | Pass |
| ATN-AMHS-P3-INT-01 | P3 interoperability campaign | Multi-peer national interoperability execution shall produce reproducible release-tagged logs and pcap-hash outputs. | `docs/icao/NATIONAL_INTEROP_CAMPAIGN_ITALY.md` §2-§4; `docs/icao/ITALY_NATIONAL_USE_REQUIREMENT_MAP.md` §3 | `scripts/evidence/italy_national_interop_campaign.sh`; `scripts/evidence/generate_italy_interop_pcap.py`; `docs/icao/releases/R2026.03/evidence/italy-national-interop/20260308T125750Z-run.log`; `docs/icao/releases/R2026.03/evidence/italy-national-interop/20260308T125750Z-peer-diversity.pcap.sha256` | Pass with environment warning |
| ATN-AMHS-SEC-01 | Security and PKI controls | TLS identity validation, security-label policy, and PKI runtime enforcement shall be evidenced for declared channels and profiles. | `docs/icao/ATN_PKI_SECURITY_LABEL_EVIDENCE.md` §2-§4; `docs/icao/releases/R2026.03/PIXIT_R2026.03.md` §3-§4 | `./gradlew test --tests it.amhs.security.TLSContextFactoryTest --tests it.amhs.compliance.SecurityLabelPolicyTest --tests it.amhs.compliance.AMHSComplianceValidatorTest`; `scripts/evidence/security_pki_label_evidence.sh`; `scripts/evidence/atn_pki_runtime_enforcement_assurance.sh`; `docs/icao/releases/R2026.03/evidence/atn-pki-runtime-enforcement/20260308T195757Z-execution.log` | Pass |
| ATN-AMHS-OPS-01 | Operational controls | Availability, failover, backup/restore, and observability controls shall be validated and release-bound with signed assurance artifacts. | `docs/icao/OPERATIONAL_HA_FAILOVER_EVIDENCE_PACK.md` §4-§7; `OPERATIONS_GUIDE.md` §6-§9 | `scripts/evidence/p1_dr_ndr_interop_traces.sh`; `scripts/evidence/p3_negative_apdu_regression.sh`; `docs/icao/releases/R2026.03/evidence/p1-dr-ndr-interop/20260308T203825Z-run.log`; `docs/icao/releases/R2026.03/evidence/p3-negative-apdu/20260308T130945Z-run.log`; `docs/icao/releases/R2026.03/evidence/operational-assurance/20260308T141500Z-performance-resilience-report.md`; `docs/icao/releases/R2026.03/evidence/operational-assurance/20260308T141500Z-failover-drill-report.md`; `docs/icao/releases/R2026.03/evidence/operational-assurance/latest-manifest.txt` | Pass |

## 5. Sign-off record for external declaration

| Role | Name | Decision | Date (UTC) |
|---|---|---|---|
| Engineering owner | _Pending_ | Pending | - |
| Compliance owner | _Pending_ | Pending | - |
| Security owner | _Pending_ | Pending | - |
| Accountable authority | _Pending_ | Pending | - |

## 6. Closure rule

External declaration is claimable only when all rows in section 4 are `Pass` (or formally risk-accepted with explicit statement), every row satisfies section 2, and section 5 sign-off is complete.
