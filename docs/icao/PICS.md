# AMHS PICS (Protocol Implementation Conformance Statement)

Document status: **gateway-profile baseline** for controlled interoperability, with an explicit closure plan toward ICAO-compliant AMHS server declarations for P1/P3 service areas.

## 1. Scope

This PICS describes the currently implemented behavior of this AMHS server for the following protocol areas:

- RFC1006 / TPKT / COTP transport handling
- ACSE association handling (X.227-oriented, profile-limited)
- P1/P3 gateway envelope/content processing (X.411-oriented subset)
- O/R Address and O/R Name validation constraints
- Routing, retry, and delivery-report persistence behavior

## 2. Claimed implementation class

- **Implementation type**: AMHS gateway-oriented server with inbound processing and outbound relay support.
- **Conformance claim level**: profile-limited implementation for controlled lab/integration usage; **not** a declared full external P3 endpoint conformance claim.

## 3. Capability matrix (PICS-style answers)

Legend:

- **Y**: implemented
- **N**: not implemented
- **P**: partially implemented

| Ref | Capability | Status | Notes |
|---|---|---|---|
| T-01 | TPKT version/length validation | Y | Rejects invalid framing. |
| T-02 | COTP CR/CC negotiation | Y | Class 0 association flow supported. |
| T-03 | TPDU size negotiation | Y | Negotiated and enforced with limits. |
| T-04 | COTP segmentation/reassembly | Y | Handles segmented payloads. |
| T-05 | COTP DR/ER handling | Y | Disconnect and error TPDUs handled. |
| T-06 | Idle timeout / frame size guard | Y | Idle and max-frame controls enforced. |
| A-01 | ACSE AARQ decoding and checks | Y | Application context and identity checks for supported gateway profile paths. |
| A-02 | ACSE AARE structured response | Y | Result + diagnostic container emitted for supported flows, including deterministic rejection diagnostics for invalid AARQ profile elements. |
| A-03 | Presentation context negotiation | P | Basic/controlled negotiation support; not a full profile-complete negotiation stack. |
| A-04 | ACSE user-information semantics | P | Supported through constrained EXTERNAL/OCTET STRING handling path. |
| A-05 | AP-title / AE-qualifier structures | P | Core structures supported; not a broad complete ACSE interoperability claim. |
| A-06 | Authentication-value semantics | P | Implemented for configured policy checks, not exhaustive profile-semantic coverage. |
| A-07 | P3 bind/re-bind/release error semantics | Y | Single-bind association policy, release-before-bind diagnostics, and post-release association-closed diagnostics are enforced. |
| U-01 | ROSE operation coverage for full P3 service set | Y | Full gateway-profile ROSE semantics are implemented: request operations map deterministically, request/response role mismatches are rejected with explicit diagnostics, and unexpected non-invoke ROSE APDUs produce deterministic ROSE reject responses. |
| U-02 | RTSE behavior coverage | Y | RTSE wrapper semantics are implemented for the declared gateway profile operations, including deterministic `RTORQ`/`RTOAC`, `RTTD`/`RTTR`, `RTAB`, and `RTORJ` rejection paths. |
| U-03 | Session semantics beyond wrapper preservation | P | Session/presentation envelopes are preserved/rewrapped in supported gateway paths. |
| U-04 | Complete X.411/P3 service behavior and error semantics | P | Gateway service now provides explicit bind/submit/status/report/release behavior with deterministic error semantics; full externally certifiable profile breadth remains pending. |
| P1-01 | BER parsing for P1-like envelope | Y | Structured BER/TLV support in parser. |
| P1-02 | Envelope/content separation | Y | Envelope and content are separated. |
| P1-03 | Per-recipient handling | Y | Per-recipient routing state supported. |
| P1-04 | Trace information handling | Y | Trace extraction/injection supported. |
| P1-05 | Unknown extension preservation | Y | Unknown extension containers retained. |
| P1-06 | Full X.411 ASN.1 module conformance | P | Runtime profile tag-table checks, DR/NDR BER evidence, and canonical module-level ASN.1 proof-pack traceability are implemented for the declared gateway profile (`docs/icao/X411_CANONICAL_ASN1_MODULE_PROOF.md`). |
| OR-01 | Structured O/R Address parsing | Y | Supports keyed O/R attribute model. |
| OR-02 | OU sequencing validation (OU1..OU4) | Y | Enforces non-skipping OU order. |
| OR-03 | ISO/Numeric country validation | Y | Country checks for C attribute. |
| OR-04 | Full ORName CHOICE coverage | Y | DirectoryName-only and ORAddress-only CHOICE paths are decoded and normalized into canonical O/R attributes with ICAO validation hooks, including strict 8-letter ICAO unit checks. |
| OR-05 | Teletex/DirectoryName compatibility | Y | Teletex, BMPString, UniversalString, IA5 and PrintableString variants are decoded for DirectoryName/legacy paths. |
| SEC-01 | TLS transport protection | Y | Server TLS supported; optional client auth. |
| SEC-02 | Certificate CN/OU channel policy | Y | Channel policy and sender binding checks. |
| SEC-03 | Full PKI path validation profile | C | PKIX trust-path validation controls (including required policy OIDs) are implemented and release-bound evidence is published in `docs/icao/ATN_PKI_SECURITY_LABEL_EVIDENCE.md`. |
| SEC-04 | CRL / OCSP runtime enforcement | C | Runtime revocation control is enforced via PKIX revocation checker wiring (`tls.pkix.revocation-enabled`) with release evidence package and reproducible campaign script in `docs/icao/ATN_PKI_SECURITY_LABEL_EVIDENCE.md`. |
| SEC-05 | Security label enforcement (Doc 9880) | C | Classification ordering, compartment syntax checks, and dominance enforcement are implemented with gateway bind-path diagnostics and evidence mapped in `docs/icao/ATN_PKI_SECURITY_LABEL_EVIDENCE.md`. |
| R-01 | Outbound relay routing table | Y | Prefix-based route selection implemented. |
| R-02 | Alternate route fallback | Y | Alternate next-hop path supported. |
| R-03 | Retry with exponential backoff | Y | Retry policy and dead-letter path supported. |
| R-04 | NDR/DR protocol-level correlation | Y | DR/NDR reports now persist `related_mts_identifier` and `correlation_token` for protocol-level message/report linkage. |
| D-01 | Negative diagnostic mapping completeness | Y | Dedicated X.411 diagnostic mapper covers timeout, routing, loop, security/auth and validation failure classes with explicit/fallback code selection. |
| O-01 | Operational HA/failover profile | Y | Formal oversight evidence baseline published in `docs/icao/OPERATIONAL_HA_FAILOVER_EVIDENCE_PACK.md`; periodic drill artifacts remain release-operational obligations. |

## 4. Protocol P3 section (profile declaration)

This implementation exposes a **gateway-oriented P3 profile** and does not currently claim full ICAO-certifiable end-to-end P3 conformance.

### 4.1 Supported P3 behaviors

- ACSE association establishment/release for the constrained gateway profile.
- Bind lifecycle guards:
  - single active bind per association,
  - re-bind rejection while bound,
  - explicit diagnostics for operations attempted before bind or after release.
- Submission-oriented message ingress mapped into the internal AMHS canonical message model.
- O/R Name and O/R Address normalization with ICAO-oriented validation hooks.
- Delivery/Non-delivery report persistence with protocol-level correlation fields (`related_mts_identifier`, `correlation_token`).

### 4.2 Declared limitations for P3

- ROSE operation/error mapping now enforces full declared gateway-profile semantics for bind/submit/status/report/release, including deterministic diagnostics for unsupported operations, request/response role misuse, and unexpected non-invoke ROSE APDUs.
- RTSE wrapper behavior is implemented for the declared gateway operation subset; broader external profile breadth beyond the gateway declaration remains out of scope.
- Presentation/ACSE negotiation semantics are implemented for supported paths only, not as a universal full interoperability surface.
- CRL/OCSP runtime checks are available via PKIX revocation toggles (`tls.pkix.revocation-enabled` + JVM security policy), but external-claim completeness still depends on release-bound objective evidence.
- Security label behavior now enforces Doc 9880-style classification ordering and compartment dominance for gateway labels, but full certifiable policy scope remains pending.

### 4.3 Interoperability posture

- Intended for controlled integration and gateway scenarios where peer expectations are aligned with the declared profile.
- External operational declaration as a fully conformant P3 endpoint requires closure of all items in Section 5.

### 4.4 Release-bound configuration fingerprint

This PICS baseline is bound to release fingerprint material in:

- `docs/icao/releases/R2026.03/CONFIGURATION_FINGERPRINT.txt`

The fingerprint pins transport ports, TLS modes, listener profile, and route/policy feature flags that scope the declared behavior for this release.

## 5. P3 compliance evaluation by usage scope

The table below evaluates the current P3 posture for three declaration scopes requested by operators: internal use, national deployment (Italy), and ICAO-oriented external declaration.

| Scope | Current verdict | Rationale from implemented evidence | What is still missing |
|---|---|---|---|
| Internal use (single-organization / controlled peers) | **Acceptable for release `R2026.03` baseline** | Internal P3 operation profile statement, deterministic negative APDU regression script/artifacts, and release fingerprint binding are published and traceable. | No structural gap for the declared internal baseline. For each new release, re-run the negative campaign, refresh artifacts, and republish fingerprint-bound PICS/PIXIT. |
| National use (Italy, multi-organization operational use) | **Ready for national-use baseline declaration (`R2026.03`)** | Italy requirement map, reproducible interoperability campaign, and authority-facing national declaration package are published (`§5.2` items 4..6). | No structural national-use gap remains for `R2026.03`; maintain release-bound evidence refresh and approval sign-off per declaration cycle. |
| ICAO-oriented external declaration | **Not yet compliant for external claim** | Gateway-profile P3 behavior and deterministic diagnostics are declared, but this is not a full external P3 endpoint claim. | Close all open ICAO claim items in `§5.3`, `§6`, and `§7` (profile-complete semantics evidence, ASN.1 module proof, ATN PKI + CRL/OCSP evidence, Doc 9880 security-label treatment, operational assurance pack, governance sign-off artifacts). |

### 5.1 Internal-use gap closure (minimum)

Status for `R2026.03`: **closed at minimum baseline** with release-bound artifacts:

1. Release-specific internal P3 operation profile + diagnostics: `docs/icao/releases/R2026.03/P3_INTERNAL_PROFILE_STATEMENT.md`.
2. Automated malformed/negative APDU regression + artifact preservation: `scripts/evidence/p3_negative_apdu_regression.sh` publishing under `docs/icao/releases/R2026.03/evidence/p3-negative-apdu/`.
3. PICS/PIXIT release fingerprint binding: `docs/icao/releases/R2026.03/CONFIGURATION_FINGERPRINT.txt`.

### 5.2 National-use (Italy) gap closure

4. ✅ Closed (`R2026.03`): traceable requirement map published in `docs/icao/ITALY_NATIONAL_USE_REQUIREMENT_MAP.md` from adopted AMHS profile obligations to implementation/tests/evidence artifacts.
5. ✅ Closed (`R2026.03`): national interoperability campaign executed with reproducible logs + pcaps and peer-diversity model, published in `docs/icao/NATIONAL_INTEROP_CAMPAIGN_ITALY.md` and `docs/icao/releases/R2026.03/evidence/italy-national-interop/`.
6. ✅ Closed (`R2026.03`): national declaration package published in `docs/icao/ITALY_NATIONAL_DECLARATION_PACKAGE.md` covering operational responsibilities, security controls (PKI revocation behavior included), incident/failover procedures, and authority-facing approvals.

### 5.3 ICAO external-claim gap closure

7. ✅ Closed (`R2026.03`): non-claim boundary for external P3 profile-complete semantics is formalized with an authority-acceptance workflow in `docs/icao/ICAO_EXTERNAL_P3_NONCLAIM_BOUNDARY_ACCEPTANCE.md`.
8. ✅ Closed (`R2026.03`): canonical X.411 ASN.1 module traceability proof pack linked to runtime behavior and test vectors is published in `docs/icao/X411_CANONICAL_ASN1_MODULE_PROOF.md`.
9. Complete objective security evidence for ATN PKI path validation, CRL/OCSP handling, and Doc 9880-aligned security-label policy treatment.
10. ✅ Closed (`R2026.03`): operational assurance evidence set is published under `docs/icao/releases/R2026.03/evidence/operational-assurance/` including performance/resilience qualification, SLO declaration, monitoring/alerting export summary, failover drill report, and backup/restore verification.

### 5.4 Consolidated “still missing” checklist for protocol P3

This checklist summarizes only open items after the `R2026.03` baseline evaluation.

- **Internal use**
  - No open structural gap for the declared baseline profile.
  - Recurring release obligation: regenerate evidence + fingerprint-bound declarations.
- **National use (Italy)**
  - No open structural gap for the declared national-use baseline.
  - Recurring release obligation: refresh campaign/declaration artifacts and approval records.
- **ICAO external claim**
  - Complete `§5.3` items 8..10 (item 7 closed via non-claim boundary acceptance path).
  - Complete all mandatory evidence/governance items in `§6` and delivery steps in `§7`.

## 6. Missing points for ICAO compliance closure

The following items are currently open and should be treated as mandatory closure points before claiming ICAO-oriented external compliance.

### 6.1 Standards/profile conformance evidence

1. ⚠️ Closure artifact published for `R2026.03` at `docs/icao/ICAO_ATN_PROFILE_REQUIREMENT_TRACEABILITY.md`; sign-off remains mandatory before external claim.
2. ⚠️ Closure artifact published for `R2026.03` at `docs/icao/P3_SERVICE_EXTERNAL_DECLARATION_MATRIX.md`; explicit authority sign-off remains mandatory before external claim.
3. ✅ Closed (`R2026.03`): ASN.1 traceability package proving canonical X.411 module/tag alignment (beyond runtime profile-table checks) is published in `docs/icao/X411_CANONICAL_ASN1_MODULE_PROOF.md`.

### 6.2 Interoperability campaign evidence

4. Multi-peer interoperability campaign (including at least one certified AMHS implementation) with reproducible logs and pcaps.
5. Negative-scenario campaign pack (malformed TPDU, ACSE rejection vectors, unsupported P3 operations) with deterministic verdicts.
6. Evidence of behavior with legacy peer encodings for O/R and DirectoryName variants observed in operational networks.

### 6.3 Security and PKI compliance

7. ✅ Closed (`R2026.03`): ATN PKI profile statement with objective evidence for certificate path-validation behavior is published in `docs/icao/ATN_PKI_SECURITY_LABEL_EVIDENCE.md`.
8. ✅ Closed (`R2026.03`): CRL/OCSP runtime enforcement handling controls and reproducible evidence-generation procedure are documented in `docs/icao/ATN_PKI_SECURITY_LABEL_EVIDENCE.md`.
9. ✅ Closed (`R2026.03`): formal security-label policy treatment aligned to Doc 9880-style classification/compartment dominance behavior is documented in `docs/icao/ATN_PKI_SECURITY_LABEL_EVIDENCE.md`.

### 6.4 Operational assurance

10. ✅ Closed (`R2026.03`): performance/resilience qualification under sustained load, including retry/fallback and recovery behavior (`docs/icao/releases/R2026.03/evidence/operational-assurance/20260308T141500Z-performance-resilience-report.md`).
11. ✅ Closed (`R2026.03`): operational readiness execution artifacts for release `R2026.03` are published in `docs/icao/releases/R2026.03/evidence/operational-assurance/` (SLO declaration, monitoring/alerting export summary, failover drill report, backup/restore verification; baseline structure in `docs/icao/OPERATIONAL_HA_FAILOVER_EVIDENCE_PACK.md`).
12. ✅ Closed (`R2026.03`): safety/security assessment records with residual-risk acceptance by accountable authority are published in `docs/icao/releases/R2026.03/evidence/operational-assurance/20260308T141500Z-safety-security-residual-risk-acceptance.md`.

### 6.5 Governance and declaration artifacts

13. Completed PICS/PIXIT set tied to a specific release baseline and configuration fingerprint.
14. Conformance test matrix verdict completion with artifact references per row.
15. National oversight packaging (including any EU/Italy-specific authority expectations) with traceable approval records.

## 7. P1/P3 ICAO-compliance build plan (implementation-oriented)

This section translates open closure points into a concrete delivery plan for building an AMHS server profile that can be declared ICAO-compliant for P1/P3 scope once all evidence is complete.

### 7.1 Target declaration profile

- **P1 target**: externalized MTS relay/interpersonal handling profile aligned with X.411 module definitions and deterministic DR/NDR behavior.
- **P3 target**: externally declared P3 endpoint profile (beyond gateway-only posture) with full documented operation/error semantics.
- **Security target**: ATN PKI + Doc 9880-aligned operational evidence set suitable for oversight review.

### 7.2 Required technical closure for P1

1. ✅ Closed (`R2026.03`): canonical ASN.1 module-level proof package for X.411 is linked to runtime codec behavior and BER vectors in `docs/icao/X411_CANONICAL_ASN1_MODULE_PROOF.md`.
2. Freeze and sign-off extension handling rules (known + unknown elements) with backward-compatibility checks.
3. Complete end-to-end DR/NDR interoperability traces proving correlation and semantic consistency across peers.

### 7.3 Required technical closure for P3

4. ACSE/presentation negotiation behavior matrix completed and published (`docs/icao/ACSE_PRESENTATION_NEGOTIATION_MATRIX.md`) for external interoperability declaration vectors.
5. Produce reproducible multi-vendor bind/submit/status/report/release evidence with negative-path diagnostics.

### 7.4 Compliance packaging required before claim

7. Publish release-bound PICS + PIXIT with configuration fingerprint and feature flags.
8. Link each conformance matrix row to executable test artifacts/logs/pcaps.
9. Package authority-facing declaration dossier (technical evidence, security evidence, operational controls, residual-risk approvals).

## 8. Evidence pointers in this repository

- Transport and parser tests under `src/test/java/it/amhs/service/`.
- BER codec tests under `src/test/java/it/amhs/asn1/`.
- Compliance and address validation tests under `src/test/java/it/amhs/compliance/` and `src/test/java/it/amhs/service/ORAddressTest.java`.
- ACSE/presentation external declaration matrix under `docs/icao/ACSE_PRESENTATION_NEGOTIATION_MATRIX.md`.
