# AMHS PICS (Protocol Implementation Conformance Statement)

Document status: **authority-ready release baseline (`R2026.03`)** for controlled interoperability, with technical and governance closure artifacts assembled for authority-facing review.

Last updated: `2026-03-08` (synchronized with the release-bound wrapper `docs/icao/releases/R2026.03/PICS_R2026.03.md`).

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
- **C**: implemented and closure-evidenced for `R2026.03` (claim still scoped by declaration/governance boundary)

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
| ICAO-oriented external declaration | **Submission-ready declared baseline (`R2026.03`)** | External declaration corpus, security/operational assurance artifacts, and governance approval records are published as a release-bound dossier. | No structural baseline gap remains for `R2026.03`; external authority acceptance workflow and release-over-release delta revalidation remain recurring obligations. |

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
9. ✅ Closed (`R2026.03`): objective security evidence for ATN PKI path validation, CRL/OCSP handling, and Doc 9880-aligned security-label policy treatment is published in `docs/icao/ATN_PKI_SECURITY_LABEL_EVIDENCE.md`.
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
  - No structural baseline gap remains for `R2026.03`; maintain recurring authority acceptance workflow execution and release-to-release evidence refresh.

## 6. ICAO compliance closure status

The following list tracks closure status for ICAO-oriented external compliance. For `R2026.03`, the technical artifacts and governance records are published in a release-bound authority dossier.

### 6.1 Standards/profile conformance evidence

1. ✅ Closed (`R2026.03`): profile requirement traceability and declaration governance references are published at `docs/icao/ICAO_ATN_PROFILE_REQUIREMENT_TRACEABILITY.md` and linked in `docs/icao/AUTHORITY_READY_DOSSIER_R2026.03.md`.
2. ✅ Closed (`R2026.03`): external declaration matrix with accountable review chain references is published at `docs/icao/P3_SERVICE_EXTERNAL_DECLARATION_MATRIX.md` and indexed in `docs/icao/AUTHORITY_READY_DOSSIER_R2026.03.md`.
3. ✅ Closed (`R2026.03`): ASN.1 traceability package proving canonical X.411 module/tag alignment (beyond runtime profile-table checks) is published in `docs/icao/X411_CANONICAL_ASN1_MODULE_PROOF.md`.

### 6.2 Interoperability campaign evidence

4. ✅ Closed (`R2026.03`): multi-peer interoperability campaign (including certified AMHS lab peer profile) with reproducible logs and pcaps is published in `docs/icao/ICAO_INTEROPERABILITY_CLOSURE_EVIDENCE.md` and `docs/icao/releases/R2026.03/evidence/italy-national-interop/`.
5. ✅ Closed (`R2026.03`): negative-scenario campaign pack covering malformed TPDU, ACSE rejection vectors, and unsupported P3 operations with deterministic verdicts is published in `docs/icao/ICAO_INTEROPERABILITY_CLOSURE_EVIDENCE.md` and `docs/icao/releases/R2026.03/evidence/p3-negative-apdu/`.
6. ✅ Closed (`R2026.03`): legacy peer encoding behavior for O/R and DirectoryName variants is evidenced via deterministic ORName/DirectoryName tests and campaign artifacts in `docs/icao/ICAO_INTEROPERABILITY_CLOSURE_EVIDENCE.md`.

### 6.3 Security and PKI compliance

7. ✅ Closed (`R2026.03`): ATN PKI profile statement with objective evidence for certificate path-validation behavior is published in `docs/icao/ATN_PKI_SECURITY_LABEL_EVIDENCE.md`.
8. ✅ Closed (`R2026.03`): CRL/OCSP runtime enforcement handling controls and reproducible evidence-generation procedure are documented in `docs/icao/ATN_PKI_SECURITY_LABEL_EVIDENCE.md`.
9. ✅ Closed (`R2026.03`): formal security-label policy treatment aligned to Doc 9880-style classification/compartment dominance behavior is documented in `docs/icao/ATN_PKI_SECURITY_LABEL_EVIDENCE.md`.

### 6.4 Operational assurance

10. ✅ Closed (`R2026.03`): performance/resilience qualification under sustained load, including retry/fallback and recovery behavior (`docs/icao/releases/R2026.03/evidence/operational-assurance/20260308T141500Z-performance-resilience-report.md`).
11. ✅ Closed (`R2026.03`): operational readiness execution artifacts for release `R2026.03` are published in `docs/icao/releases/R2026.03/evidence/operational-assurance/` (SLO declaration, monitoring/alerting export summary, failover drill report, backup/restore verification; baseline structure in `docs/icao/OPERATIONAL_HA_FAILOVER_EVIDENCE_PACK.md`).
12. ✅ Closed (`R2026.03`): safety/security assessment records with residual-risk acceptance by accountable authority are published in `docs/icao/releases/R2026.03/evidence/operational-assurance/20260308T141500Z-safety-security-residual-risk-acceptance.md`.

### 6.5 Governance and declaration artifacts

13. ✅ Closed (`R2026.03`): completed release-bound PICS/PIXIT set is published (`docs/icao/PICS.md`, `docs/icao/PIXIT.md`, `docs/icao/releases/R2026.03/PICS_R2026.03.md`, `docs/icao/releases/R2026.03/PIXIT_R2026.03.md`) and cryptographically tied to `docs/icao/releases/R2026.03/CONFIGURATION_FINGERPRINT.txt`.
14. ✅ Closed (`R2026.03`): conformance test matrix verdicts and row-level artifact references are completed in `docs/icao/CONFORMANCE_TEST_MATRIX.md`.
15. ✅ Closed (`R2026.03`): national oversight packaging (EU/Italy baseline) with traceable approval records is published in `docs/icao/ITALY_NATIONAL_DECLARATION_PACKAGE.md` and `docs/icao/releases/R2026.03/evidence/italy-national-interop/20260308T150500Z-approval-register.md`.

16. ✅ Closed (`R2026.03`): declaration-profile deterministic behavior contracts for DR/NDR, ACSE reject paths, and unsupported-operation semantics are versioned and published in `docs/icao/contracts/R2026.03/DECLARATION_BEHAVIOR_CONTRACT.md` (`DECL-BEHAVIOR-R2026.03`) with explicit release-blocking divergence policy.

## 7. P1/P3 ICAO-compliance build plan (implementation-oriented)

This section translates open closure points into a concrete delivery plan for building an AMHS server profile that can be declared ICAO-compliant for P1/P3 scope once all evidence is complete.

### 7.1 Target declaration profile

- **P1 target**: externalized MTS relay/interpersonal handling profile aligned with X.411 module definitions and deterministic DR/NDR behavior.
- **P3 target**: externally declared P3 endpoint profile (beyond gateway-only posture) with full documented operation/error semantics.
- **Security target**: ATN PKI + Doc 9880-aligned operational evidence set suitable for oversight review.

Implementation framing for the declaration profile:

1. **Release-bounded declaration baseline**
   - Pin declaration to a single release tag with immutable build fingerprint (commit SHA, artifact digest, active feature flags, runtime profile hash).
   - Enforce “no declaration without artifact manifest” gate in release CI.
   - Implemented baseline controls for `R2026.03`: declaration artifact manifest (`docs/icao/releases/R2026.03/DECLARATION_ARTIFACT_MANIFEST.txt`), fingerprint linkage (`docs/icao/releases/R2026.03/CONFIGURATION_FINGERPRINT.txt`), and CI gate script/workflow (`scripts/release/verify_declaration_gate.sh`, `.github/workflows/release-declaration-gate.yml`).
2. **Single-source conformance map**
   - Maintain one requirement-to-evidence matrix covering P1, P3, security, and operational controls.
   - Require every declaration statement to link to at least one executable test/log/pcap artifact and one governing document section.
3. **Deterministic behavior policy**
   - ✅ Closed (`R2026.03`): DR/NDR, ACSE reject paths, and unsupported-operation semantics are promoted to normative, versioned behavior contracts in `docs/icao/contracts/R2026.03/DECLARATION_BEHAVIOR_CONTRACT.md` (`DECL-BEHAVIOR-R2026.03`).
   - ✅ Closed (`R2026.03`): runtime divergence from contract semantics is release-blocking for declaration claims under the release gate defined by `docs/icao/contracts/R2026.03/DECLARATION_BEHAVIOR_CONTRACT.md`.

### 7.1.1 P1 implementation work packages

1. **MTS relay/interpersonal profile hardening**
   - Finalize supported P1 service subset and explicitly encode unsupported behaviors with stable diagnostics.
   - Lock message-transfer and interpersonal handling semantics to X.411 canonical module interpretation proven in ASN.1 evidence.
2. **DR/NDR determinism evidence**
   - Build reproducible scenarios for delivery success, non-delivery, delay, redirection, and transfer-failure outcomes.
   - Capture cross-peer trace chain (ingress event → queue state → emitted DR/NDR → peer acknowledgment) with correlation IDs.
   - ✅ Closed (`R2026.03`): scenario and trace-chain evidence is published in `docs/icao/releases/R2026.03/evidence/p1-dr-ndr-interop/latest-manifest.txt` and the corresponding timestamped `*-dr-ndr-trace-ledger.md`.
3. **Extension and compatibility governance**
   - Freeze extension handling policy (known/unknown elements, criticality handling, forward/backward compatibility).
   - Add regression vectors for legacy encodings observed in operational AMHS environments.

### 7.1.2 P3 implementation work packages

1. **External endpoint profile completion**
   - ✅ Closed (`R2026.03`): complete operation matrix (bind, submit, probe/status, report handling, release, abort, reject/error classes) is published in `docs/icao/P3_SERVICE_EXTERNAL_DECLARATION_MATRIX.md`.
   - ✅ Closed (`R2026.03`): explicit unsupported/malformed input semantics with deterministic reject reason mapping are published in `docs/icao/P3_SERVICE_EXTERNAL_DECLARATION_MATRIX.md` section 4 and release-locked to `docs/icao/releases/R2026.03/P3_INTERNAL_PROFILE_STATEMENT.md`.
2. **Negotiation and error semantics closure**
   - Complete ACSE/presentation matrix with all selector/context-name/authentication permutations needed for external claim.
   - Attach packet-level and log-level evidence for success and failure paths, including negative vectors.
3. **Multi-vendor interoperability campaign**
   - Run repeatable campaign against at least one certified AMHS implementation plus an additional heterogenous stack.
   - Produce signed campaign report with replay instructions and artifact manifest (pcaps, decoded traces, verdict ledger).

### 7.1.3 Security/oversight evidence work packages

1. **ATN PKI runtime enforcement assurance**
   - ✅ Closed (`R2026.03`): path validation, CRL/OCSP enforcement controls, revocation-freshness inputs, and fail-closed degraded-PKI behavior are evidenced in `docs/icao/releases/R2026.03/evidence/atn-pki-runtime-enforcement/20260308T200850Z-verdict.md` and `docs/icao/releases/R2026.03/evidence/atn-pki-runtime-enforcement/20260308T200850Z-execution.log`.
   - ✅ Closed (`R2026.03`): each control is tied to objective runtime proof (`configuration snapshot + execution log + verdict`) and release-indexed in `docs/icao/releases/R2026.03/evidence/atn-pki-runtime-enforcement/20260308T200850Z-manifest.txt` (`latest-manifest.txt` pointer maintained for oversight retrieval).
2. **Doc 9880-aligned security-label operations**
   - ✅ Closed (`R2026.03`): label parsing, dominance decisions, downgrade/upgrade constraints, and rejection semantics under mixed-label traffic are evidenced in `docs/icao/releases/R2026.03/evidence/security-pki-label/20260308T152500Z-doc9880-label-operations-oversight-record.md`.
   - ✅ Closed (`R2026.03`): residual-risk decisions for local policy tailoring are recorded with accountable-authority acceptance linkage (`AA-R2026.03-OPS-SEC-001`) in `docs/icao/releases/R2026.03/evidence/security-pki-label/20260308T152500Z-doc9880-label-operations-oversight-record.md` and `docs/icao/releases/R2026.03/evidence/operational-assurance/20260308T141500Z-safety-security-residual-risk-acceptance.md`.
3. **Authority-ready dossier assembly**
   - ✅ Closed (`R2026.03`): technical conformance evidence, operational assurance pack, security assurance pack, and governance approvals are assembled into one indexable dossier in `docs/icao/AUTHORITY_READY_DOSSIER_R2026.03.md`.
   - ✅ Closed (`R2026.03`): change-impact delta for oversight revalidation is documented in section 5 of `docs/icao/AUTHORITY_READY_DOSSIER_R2026.03.md`, including baseline handling where no prior declared release exists in this repository.

### 7.2 Required technical closure for P1

1. ✅ Closed (`R2026.03`): canonical ASN.1 module-level proof package for X.411 is linked to runtime codec behavior and BER vectors in `docs/icao/X411_CANONICAL_ASN1_MODULE_PROOF.md`.
2. ✅ Closed (`R2026.03`): extension handling rules (known + unknown elements), criticality posture, and backward-compatibility checks are frozen and signed in `docs/icao/P1_EXTENSION_HANDLING_POLICY.md`, with regression vectors in `src/test/java/it/amhs/service/P1AssociationProtocolTest.java` and `src/test/java/it/amhs/service/P1BerMessageParserTest.java`.
3. ✅ Closed (`R2026.03`): end-to-end DR/NDR interoperability traces with correlation evidence are published in `docs/icao/releases/R2026.03/evidence/p1-dr-ndr-interop/20260308T195506Z-dr-ndr-trace-ledger.md` and indexed by `docs/icao/releases/R2026.03/evidence/p1-dr-ndr-interop/latest-manifest.txt`.

### 7.3 Required technical closure for P3

4. ✅ Closed (`R2026.03`): ACSE/presentation negotiation behavior matrix is completed and published in `docs/icao/ACSE_PRESENTATION_NEGOTIATION_MATRIX.md` for external interoperability declaration vectors.
5. ✅ Closed (`R2026.03`): reproducible multi-vendor bind/submit/status/report/release evidence with negative-path diagnostics is published in `docs/icao/ICAO_INTEROPERABILITY_CLOSURE_EVIDENCE.md` and manifest-linked under `docs/icao/releases/R2026.03/evidence/italy-national-interop/latest-manifest.txt` and `docs/icao/releases/R2026.03/evidence/p3-negative-apdu/latest-manifest.txt`.
6. ✅ Closed (`R2026.03`): external endpoint profile completion (complete operation matrix + deterministic unsupported/malformed reject mapping) is published in `docs/icao/P3_SERVICE_EXTERNAL_DECLARATION_MATRIX.md`, with release-binding in `docs/icao/releases/R2026.03/P3_INTERNAL_PROFILE_STATEMENT.md`.

### 7.4 Compliance packaging required before claim

7. ✅ Closed (`R2026.03`): release-bound PICS + PIXIT with configuration fingerprint and feature flags are published in `docs/icao/PICS.md`, `docs/icao/PIXIT.md`, and `docs/icao/releases/R2026.03/CONFIGURATION_FINGERPRINT.txt`.
8. ✅ Closed (`R2026.03`): conformance matrix rows are linked to executable test artifacts/logs/pcaps in `docs/icao/CONFORMANCE_TEST_MATRIX.md`.
9. ✅ Closed (`R2026.03`): authority-facing declaration dossier packaging is published in `docs/icao/AUTHORITY_READY_DOSSIER_R2026.03.md`.

## 8. Evidence pointers in this repository

- Release-bound declaration package index under `docs/icao/releases/R2026.03/AUTHORITY_DECLARATION_DOSSIER.md`.
- Transport and parser tests under `src/test/java/it/amhs/service/`.
- BER codec tests under `src/test/java/it/amhs/asn1/`.
- Compliance and address validation tests under `src/test/java/it/amhs/compliance/` and `src/test/java/it/amhs/service/ORAddressTest.java`.
- ACSE/presentation external declaration matrix under `docs/icao/ACSE_PRESENTATION_NEGOTIATION_MATRIX.md`.
