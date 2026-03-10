# AMHS PICS (Protocol Implementation Conformance Statement)

Document status: **profile-limited implementation baseline (`R2026.03`)** with explicit gap-oriented assessment for internal, national, and ICAO deployment contexts.

Last updated: `2026-03-10` (added a repository-based reality-check for internal, national, and ICAO usage scopes and adjusted readiness wording to reflect implemented-vs-missing capability boundaries).

Revision note (`2026-03-10`): integrated a verification section that classifies requested capability statements as true/partial/false against codebase evidence, and replaced scope-readiness text with a conservative gap-oriented assessment for internal, national, and ICAO deployment contexts.

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
- **Declaration governance boundary**: ICAO-facing claim scope is constrained by the accepted non-claim boundary and external declaration matrix (`docs/icao/ICAO_EXTERNAL_P3_NONCLAIM_BOUNDARY_ACCEPTANCE.md`, `docs/icao/P3_SERVICE_EXTERNAL_DECLARATION_MATRIX.md`).

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
| A-03 | Presentation context negotiation | Y | Profile-complete presentation-context negotiation semantics are enforced, including deterministic AMHS abstract/transfer-syntax compatibility validation and context-id acceptance selection. |
| A-04 | ACSE user-information semantics | Y | Supports AMHS association payload extraction across interoperable ACSE user-information EXTERNAL variants (including octet-aligned and metadata-bearing forms). |
| A-05 | AP-title / AE-qualifier structures | C | Certifiable interoperability breadth is declared for AP-title ↔ AE-title/AE-qualifier pairing semantics, including positive and negative deterministic diagnostics. |
| A-06 | Authentication-value semantics | C | Certifiable interoperability breadth is declared for optional/required/expected authentication-value permutations with deterministic acceptance/rejection diagnostics. |
| A-07 | P3 bind/re-bind/release error semantics | Y | Single-bind association policy, release-before-bind diagnostics, and post-release association-closed diagnostics are enforced. |
| U-01 | ROSE operation coverage for full P3 service set | Y | Full gateway-profile ROSE semantics are implemented: request operations map deterministically, request/response role mismatches are rejected with explicit diagnostics, and unexpected non-invoke ROSE APDUs produce deterministic ROSE reject responses. |
| U-02 | RTSE behavior coverage | Y | RTSE wrapper semantics are implemented for the declared gateway profile operations, including deterministic `RTORQ`/`RTOAC`, `RTTD`/`RTTR`, `RTAB`, and `RTORJ` rejection paths. |
| U-03 | Session semantics beyond wrapper preservation | Y | Session/presentation responses are emitted with deterministic external semantics (session connect→accept mapping, presentation connect→CPA mapping, and ACSE AARQ→AARE mapping) while preserving declared gateway payload behavior. |
| U-04 | Complete X.411/P3 service behavior and error semantics | C | Runtime breadth coverage now hardens all externally claimed APDU/service variants (direct gateway APDUs plus ROSE/RTSE claim surface) with deterministic success/error role semantics. |
| P1-01 | BER parsing for P1-like envelope | Y | Structured BER/TLV support in parser. |
| P1-02 | Envelope/content separation | Y | Envelope and content are separated. |
| P1-03 | Per-recipient handling | Y | Per-recipient routing state supported. |
| P1-04 | Trace information handling | Y | Trace extraction/injection supported. |
| P1-05 | Unknown extension preservation | Y | Unknown extension containers retained. |
| P1-06 | Full X.411 ASN.1 module conformance | C | Canonical module proof, runtime tag-table checks, and executable breadth coverage now span all externally claimed P1/P3 APDU-service variants for the declared profile (`docs/icao/X411_CANONICAL_ASN1_MODULE_PROOF.md`). |
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
| G-01 | External declaration governance boundary traceability | C | External declaration scope is explicitly controlled by the non-claim boundary acceptance and service declaration matrix (`docs/icao/ICAO_EXTERNAL_P3_NONCLAIM_BOUNDARY_ACCEPTANCE.md`, `docs/icao/P3_SERVICE_EXTERNAL_DECLARATION_MATRIX.md`). |

## 4. Protocol P3 section (profile declaration)

This implementation exposes a **gateway-oriented P3 profile** and does not currently claim full ICAO-certifiable end-to-end P3 conformance.

### 4.1 Supported P3 behaviors

- ACSE association establishment/release for the constrained gateway profile.
- Bind lifecycle guards:
  - single active bind per association,
  - re-bind rejection while bound,
  - explicit diagnostics for operations attempted before bind or after release.
- Submission-oriented message ingress and deterministic status/report/read query handling mapped into the internal AMHS canonical model.
- O/R Name and O/R Address normalization with ICAO-oriented validation hooks.
- Delivery/Non-delivery report persistence with protocol-level correlation fields (`related_mts_identifier`, `correlation_token`).

### 4.2 Declared limitations for P3

- ROSE operation/error mapping now enforces full declared gateway-profile semantics for bind/submit/status/report/read/release, including deterministic diagnostics for unsupported operations, request/response role misuse, and unexpected non-invoke ROSE APDUs.
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

## 5. Reality-check assessment (internal / national / ICAO)

This section validates the requested assessment against what is actually implemented in this repository.

### 5.1 Verification of statements

| Statement from assessment | Verification | Evidence in this repository |
|---|---|---|
| The project is a simplified AMHS gateway/server, not a complete AMHS ecosystem. | **True** | Runtime documentation explicitly describes a non-web AMHS simulator/profile-limited stack, not a full ICAO Doc 9880/9705 AMHS implementation. |
| Core message transfer (MTA-like/gateway routing) exists. | **True** | RFC1006 service + relay/outbound engine + P1/P3 gateway handlers are implemented. |
| Message Store (MS) is only partial compared with full AMHS mailbox services. | **Mostly true** | Messages are persisted via repositories and can be retrieved with simple commands, but there is no full P7 mailbox service surface. |
| User Agent (UA) and operator console are missing. | **True** | Runtime is explicitly non-web and no UA/UI component is implemented in code. |
| Directory Service (X.500/LDAP directory role for AMHS addressing) is missing. | **True** | No X.500 directory-server subsystem, address-book/distribution-list authority, or AMHS directory integration is implemented. |
| Full X.400 stack (especially complete P1/P3/P7 semantics) is not fully implemented. | **True (with partial P1/P3 support)** | Project implements constrained/profile-limited P1/P3 gateway behavior; it does not claim complete certified end-to-end X.400 service scope. |
| Security exists but not full ICAO operational PKI/compliance stack. | **Partially true** | TLS and certificate checks are implemented; full operational ICAO compliance depends on broader governance, interop, and authority acceptance activities. |
| High-availability capabilities are incomplete for carrier-grade operations. | **True** | Documented HA mode is active/passive with external orchestration limits; no in-process cluster coordination/leader-election fabric. |

### 5.2 Missing capabilities by deployment scope

#### A) Internal use (lab/training/local ATC integration)

Current state:
- Available: message ingest/relay, persistence, retrieval primitives, delivery-report persistence, basic TLS/mTLS policy hooks.
- Missing or weak for day-to-day operator use: full UA/operator console, rich ATS templates/UI workflow, advanced audit/monitoring dashboards, and turnkey HA automation.

Readiness estimate (engineering judgment): **~70-80%** for controlled internal usage.

#### B) National operational use (ANSP multi-node production)

Major remaining gaps:
1. Directory capability for scalable AMHS addressing/distribution/routing policy authority.
2. Full operational service breadth expectations beyond the constrained gateway profile.
3. Migration-grade gateway and lifecycle tooling expected in mixed AFTN/AMHS environments.
4. Stronger HA/DR posture (dual-node orchestration, replicated operations model, formal DR drills as recurring obligations).
   - Target operating pattern: two production nodes in active/passive topology with deterministic role-election owned by external orchestrator and published runbooks.
   - Replication baseline: message-state repository replication with bounded RPO/RTO targets, periodic integrity reconciliation, and documented split-brain prevention controls.
   - DR governance: scheduled failover and region-loss drills as a recurring control (minimum quarterly), with signed drill reports, corrective-action tracking, and release-gate linkage.
   - Observable acceptance criteria: evidence bundle per release showing successful switchover, data-consistency validation, alerting/telemetry continuity, and rollback rehearsal.
5. Security/PKI operations hardening and authority-governed lifecycle controls.

Readiness estimate (engineering judgment): **~30-40%** for national operational deployment without additional platform layers.

#### C) ICAO-compliant external declaration/use

Critical remaining expectations (system-level):
1. Complete profile conformance posture against Doc 9880 and applicable regional profiles.
2. Full operational directory, security, and lifecycle evidence accepted by oversight authorities.
3. Formal conformance/interoperability campaign closure under authority-recognized procedures.
4. End-to-end operational assurance posture (auditability, redundancy, measurable SLO/performance governance).

Readiness estimate (engineering judgment): **not yet at full ICAO production-compliance state** without additional implementation, validation, and authority acceptance closure.

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
   - ✅ Closed (`R2026.03`): supported inbound P1 relay/interpersonal APDU subset and explicit unsupported inbound APDU diagnostics are frozen in `docs/icao/releases/R2026.03/P1_INTERNAL_PROFILE_STATEMENT.md` with deterministic `unsupported-operation` semantics.
   - ✅ Closed (`R2026.03`): message-transfer/interpersonal handling semantics are locked to the X.411 canonical module interpretation proven in `docs/icao/X411_CANONICAL_ASN1_MODULE_PROOF.md`.
2. **DR/NDR determinism evidence**
   - Build reproducible scenarios for delivery success, non-delivery, delay, redirection, and transfer-failure outcomes.
   - Capture cross-peer trace chain (ingress event → queue state → emitted DR/NDR → peer acknowledgment) with correlation IDs.
   - ✅ Closed (`R2026.03`): scenario and trace-chain evidence is published in `docs/icao/releases/R2026.03/evidence/p1-dr-ndr-interop/latest-manifest.txt` and the corresponding timestamped `*-dr-ndr-trace-ledger.md`.
3. **Extension and compatibility governance**
   - ✅ Closed (`R2026.03`): extension handling policy (known/unknown elements, criticality handling, forward/backward compatibility) is frozen in `docs/icao/P1_EXTENSION_HANDLING_POLICY.md` and release-bound via `docs/icao/releases/R2026.03/PICS_R2026.03.md` section 4.
   - ✅ Closed (`R2026.03`): regression vectors for operational legacy encodings are catalogued in `docs/icao/P1_LEGACY_ENCODING_REGRESSION_VECTORS.md` with executable coverage in `src/test/java/it/amhs/service/P1AssociationProtocolTest.java` and `src/test/java/it/amhs/service/P1BerMessageParserTest.java`.

### 7.1.2 P3 implementation work packages

1. **External endpoint profile completion**
   - ✅ Closed (`R2026.03`): complete operation matrix (bind, submit, probe/status, report handling, release, abort, reject/error classes) is published in `docs/icao/P3_SERVICE_EXTERNAL_DECLARATION_MATRIX.md`.
   - ✅ Closed (`R2026.03`): explicit unsupported/malformed input semantics with deterministic reject reason mapping are published in `docs/icao/P3_SERVICE_EXTERNAL_DECLARATION_MATRIX.md` section 4 and release-locked to `docs/icao/releases/R2026.03/P3_INTERNAL_PROFILE_STATEMENT.md`.
2. **Negotiation and error semantics closure**
   - ✅ Closed (`R2026.03`): ACSE/presentation matrix with selector/context-name/authentication permutations for external claim closure is published in `docs/icao/ACSE_PRESENTATION_NEGOTIATION_MATRIX.md` section 4.
   - ✅ Closed (`R2026.03`): packet-level and log-level success/failure evidence (including negative vectors) is release-published in `docs/icao/releases/R2026.03/evidence/p3-negative-apdu/20260308T210500Z-negotiation-error-semantics-closure.md`, with reproducible execution captures indexed by `docs/icao/releases/R2026.03/evidence/p3-negative-apdu/latest-manifest.txt`.
3. **Multi-vendor interoperability campaign**
   - ✅ Closed (`R2026.03`): repeatable campaign against one certified AMHS implementation profile (`CERTIFIED-AMHS-LAB`) plus heterogeneous stacks (`MIL-NET`, `ENAV-OPS`, `METEO-LEGACY`) is reproducibly executed via `scripts/evidence/p3_multi_vendor_evidence.sh` and published under `docs/icao/releases/R2026.03/evidence/p3-multi-vendor/`.
   - ✅ Closed (`R2026.03`): signed campaign report with replay instructions and artifact manifest (pcap checksum, decoded trace, verdict ledger, run log) is published in `docs/icao/releases/R2026.03/evidence/p3-multi-vendor/` (`*-signed-campaign-report.md`, `*-manifest.txt`, `latest-manifest.txt`).

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
