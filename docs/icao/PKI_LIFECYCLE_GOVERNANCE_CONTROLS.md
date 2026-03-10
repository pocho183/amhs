# PKI Lifecycle Governance Controls (National Operational Use)

## 1. Scope

This document defines the minimum operational hardening and authority-governed lifecycle controls required to operate AMHS TLS/PKI trust at ANSP multi-node production scale.

It complements:
- `docs/icao/ATN_PKI_SECURITY_LABEL_EVIDENCE.md` (runtime technical controls),
- `docs/icao/ITALY_NATIONAL_DECLARATION_PACKAGE.md` (responsibility model and declaration workflow), and
- `OPERATIONS_GUIDE.md` (runbook execution patterns).

## 2. Control objectives

For national operational use, PKI governance must prove four properties:

1. **Authority ownership**: trust anchors, policy OIDs, and revocation policy are approved by designated authority roles.
2. **Deterministic lifecycle**: issue/renew/revoke/retire actions are pre-defined, versioned, and auditable.
3. **Fail-safe runtime posture**: runtime behavior under PKI degradation follows declared hard-fail/controlled-soft-fail policy and incident escalation.
4. **Release-bound evidence**: each release contains reproducible artifacts showing configuration, execution, and accountable sign-off.

## 3. Authority-governed lifecycle model

### 3.1 Role separation and approvals

Minimum accountable roles (can map to equivalent national designations):

- **PKI Authority Owner (A)**: approves trust anchor set, certificate policy profile, revocation strictness baseline.
- **Security Operations Lead (R)**: executes truststore updates, key rollover procedure, revocation endpoint validation.
- **Service Operations Lead (R)**: performs deployment and rollback under change ticket.
- **Oversight/Compliance Function (C/I)**: verifies evidence package completeness and residual-risk acceptance statements.

No trust anchor addition/removal or revocation policy mode change is operationally valid without explicit PKI Authority Owner approval recorded in release evidence.

### 3.2 Lifecycle states and gates

1. **Plan**: change request opened (new CA, certificate renewal, revocation policy update, endpoint change).
2. **Stage**: trust artifacts validated in pre-production (path build, EKU/SAN policy, revocation reachability tests).
3. **Approve**: authority sign-off captured with ticket/reference ID.
4. **Deploy**: controlled rollout with rollback fingerprint and service restart sequence.
5. **Verify**: post-deploy evidence generated (config snapshot + runtime execution log + verdict).
6. **Retire**: superseded anchors/certs removed on defined retirement date; exception register updated if delay occurs.

### 3.3 Mandatory cryptographic lifecycle controls

- Dual-control for private-key generation/import events (human process requirement).
- Defined certificate validity window limits and renewal lead-time threshold.
- Explicit revocation-mode declaration (`hard-fail` or `controlled soft-fail`) with residual-risk record.
- Truststore integrity fingerprinting bound to release manifest.
- Emergency compromise procedure with maximum allowed response SLA for trust-anchor disablement.

## 4. Operational hardening controls

### 4.1 Runtime hardening baseline

The deployment baseline must include:

- TLS enabled on all operational AMHS ingress/egress links requiring authenticated peers.
- `need-client-auth=true` on mutually authenticated channels where bilateral trust is required.
- PKIX path validation enabled with expected policy OIDs where applicable.
- Revocation controls configured per national policy and tested in release campaign.

### 4.2 Evidence hardening baseline

Each release must publish, at minimum:

- configuration fingerprint (effective TLS/PKIX switches),
- runtime PKI enforcement execution log,
- verdict sheet mapping controls to pass/fail,
- accountable approval/sign-off references,
- residual-risk acceptance statement for any declared controlled soft-fail posture.

## 5. R2026.03 closure status

For release `R2026.03`, technical controls and evidence structure for PKI runtime enforcement and security governance are available and linked through:

- `docs/icao/ATN_PKI_RUNTIME_ENFORCEMENT_ASSURANCE.md`,
- `docs/icao/releases/R2026.03/evidence/atn-pki-runtime-enforcement/`,
- `docs/icao/releases/R2026.03/evidence/operational-assurance/20260308T141500Z-safety-security-residual-risk-acceptance.md`,
- `docs/icao/ITALY_NATIONAL_DECLARATION_PACKAGE.md`.

Accordingly, the prior national-gap statement "Security/PKI operations hardening and authority-governed lifecycle controls" is reclassified from an open design gap to a **closed baseline control set with mandatory per-release evidence refresh**.

## 6. Recurring obligations (post-closure)

Closure does not remove recurring obligations. For each release cycle:

1. Re-run PKI runtime enforcement evidence generation.
2. Revalidate revocation endpoint reachability and policy behavior.
3. Reconfirm authority approvals for trust-anchor/policy changes.
4. Refresh residual-risk acceptance entries where exceptions persist.
5. Publish updated manifest pointers in the authority-ready dossier.
