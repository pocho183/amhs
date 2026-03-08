# Doc 9880 Security-Label Operations Oversight Record (R2026.03)

- Release baseline: `R2026.03`
- Scope: mixed-label gateway traffic handling for Doc 9880-aligned security-label controls
- Evidence owner: Security Assurance Function
- Record timestamp (UTC): `2026-03-08T15:25:00Z`

## 1. Objective

Close the PICS security/oversight work package item for Doc 9880-aligned security-label operations by providing release-bound evidence that:

1. label parsing is deterministic,
2. dominance decisions are deterministic,
3. downgrade/upgrade constraints are enforced via policy checks, and
4. rejection semantics under mixed-label traffic are deterministic and reproducible.

## 2. Control points and verification vectors

| Control objective | Control implementation | Verification vectors | Verdict |
|---|---|---|---|
| Label parsing and classification ordering | `SecurityLabelPolicy.parse(...)` validates Doc 9880 classification and compartment syntax | `SecurityLabelPolicyTest.shouldAcceptDoc9880StyleLabelAndTokenOid`, `shouldRejectUnknownClassification`, `shouldNormalizeCaseAndWhitespaceForDoc9880Labels` | Pass |
| Dominance decisions and downgrade/upgrade constraints | `SecurityLabelPolicy.dominates(...)` enforces classification rank and compartment superset logic | `SecurityLabelPolicyTest.shouldApplyDominanceSemantics`, `shouldEnforceDowngradeUpgradeConstraintsThroughDominanceChecks` | Pass |
| Rejection semantics under mixed-label traffic | `P3GatewaySessionService.bind(...)` rejects malformed/unsupported labels and non-dominant label pairs with deterministic diagnostics | `P3GatewaySessionServiceTest.bindRejectsInvalidSecurityLabelClassification`, `bindRejectsWhenSecurityLabelDoesNotDominateGatewayPolicyLabel`, `bindRejectsGatewayPolicyLabelWithoutSecurityLabel` | Pass |
| Local policy-tailoring guardrails | Compartment token syntax (`[A-Z0-9-]{2,20}`) prevents unsafe local-tailoring variants from being accepted silently | `SecurityLabelPolicyTest.shouldRejectMixedLabelTrafficWhenPolicyTailoringIntroducesInvalidCompartmentToken` | Pass |

## 3. Mixed-label traffic decision summary

The release baseline behavior is:

- **Accept** when security-label is syntactically valid and dominates the configured gateway-policy-label.
- **Reject** with `ERR code=security-policy` when:
  - classification is unsupported,
  - compartment token format is invalid,
  - gateway policy label is supplied without security label,
  - dominance check fails.

This behavior is deterministic and stable for the declared gateway profile.

## 4. Residual-risk statement for local policy tailoring

Residual risk record for local tailoring decisions:

| Risk ID | Description | Mitigation | Residual rating | Decision |
|---|---|---|---|---|
| RR-LABEL-01 | Local operators may request non-standard compartment strings (spaces/special symbols), creating potential interoperability drift if accepted. | Enforced strict compartment regex in parser, deterministic reject diagnostics, and change-control requirement before policy expansion. | Low | Accepted for `R2026.03` |
| RR-LABEL-02 | Classification vocabulary expansion (e.g., national-only values) may diverge from declared Doc 9880 profile. | Unsupported classifications are rejected by policy; changes require release-bound profile update and oversight revalidation. | Low | Accepted for `R2026.03` |

## 5. Accountable-authority acceptance linkage

Accountable-authority acceptance for residual risk is recorded in:

- `docs/icao/releases/R2026.03/evidence/operational-assurance/20260308T141500Z-safety-security-residual-risk-acceptance.md`

Approval reference: `AA-R2026.03-OPS-SEC-001`.

## 6. Closure statement

For `R2026.03`, the Doc 9880 security-label operations work package is closed with objective implementation-test evidence and release-bound residual-risk acceptance linkage.
