# AMHS PICS — Release Bound (`R2026.03`)

This release-bound PICS packages the conformance claim baseline for release `R2026.03`.

## 1. Release binding and immutability anchors

- Release identifier: `R2026.03`
- Configuration fingerprint anchor: `docs/icao/releases/R2026.03/CONFIGURATION_FINGERPRINT.txt`
- Functional PICS baseline source: `docs/icao/PICS.md`

The effective release claim is valid only when this document, the functional baseline PICS, and the configuration fingerprint remain unchanged for the declared release package.

## 2. Configuration fingerprint (normative)

The release package fingerprint is declared in:

- `docs/icao/releases/R2026.03/CONFIGURATION_FINGERPRINT.txt`

Normative fingerprint digest:

- `fingerprint.sha256=491e00414f349ac9321005b480b6a1026169222e9a5554606b15096e8ef1a52f`

## 3. Feature flags (release-effective)

The following configuration flags are release-effective for the declared baseline:

| Feature/control | Value (`R2026.03`) | Source |
|---|---|---|
| `rfc1006.tls.enabled` | `false` | `CONFIGURATION_FINGERPRINT.txt` |
| `rfc1006.tls.need-client-auth` | `false` | `CONFIGURATION_FINGERPRINT.txt` |
| `amhs.p3.gateway.enabled` | `false` | `CONFIGURATION_FINGERPRINT.txt` |
| `amhs.p3.gateway.tls.enabled` | `false` | `CONFIGURATION_FINGERPRINT.txt` |
| `amhs.p3.gateway.tls.need-client-auth` | `false` | `CONFIGURATION_FINGERPRINT.txt` |
| `amhs.p3.gateway.listener-profile` | `STANDARD_P3` | `CONFIGURATION_FINGERPRINT.txt` |
| `amhs.relay.enabled` | `false` | `CONFIGURATION_FINGERPRINT.txt` |
| `amhs.acse.require-authentication-value` | `false` | `CONFIGURATION_FINGERPRINT.txt` |
| `tls.pkix.revocation-enabled` | `false` | `CONFIGURATION_FINGERPRINT.txt` |

## 4. Claimed protocol conformance matrix

The complete capability-by-capability PICS answers for this release are inherited from:

- `docs/icao/PICS.md`

This release-bound wrapper does not widen claim scope; it fixes claim scope to `R2026.03` through the fingerprint above.
