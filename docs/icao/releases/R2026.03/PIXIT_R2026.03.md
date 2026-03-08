# AMHS PIXIT — Release Bound (`R2026.03`)

This release-bound PIXIT packages implementation-specific protocol and deployment parameters for release `R2026.03`.

## 1. Release binding and references

- Release identifier: `R2026.03`
- Configuration fingerprint anchor: `docs/icao/releases/R2026.03/CONFIGURATION_FINGERPRINT.txt`
- Functional PIXIT baseline source: `docs/icao/PIXIT.md`

## 2. Release-effective implementation parameters

| Parameter | Value (`R2026.03`) | Scope |
|---|---|---|
| `rfc1006.server.host` | `0.0.0.0` | Listener bind |
| `rfc1006.server.port` | `102` | Listener bind |
| `amhs.p3.gateway.enabled` | `false` | Optional gateway disabled in baseline |
| `amhs.p3.gateway.host` | `0.0.0.0` | Gateway bind |
| `amhs.p3.gateway.port` | `102` | Gateway bind |
| `amhs.p3.gateway.listener-profile` | `STANDARD_P3` | P3 profile mode |
| `amhs.relay.enabled` | `false` | Outbound relay disabled in baseline |
| `amhs.relay.max-attempts` | `5` | Relay retry policy |
| `amhs.relay.scan-delay-ms` | `5000` | Relay scheduler |
| `amhs.acse.require-authentication-value` | `false` | ACSE auth-value gate |
| `tls.pkix.revocation-enabled` | `false` | PKIX runtime revocation check switch |

All values above are bound to the release fingerprint file and are authoritative for this declared release package.

## 3. Feature-flag declaration

For authority review, the following flags are explicitly declared as claim-impacting toggles:

1. `rfc1006.tls.enabled`
2. `rfc1006.tls.need-client-auth`
3. `amhs.p3.gateway.enabled`
4. `amhs.p3.gateway.tls.enabled`
5. `amhs.p3.gateway.tls.need-client-auth`
6. `amhs.relay.enabled`
7. `amhs.acse.require-authentication-value`
8. `tls.pkix.revocation-enabled`

Any change to these flags requires a new fingerprint and re-issuance of release-bound PICS/PIXIT packaging.

## 4. Detailed deployment assumptions

Detailed interoperability constraints, naming assumptions, and profile boundaries remain documented in:

- `docs/icao/PIXIT.md`
- `docs/icao/releases/R2026.03/P3_INTERNAL_PROFILE_STATEMENT.md`
