# ACSE/Presentation Negotiation Behavior Matrix (External Interoperability Declaration)

This matrix completes the closure item from `docs/icao/PICS.md` §6.3 ("Complete ACSE/presentation negotiation behavior matrix for external interoperability declaration") by declaring deterministic gateway-profile behavior for ACSE bind negotiation.

## 1. Declaration legend

- **Y**: fully supported for external gateway interoperability declaration.
- **P**: partially supported; usable in controlled campaigns with explicit peer alignment.
- **N**: not supported in the declared gateway profile.

## 2. Behavior matrix

| Ref | Negotiation area | Inbound peer condition / vector | Gateway behavior | Declared status | Interoperability declaration note | Evidence pointers |
|---|---|---|---|---|---|---|
| ACSE-01 | Application-context OID match | `AARQ.application-context-name == 2.6.0.1.6.1` | Association validation continues. | Y | Required baseline vector for external peer bind attempts. | `RFC1006Service.validateAarqForAmhsP1`; unit coverage for valid bind path. |
| ACSE-02 | Application-context OID mismatch | Any OID other than `2.6.0.1.6.1` | Rejects AARQ with deterministic diagnostic mapping and rejected AARE result container. | Y | Unsupported contexts are explicitly rejected; behavior is safe for declaration. | `validateAarqForAmhsP1`, `mapAarqDiagnostic`, `buildRejectedAare`. |
| ACSE-03 | Presentation context list presence | `AARQ.presentation-context-definition-list` absent/empty | Rejects AARQ (`presentation-layer negotiation is missing presentation contexts`). | Y | Mandatory check declared as enforced for all external peers. | `validateAarqPresentationContexts`; negative unit test coverage. |
| ACSE-04 | AMHS abstract syntax negotiated | Presentation context list does not include `2.6.0.1.6.1` abstract syntax | Rejects AARQ (`presentation contexts do not negotiate AMHS P1 abstract syntax`) and maps to provider diagnostic bucket. | Y | Explicit rejection semantics declared for non-AMHS contexts. | `validateAarqPresentationContexts`; diagnostic mapping test coverage. |
| ACSE-05 | Empty presentation-context OID elements | Context list contains blank OID entry | Rejects AARQ (`presentation context OID must not be empty`). | Y | Empty OIDs are treated as protocol errors in declaration profile. | `validateAarqPresentationContexts`. |
| ACSE-06 | Repeated AMHS abstract syntax across contexts | Context list includes duplicate OID values for AMHS abstract syntax | Accepts and continues validation (duplicates tolerated in current profile). | P | Accepted for interoperability pragmatism; not asserted as full ISO presentation negotiation breadth. | `shouldAllowRepeatedAbstractSyntaxAcrossPresentationContexts`. |
| ACSE-07 | AE/AP title structural coherence | AP-title without AE-title/AE-qualifier, or AE-title/AE-qualifier without AP-title | Rejects AARQ with deterministic validation diagnostics. | Y | Structure-pair constraints are part of external declaration baseline. | `validateAarqEntityTitles`, `validateAeTitlePair`; negative unit coverage. |
| ACSE-08 | Certificate-bound calling AE-title | Peer cert CN/OU is present and calling AE-title absent or not matching cert identity | Rejects AARQ (`calling AE-title is mandatory...` / `not bound to peer certificate identity`). | Y | Identity-binding semantics declared as mandatory when channel identity exists. | `validateAarqForAmhsP1`. |
| ACSE-09 | Authentication-value mandatory policy | Runtime policy requires auth and `authentication-value` is missing/empty | Rejects AARQ with deterministic diagnostics. | Y | Enforced policy behavior is declaration-safe when feature enabled. | `validateAarqAuthentication`. |
| ACSE-10 | Authentication-value content verification | Runtime expected auth value configured and peer value mismatches | Rejects AARQ (`authentication-value verification failed`) with requestor diagnostic bucket. | Y | Deterministic negative path declared for external testing. | `validateAarqForAmhsP1`; diagnostics tests. |
| ACSE-11 | User-information presence and size | Missing user-information, zero-length payload, or payload > profile maximum | Rejects AARQ with explicit diagnostics. | Y | Profile-limited AMHS association information is mandatory and bounded. | `validateAarqUserInformation`; negative unit coverage. |
| ACSE-12 | AARE diagnostic structure on rejection | Any rejected AARQ path | Emits structured `AARE` with `result-source-diagnostic` and negotiated context OID list. | Y | Rejection responses are machine-readable for campaign verdict reproducibility. | `buildRejectedAare`; AARE diagnostics tests. |
| ACSE-13 | Generic ACSE user-information encoding breadth | Peer requires broad EXTERNAL variations beyond constrained EXTERNAL/OCTET STRING mapping | Supported only for constrained encoding path; broader variants are out of declared scope. | P | External declaration remains gateway-profile limited, not full ACSE universality claim. | `AcseAssociationProtocol` constrained encode/decode path; PICS section 4.2 limits. |
| ACSE-14 | Full ISO session/presentation negotiation surface | Peer expects profile-complete presentation/session negotiation semantics | Not declared; only supported gateway paths are claimed. | N | Explicit non-claim for full profile-complete external interoperability. | `PICS.md` §4.2 declared limitation and gateway posture. |

## 3. External declaration statement

For external interoperability declaration, this implementation claims **deterministic ACSE/presentation negotiation behavior for the gateway profile vectors ACSE-01..ACSE-12**, with **partial support notes for ACSE-06 and ACSE-13**, and an explicit **non-claim for full profile-complete negotiation breadth (ACSE-14)**.

Assessment campaigns should record verdicts against this matrix and attach reproducible logs/pcaps per vector.
