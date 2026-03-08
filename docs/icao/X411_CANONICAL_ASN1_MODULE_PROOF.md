# X.411 Canonical ASN.1 Module Proof Pack (Gateway Profile)

This document closes the module-level proof gap for the **declared gateway profile** by binding:

1. canonicalized ASN.1 module declarations used by this repository,
2. runtime tag constants/validators,
3. executable BER vectors (including DR/NDR evidence hooks).

> Scope boundary: this is a release-bound proof pack for this gateway profile implementation.
> It does not expand the external conformance claim beyond what is declared in `docs/icao/PICS.md`.

## 1) Canonical module-level declarations used for proof

For the runtime gateway profile, the ASN.1 APDU surface is canonicalized to the following tag declarations:

```asn1
X411-Gateway-Association-APDUs DEFINITIONS ::= BEGIN

AssociationAPDU ::= CHOICE {
  bind             [0]  IMPLICIT SEQUENCE,
  transfer         [1]  IMPLICIT SEQUENCE,
  release          [2]  IMPLICIT SEQUENCE,
  abort            [3]  IMPLICIT SEQUENCE,
  error            [4]  IMPLICIT SEQUENCE,
  bindResult       [10] IMPLICIT SEQUENCE,
  releaseResult    [11] IMPLICIT SEQUENCE,
  transferResult   [12] IMPLICIT SEQUENCE,
  nonDeliveryReport [13] IMPLICIT SEQUENCE,
  deliveryReport   [14] IMPLICIT SEQUENCE
}

END
```

These declarations are exactly mirrored by `X411TagMap` and enforced by runtime validators.

## 2) Runtime lock-step evidence

Primary runtime source:

- `src/main/java/it/amhs/service/protocol/p1/X411TagMap.java`

Executable lock-step test coverage:

- `src/test/java/it/amhs/service/X411CanonicalModuleConformanceTest.java`
- `src/test/java/it/amhs/service/X411TagMapTest.java`
- `src/test/java/it/amhs/service/X411DeliveryReportApduCodecTest.java`

What is proven by tests:

- association APDU tag table exact-match (0,1,2,3,4,10,11,12,13,14);
- bind/envelope field table exact-match for baseline fields;
- deterministic rejection of undeclared association tags;
- DR/NDR BER vectors decode with application-tag class and APDU identities expected by codecs.

## 3) DR/NDR BER vectors tied to module proof

The report codec evidence demonstrates that report APDUs produced and validated by the runtime are stable and inspectable:

- `APDU_NON_DELIVERY_REPORT` BER payload validation and structural field checks;
- persistence hooks storing raw BER evidence for audit/interop campaigns.

Reference runtime/test artifacts:

- `src/main/java/it/amhs/service/report/X411DeliveryReportApduCodec.java`
- `src/main/java/it/amhs/service/report/AMHSDeliveryReportService.java`
- `src/test/java/it/amhs/service/AMHSDeliveryReportServiceTest.java`

## 4) Release conformance statement impact

With this proof pack + executable lock-step tests, the previous "canonical module-level ASN.1 proof pending" condition is closed for the declared gateway-profile scope and release baseline.
