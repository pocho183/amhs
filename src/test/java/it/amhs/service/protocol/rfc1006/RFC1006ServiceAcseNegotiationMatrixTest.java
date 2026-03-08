package it.amhs.service.protocol.rfc1006;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import it.amhs.service.protocol.acse.AcseModels;
import it.amhs.service.protocol.acse.PresentationContext;

class RFC1006ServiceAcseNegotiationMatrixTest {

    @ParameterizedTest(name = "{0}")
    @MethodSource("negotiationVectors")
    void validatesNegotiationAndErrorSemanticsMatrix(
        String vector,
        RFC1006Service service,
        AcseModels.AARQApdu aarq,
        String certificateCn,
        String certificateOu,
        String expectedDiagnostic
    ) {
        if (expectedDiagnostic == null) {
            assertDoesNotThrow(() -> service.validateAarqForAmhsP1(aarq, certificateCn, certificateOu));
            return;
        }

        IllegalArgumentException ex = assertThrows(
            IllegalArgumentException.class,
            () -> service.validateAarqForAmhsP1(aarq, certificateCn, certificateOu)
        );
        assertEquals(expectedDiagnostic, ex.getMessage());
    }

    private static Stream<Arguments> negotiationVectors() {
        byte[] userInfo = "assoc-info".getBytes(StandardCharsets.UTF_8);
        byte[] auth = "token-ok".getBytes(StandardCharsets.UTF_8);

        AcseModels.AARQApdu baseline = aarq(
            RFC1006Service.ICAO_AMHS_P1_OID,
            Optional.of("ALICE"),
            Optional.of(new AcseModels.ApTitle("1.3.6.1.4.1.999")),
            Optional.of(auth),
            Optional.of(userInfo),
            List.of(new PresentationContext(1, RFC1006Service.ICAO_AMHS_P1_OID, List.of("2.1.1")))
        );

        AcseModels.AARQApdu wrongContextName = aarq(
            "1.0.8571.1.1",
            Optional.of("ALICE"),
            Optional.of(new AcseModels.ApTitle("1.3.6.1.4.1.999")),
            Optional.of(auth),
            Optional.of(userInfo),
            List.of(new PresentationContext(1, RFC1006Service.ICAO_AMHS_P1_OID, List.of("2.1.1")))
        );

        AcseModels.AARQApdu missingAmhsPresentation = aarq(
            RFC1006Service.ICAO_AMHS_P1_OID,
            Optional.of("ALICE"),
            Optional.of(new AcseModels.ApTitle("1.3.6.1.4.1.999")),
            Optional.of(auth),
            Optional.of(userInfo),
            List.of(new PresentationContext(1, "1.0.9506.2.3", List.of("2.1.1")))
        );

        AcseModels.AARQApdu missingCallingSelectorWithCert = aarq(
            RFC1006Service.ICAO_AMHS_P1_OID,
            Optional.empty(),
            Optional.empty(),
            Optional.of(auth),
            Optional.of(userInfo),
            List.of(new PresentationContext(1, RFC1006Service.ICAO_AMHS_P1_OID, List.of("2.1.1")))
        );

        AcseModels.AARQApdu certSelectorMismatch = aarq(
            RFC1006Service.ICAO_AMHS_P1_OID,
            Optional.of("BOB"),
            Optional.of(new AcseModels.ApTitle("1.3.6.1.4.1.999")),
            Optional.of(auth),
            Optional.of(userInfo),
            List.of(new PresentationContext(1, RFC1006Service.ICAO_AMHS_P1_OID, List.of("2.1.1")))
        );

        AcseModels.AARQApdu missingAuth = aarq(
            RFC1006Service.ICAO_AMHS_P1_OID,
            Optional.of("ALICE"),
            Optional.of(new AcseModels.ApTitle("1.3.6.1.4.1.999")),
            Optional.empty(),
            Optional.of(userInfo),
            List.of(new PresentationContext(1, RFC1006Service.ICAO_AMHS_P1_OID, List.of("2.1.1")))
        );

        AcseModels.AARQApdu wrongAuth = aarq(
            RFC1006Service.ICAO_AMHS_P1_OID,
            Optional.of("ALICE"),
            Optional.of(new AcseModels.ApTitle("1.3.6.1.4.1.999")),
            Optional.of("token-bad".getBytes(StandardCharsets.UTF_8)),
            Optional.of(userInfo),
            List.of(new PresentationContext(1, RFC1006Service.ICAO_AMHS_P1_OID, List.of("2.1.1")))
        );

        AcseModels.AARQApdu missingUserInformation = aarq(
            RFC1006Service.ICAO_AMHS_P1_OID,
            Optional.of("ALICE"),
            Optional.of(new AcseModels.ApTitle("1.3.6.1.4.1.999")),
            Optional.of(auth),
            Optional.empty(),
            List.of(new PresentationContext(1, RFC1006Service.ICAO_AMHS_P1_OID, List.of("2.1.1")))
        );

        return Stream.of(
            Arguments.of("ACSE-MAT-01 valid selectors/context/auth", service(false, ""), baseline, "", "", null),
            Arguments.of("ACSE-MAT-02 invalid application-context-name", service(false, ""), wrongContextName, "", "",
                "Unsupported ACSE application-context OID 1.0.8571.1.1"),
            Arguments.of("ACSE-MAT-03 missing AMHS abstract syntax in presentation", service(false, ""), missingAmhsPresentation, "", "",
                "ACSE presentation contexts do not negotiate AMHS P1 abstract syntax"),
            Arguments.of("ACSE-MAT-04 certificate present requires calling selector", service(false, ""), missingCallingSelectorWithCert, "ALICE", "OPS",
                "ACSE calling AE-title is mandatory when peer certificate identity is present"),
            Arguments.of("ACSE-MAT-05 calling selector mismatch with certificate", service(false, ""), certSelectorMismatch, "ALICE", "OPS",
                "ACSE calling AE-title is not bound to peer certificate identity"),
            Arguments.of("ACSE-MAT-06 auth required but missing", service(true, ""), missingAuth, "", "",
                "ACSE authentication-value is mandatory"),
            Arguments.of("ACSE-MAT-07 auth content mismatch", service(false, "token-ok"), wrongAuth, "", "",
                "ACSE authentication-value verification failed"),
            Arguments.of("ACSE-MAT-08 missing association-information", service(false, ""), missingUserInformation, "", "",
                "ACSE user-information is mandatory for AMHS association information")
        );
    }

    private static RFC1006Service service(boolean requireAuth, String expectedAuth) {
        return new RFC1006Service(null, null, null, null, null, "LOCAL-MTA", "LOCAL", 30_000, requireAuth, expectedAuth);
    }

    private static AcseModels.AARQApdu aarq(
        String appContext,
        Optional<String> callingAeTitle,
        Optional<AcseModels.ApTitle> callingApTitle,
        Optional<byte[]> auth,
        Optional<byte[]> userInfo,
        List<PresentationContext> contexts
    ) {
        List<String> oids = contexts.stream().map(PresentationContext::abstractSyntaxOid).toList();
        return new AcseModels.AARQApdu(
            appContext,
            callingAeTitle,
            Optional.empty(),
            callingApTitle,
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            auth,
            userInfo,
            oids,
            contexts
        );
    }
}
