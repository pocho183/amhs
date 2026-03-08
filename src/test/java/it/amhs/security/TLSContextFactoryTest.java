package it.amhs.security;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Set;

import org.junit.jupiter.api.Test;
import org.springframework.core.io.DefaultResourceLoader;

class TLSContextFactoryTest {

    private final TLSContextFactory factory = new TLSContextFactory(new DefaultResourceLoader());

    @Test
    void shouldCreateSslContextWhenPkixRevocationDisabled() {
        assertNotNull(factory.create(
            "classpath:certs/server.p12",
            "changeit",
            "classpath:certs/client-truststore.jks",
            "changeit",
            false,
            Set.of()
        ));
    }

    @Test
    void shouldCreateSslContextWhenPkixRevocationEnabledAndPolicyRequired() {
        assertNotNull(factory.create(
            "classpath:certs/server.p12",
            "changeit",
            "classpath:certs/client-truststore.jks",
            "changeit",
            true,
            Set.of("2.5.29.32.0")
        ));
    }

    @Test
    void shouldFailForMissingTruststore() {
        assertThrows(RuntimeException.class, () -> factory.create(
            "classpath:certs/server.p12",
            "changeit",
            "classpath:certs/missing-truststore.jks",
            "changeit",
            true,
            Set.of("2.5.29.32.0")
        ));
    }
}
