package it.amhs;

import javax.net.ssl.SSLContext;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableScheduling;

import it.amhs.network.RFC1006Server;
import it.amhs.security.TLSContextFactory;

@SpringBootApplication
@EnableScheduling
public class AMHS {

    @Value("${rfc1006.server.port}")
    private int serverPort;
    @Value("${tls.keystore.path}")
    private String keystorePath;
    @Value("${tls.keystore.password}")
    private String keystorePassword;
    @Value("${tls.truststore.path:}")
    private String truststorePath;
    @Value("${tls.truststore.password:}")
    private String truststorePassword;
    @Value("${tls.pkix.revocation-enabled:false}")
    private boolean tlsRevocationEnabled;
    @Value("${tls.pkix.required-policy-oids:}")
    private String tlsRequiredPolicyOids;

    public static void main(String[] args) {
    	SpringApplication app = new SpringApplication(AMHS.class);
        app.setBanner((environment, sourceClass, out) -> { out.println("✈️ ✈️ ✈️  AMHS SERVER ️✈️ ✈️ ✈️️"); });
        app.setWebApplicationType(WebApplicationType.NONE);
        app.run(args);
    }
    
    @Bean
    public SSLContext sslContext(TLSContextFactory factory) {
        try {
            return factory.create(
                keystorePath,
                keystorePassword,
                truststorePath,
                truststorePassword,
                tlsRevocationEnabled,
                parsePolicyOids(tlsRequiredPolicyOids)
            );
        } catch (Exception e) {
            throw new RuntimeException("Failed to create SSLContext", e);
        }
    }
    
    private java.util.Set<String> parsePolicyOids(String csv) {
        if (csv == null || csv.isBlank()) {
            return java.util.Set.of();
        }
        return java.util.Arrays.stream(csv.split(","))
            .map(String::trim)
            .filter(value -> !value.isEmpty())
            .collect(java.util.stream.Collectors.toSet());
    }

    @Bean
    public CommandLineRunner startServer(RFC1006Server server) {
        return args -> {
            // Spring has already injected the port, SSLContext, and Service 
            // into the 'server' object for you.
            new Thread(() -> {
                try {
                    server.start();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }).start();
        };
    }
}