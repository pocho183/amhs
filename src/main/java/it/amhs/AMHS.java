package it.amhs;

import javax.net.ssl.SSLContext;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import it.amhs.network.RFC1006Server;
import it.amhs.security.TLSContextFactory;

@SpringBootApplication
public class AMHS {

    @Value("${rfc1006.server.port}")
    private int serverPort;
    @Value("${tls.keystore.path}")
    private String keystorePath;
    @Value("${tls.keystore.password}")
    private String keystorePassword;

    public static void main(String[] args) {
        SpringApplication.run(AMHS.class, args);
    }

    /*
    @Bean
    public CommandLineRunner startServer(TLSContextFactory factory) {
        return args -> {
            SSLContext tls = factory.create(keystorePath, keystorePassword);
            RFC1006Server server = new RFC1006Server(serverPort, tls);
            new Thread(() -> {
                try {
                    server.start();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }).start();
        };
    }*/
    
    @Bean
    public SSLContext sslContext(TLSContextFactory factory) {
        try {
            return factory.create(keystorePath, keystorePassword);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create SSLContext", e);
        }
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