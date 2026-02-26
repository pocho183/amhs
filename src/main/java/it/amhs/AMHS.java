package it.amhs;

import javax.net.ssl.SSLContext;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import it.amhs.dao.AMHSDao;
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

    @Bean
    public CommandLineRunner startServer(TLSContextFactory factory, AMHSDao dao) {
        return args -> {
            SSLContext tls = factory.create(keystorePath, keystorePassword);
            RFC1006Server server = new RFC1006Server(serverPort, tls, dao);
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