package it.amhs.security;

import javax.net.ssl.*;
import java.io.InputStream;
import java.security.KeyStore;

import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

@Component
public class TLSContextFactory {

    private final ResourceLoader resourceLoader;

    public TLSContextFactory(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    public SSLContext create(String path, String password) {

        try {

            Resource resource =
                resourceLoader.getResource(path);

            InputStream is =
                resource.getInputStream();

            KeyStore ks =
                KeyStore.getInstance("PKCS12");

            ks.load(is, password.toCharArray());

            KeyManagerFactory kmf =
                KeyManagerFactory.getInstance("SunX509");

            kmf.init(ks, password.toCharArray());

            SSLContext ctx =
                SSLContext.getInstance("TLS");

            ctx.init(
                kmf.getKeyManagers(),
                null,
                null
            );

            return ctx;

        }
        catch (Exception e) {

            throw new RuntimeException(
                "Failed to load keystore: " + path,
                e
            );

        }

    }

}