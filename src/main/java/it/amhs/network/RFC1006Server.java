package it.amhs.network;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import it.amhs.service.RFC1006Service;

@Component
public class RFC1006Server {
	
	private static final Logger logger = LoggerFactory.getLogger(RFC1006Server.class);
	
	private RFC1006Service rfc1006Service;
    private final int port;
    private final SSLContext tls;
    private final boolean needClientAuth;

    public RFC1006Server(@Value("${rfc1006.server.port:102}") int port,
                         @Value("${rfc1006.tls.need-client-auth:false}") boolean needClientAuth,
                         SSLContext tls, RFC1006Service rfc1006Service) {
		this.port = port;
		this.tls = tls;
		this.needClientAuth = needClientAuth;
		this.rfc1006Service = rfc1006Service;
    }

    public void start() throws Exception {
        SSLServerSocket server = (SSLServerSocket) tls.getServerSocketFactory().createServerSocket(port);
        server.setEnabledProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
        //server.setNeedClientAuth(false);
        server.setNeedClientAuth(needClientAuth);
        logger.info("AMHS RFC1006 TLS Server listening on " + port);
        while (true) {
            SSLSocket socket = (SSLSocket) server.accept();
            logger.info("AMHS Connection from " + socket.getInetAddress());
            new Thread(() -> rfc1006Service.handleClient(socket)).start();
        }
    }

}