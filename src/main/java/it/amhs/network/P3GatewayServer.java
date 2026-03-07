package it.amhs.network;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.EOFException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.PushbackInputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.SocketException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import it.amhs.service.protocol.p3.P3Asn1GatewayProtocol;
import it.amhs.service.protocol.p3.P3GatewaySessionService;

@Component
@ConditionalOnProperty(prefix = "amhs.p3.gateway", name = "enabled", havingValue = "true")
public class P3GatewayServer {

    private static final Logger logger = LoggerFactory.getLogger(P3GatewayServer.class);

    private final String host;
    private final int port;
    private final boolean tlsEnabled;
    private final boolean needClientAuth;
    private final boolean textWelcomeEnabled;
    private final SSLContext tls;
    private final P3GatewaySessionService sessionService;
    private final P3Asn1GatewayProtocol asn1GatewayProtocol;
    private final ExecutorService clientExecutor;

    public P3GatewayServer(
        @Value("${amhs.p3.gateway.host:0.0.0.0}") String host,
        @Value("${amhs.p3.gateway.port:1988}") int port,
        @Value("${amhs.p3.gateway.max-sessions:64}") int maxSessions,
        @Value("${amhs.p3.gateway.tls.enabled:false}") boolean tlsEnabled,
        @Value("${amhs.p3.gateway.tls.need-client-auth:false}") boolean needClientAuth,
        @Value("${amhs.p3.gateway.text.welcome-enabled:false}") boolean textWelcomeEnabled,
        SSLContext tls,
        P3GatewaySessionService sessionService,
        P3Asn1GatewayProtocol asn1GatewayProtocol
    ) {
        if (port < 1 || port > 65_535) {
            throw new IllegalArgumentException("amhs.p3.gateway.port out of range: " + port);
        }
        if (maxSessions < 1) {
            throw new IllegalArgumentException("amhs.p3.gateway.max-sessions must be >= 1");
        }
        this.host = host;
        this.port = port;
        this.tlsEnabled = tlsEnabled;
        this.needClientAuth = needClientAuth;
        this.textWelcomeEnabled = textWelcomeEnabled;
        this.tls = tls;
        this.sessionService = sessionService;
        this.asn1GatewayProtocol = asn1GatewayProtocol;
        this.clientExecutor = Executors.newFixedThreadPool(maxSessions, new NamedDaemonThreadFactory());
    }

    public void start() throws Exception {
        if (tlsEnabled) {
            SSLServerSocket server = (SSLServerSocket) tls.getServerSocketFactory().createServerSocket(port, 50, InetAddress.getByName(host));
            server.setEnabledProtocols(new String[] { "TLSv1.3", "TLSv1.2" });
            server.setNeedClientAuth(needClientAuth);
            logger.info("AMHS P3 gateway TLS server listening on {}:{}", host, port);
            acceptLoop(server);
            return;
        }

        ServerSocket server = new ServerSocket(port, 50, InetAddress.getByName(host));
        logger.info("AMHS P3 gateway clear transport server listening on {}:{}", host, port);
        acceptLoop(server);
    }

    private void acceptLoop(ServerSocket server) throws Exception {
        while (true) {
            Socket socket = server.accept();
            logger.info("P3 gateway connection from {}", socket.getInetAddress());
            clientExecutor.execute(() -> handleClient(socket));
        }
    }

    private void handleClient(Socket socket) {
        try (socket;
             PushbackInputStream input = new PushbackInputStream(socket.getInputStream(), 1);
             OutputStream output = socket.getOutputStream()) {
            P3GatewaySessionService.SessionState session = sessionService.newSession();
            int first = input.read();
            if (first < 0) {
                return;
            }
            input.unread(first);

            if (isAsciiCommand(first)) {
                logger.info("P3 gateway protocol=text-command remote={}", socket.getInetAddress());
                handleTextSession(session, input, output);
                return;
            }

            logger.info("P3 gateway protocol=ber-apdu remote={}", socket.getInetAddress());
            handleAsn1Session(session, input, output);
        } catch (Exception ex) {
            if (isExpectedDisconnect(ex)) {
                logger.debug("P3 gateway client session ended before a complete request was received: {}", ex.getMessage());
                return;
            }
            logger.warn("P3 gateway client session closed with error: {}", ex.getMessage());
        }
    }

    private boolean isExpectedDisconnect(Exception ex) {
        return ex instanceof EOFException
            || ex instanceof SocketException;
    }

    private void handleTextSession(P3GatewaySessionService.SessionState session, PushbackInputStream input, OutputStream output)
        throws Exception {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8));
             PrintWriter writer = new PrintWriter(new BufferedWriter(new OutputStreamWriter(output, StandardCharsets.UTF_8)), true)) {
            if (textWelcomeEnabled) {
                writer.println("OK code=gateway-ready");
            }
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank()) {
                    continue;
                }
                String response = sessionService.handleCommand(session, line);
                writer.println(response);
                if (session.isClosed()) {
                    return;
                }
            }
        }
    }

    private void handleAsn1Session(P3GatewaySessionService.SessionState session, PushbackInputStream input, OutputStream output)
        throws Exception {
        while (true) {
            byte[] pdu = asn1GatewayProtocol.readPdu(input);
            if (pdu == null) {
                return;
            }
            byte[] response = asn1GatewayProtocol.handle(session, pdu);
            output.write(response);
            output.flush();
            if (session.isClosed()) {
                return;
            }
        }
    }

    private boolean isAsciiCommand(int firstOctet) {
        return firstOctet >= 0x20 && firstOctet <= 0x7E;
    }

    private static final class NamedDaemonThreadFactory implements ThreadFactory {
        private int counter = 0;

        @Override
        public synchronized Thread newThread(Runnable runnable) {
            Thread thread = new Thread(runnable, "amhs-p3-gateway-client-" + (++counter));
            thread.setDaemon(true);
            return thread;
        }
    }
}
