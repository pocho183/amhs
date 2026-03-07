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
import java.util.concurrent.atomic.AtomicLong;

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
    private final AtomicLong connectionSequence = new AtomicLong(0);

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
            long connectionId = connectionSequence.incrementAndGet();
            logger.info("P3 gateway connection #{} from {}:{} to local-port={}", connectionId, socket.getInetAddress(), socket.getPort(), socket.getLocalPort());
            clientExecutor.execute(() -> handleClient(connectionId, socket));
        }
    }

    private void handleClient(long connectionId, Socket socket) {
        try (socket;
             PushbackInputStream input = new PushbackInputStream(socket.getInputStream(), 1);
             OutputStream output = socket.getOutputStream()) {
            P3GatewaySessionService.SessionState session = sessionService.newSession();
            int first = input.read();
            if (first < 0) {
                return;
            }
            input.unread(first);

            ProtocolKind protocol = detectProtocol(first);
            logger.info("P3 gateway connection #{} first-octet=0x{} protocol={}", connectionId, toHex(first), protocol.logName);
            switch (protocol) {
                case TEXT_COMMAND -> {
                    handleTextSession(connectionId, session, input, output);
                    return;
                }
                case BER_APDU -> {
                    handleAsn1Session(connectionId, session, input, output);
                    return;
                }
                case RFC1006_TPKT -> {
                    logger.warn("P3 gateway connection #{} received RFC1006/TPKT traffic on {}:{} from {}. Use the RFC1006 listener port for P1 traffic.", connectionId, host, port, socket.getInetAddress());
                    return;
                }
                case TLS_CLIENT_HELLO -> {
                    logger.warn("P3 gateway connection #{} received a TLS handshake on clear-text endpoint {}:{} from {}. Enable amhs.p3.gateway.tls.enabled or use the TLS endpoint.", connectionId, host, port, socket.getInetAddress());
                    return;
                }
                case UNKNOWN_BINARY -> {
                    logger.warn("P3 gateway connection #{} unsupported first octet 0x{} from {}. Expected text command or BER APDU.", connectionId, toHex(first), socket.getInetAddress());
                    return;
                }
            }
        } catch (Exception ex) {
            if (isExpectedDisconnect(ex)) {
                logger.debug("P3 gateway connection #{} ended before a complete request was received: {}", connectionId, ex.getMessage());
                return;
            }
            logger.warn("P3 gateway connection #{} closed with error: {}", connectionId, ex.getMessage());
        }
    }

    private boolean isExpectedDisconnect(Exception ex) {
        return ex instanceof EOFException
            || ex instanceof SocketException;
    }

    // Backward-compatible overload retained for branches/call-sites still using the previous signature.
    private void handleTextSession(P3GatewaySessionService.SessionState session, PushbackInputStream input, OutputStream output)
        throws Exception {
        handleTextSession(-1L, session, input, output);
    }

    private void handleTextSession(long connectionId, P3GatewaySessionService.SessionState session, PushbackInputStream input, OutputStream output)
        throws Exception {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8));
             PrintWriter writer = new PrintWriter(new BufferedWriter(new OutputStreamWriter(output, StandardCharsets.UTF_8)), true)) {
            if (textWelcomeEnabled) {
                writer.println("OK code=gateway-ready");
            }
            int commandIndex = 0;
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank()) {
                    logger.debug("P3 gateway connection #{} ignored blank text line", connectionId);
                    continue;
                }
                commandIndex++;
                String commandName = line.split("\\s+", 2)[0].toUpperCase();
                logger.info("P3 gateway connection #{} text command #{} {}", connectionId, commandIndex, commandName);
                String response = sessionService.handleCommand(session, line);
                writer.println(response);
                if (session.isClosed()) {
                    logger.info("P3 gateway connection #{} text session closed by command {}", connectionId, commandName);
                    return;
                }
            }
        }
    }

    // Backward-compatible overload retained for branches/call-sites still using the previous signature.
    private void handleAsn1Session(P3GatewaySessionService.SessionState session, PushbackInputStream input, OutputStream output)
        throws Exception {
        handleAsn1Session(-1L, session, input, output);
    }

    private void handleAsn1Session(long connectionId, P3GatewaySessionService.SessionState session, PushbackInputStream input, OutputStream output)
        throws Exception {
        int pduIndex = 0;
        while (true) {
            byte[] pdu = asn1GatewayProtocol.readPdu(input);
            if (pdu == null) {
                logger.info("P3 gateway connection #{} BER session closed by peer after {} APDU(s)", connectionId, pduIndex);
                return;
            }
            pduIndex++;
            logger.info("P3 gateway connection #{} BER APDU #{} len={} first-byte=0x{}", connectionId, pduIndex, pdu.length, toHex(pdu[0]));
            byte[] response = asn1GatewayProtocol.handle(session, pdu);
            output.write(response);
            output.flush();
            logger.debug("P3 gateway connection #{} BER APDU #{} response-len={}", connectionId, pduIndex, response.length);
            if (session.isClosed()) {
                logger.info("P3 gateway connection #{} BER session closed by release after {} APDU(s)", connectionId, pduIndex);
                return;
            }
        }
    }

    private ProtocolKind detectProtocol(int firstOctet) {
        if (isAsciiCommand(firstOctet)) {
            return ProtocolKind.TEXT_COMMAND;
        }
        if ((firstOctet & 0xFF) == 0x03) {
            return ProtocolKind.RFC1006_TPKT;
        }
        if ((firstOctet & 0xFF) == 0x16) {
            return ProtocolKind.TLS_CLIENT_HELLO;
        }
        if (isBerApduStart(firstOctet)) {
            return ProtocolKind.BER_APDU;
        }
        return ProtocolKind.UNKNOWN_BINARY;
    }

    private boolean isAsciiCommand(int firstOctet) {
        return firstOctet >= 0x20 && firstOctet <= 0x7E;
    }

    private boolean isBerApduStart(int firstOctet) {
        return (firstOctet & 0xE0) == 0xA0;
    }

    private String toHex(byte octet) {
        return toHex((int) octet);
    }

    private String toHex(int octet) {
        return String.format("%02X", octet & 0xFF);
    }

    private enum ProtocolKind {
        TEXT_COMMAND("text-command"),
        BER_APDU("ber-apdu"),
        RFC1006_TPKT("rfc1006-tpkt"),
        TLS_CLIENT_HELLO("tls-client-hello"),
        UNKNOWN_BINARY("unknown-binary");

        private final String logName;

        ProtocolKind(String logName) {
            this.logName = logName;
        }
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
