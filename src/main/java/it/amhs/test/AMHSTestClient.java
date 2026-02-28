package it.amhs.test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * AMHS RFC1006/TLS test client aligned with this AMHS server implementation.
 */
public class AMHSTestClient {

    private static final String DEFAULT_HOST = "localhost";
    private static final int DEFAULT_PORT = 102;
    private static final String DEFAULT_TRUSTSTORE_PATH = "src/main/resources/certs/client-truststore.jks";
    private static final String DEFAULT_TRUSTSTORE_PASSWORD = "changeit";
    private static final String DEFAULT_CHANNEL = "ATFM";

    public static void main(String[] args) {
        ClientOptions options = ClientOptions.fromArgs(args);

        try (SSLSocket socket = createSocket(options)) {
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();

            if (options.retrieveAll) {
                sendAndPrint(out, in, "RETRIEVE ALL");
                return;
            }
            if (options.retrieveMessageId != null) {
                sendAndPrint(out, in, "RETRIEVE " + options.retrieveMessageId);
                return;
            }

            for (int i = 1; i <= options.count; i++) {
                String messageId = options.messagePrefix + "-" + Instant.now().toEpochMilli() + "-" + i;
                String payload = buildMessagePayload(options, messageId, i);
                sendAndPrint(out, in, payload);
            }
        } catch (Exception e) {
            System.err.println("AMHS test client failed: " + e.getMessage());
            e.printStackTrace(System.err);
            System.exit(1);
        }
    }

    private static SSLSocket createSocket(ClientOptions options) throws Exception {
        TrustManagerFactory tmf = buildTrustManagers(options);
        KeyManagerFactory kmf = buildKeyManagers(options);

        SSLContext context = SSLContext.getInstance("TLS");
        context.init(kmf == null ? null : kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        SSLSocketFactory factory = context.getSocketFactory();
        SSLSocket socket = (SSLSocket) factory.createSocket(options.host, options.port);
        socket.setEnabledProtocols(new String[] { "TLSv1.3", "TLSv1.2" });
        socket.startHandshake();
        System.out.printf("Connected to %s:%d (channel=%s)%n", options.host, options.port, options.channel);
        return socket;
    }

    private static TrustManagerFactory buildTrustManagers(ClientOptions options) throws Exception {
        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (InputStream trustStoreStream = new FileInputStream(options.trustStorePath)) {
            trustStore.load(trustStoreStream, options.trustStorePassword.toCharArray());
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        return tmf;
    }

    private static KeyManagerFactory buildKeyManagers(ClientOptions options) throws Exception {
        if (options.keyStorePath == null || options.keyStorePath.isBlank()) {
            return null;
        }

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream keyStoreStream = new FileInputStream(options.keyStorePath)) {
            keyStore.load(keyStoreStream, options.keyStorePassword.toCharArray());
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, options.keyStorePassword.toCharArray());
        return kmf;
    }

    private static String buildMessagePayload(ClientOptions options, String messageId, int sequence) {
        String body = options.bodyTemplate
            .replace("{seq}", String.valueOf(sequence))
            .replace("{channel}", options.channel)
            .replace("{messageId}", messageId);

        String filingTime = Instant.now().toString();

        return "Message-ID: " + messageId + "\n" +
            "From: " + options.from + "\n" +
            "To: " + options.to + "\n" +
            "Profile: " + options.profile + "\n" +
            "Priority: " + options.priority + "\n" +
            "Channel: " + options.channel + "\n" +
            "Filing-Time: " + filingTime + "\n" +
            "Subject: " + options.subject + "\n" +
            "Body: " + body + "\n";
    }

    private static void sendAndPrint(OutputStream out, InputStream in, String payload) throws Exception {
        byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);
        ByteBuffer packet = ByteBuffer.allocate(2 + payloadBytes.length);
        packet.putShort((short) payloadBytes.length);
        packet.put(payloadBytes);

        out.write(packet.array());
        out.flush();

        byte[] lenBytes = readFully(in, 2);
        int responseLength = ByteBuffer.wrap(lenBytes).getShort() & 0xFFFF;
        byte[] responseBytes = readFully(in, responseLength);

        System.out.println("--- REQUEST ---");
        System.out.println(payload);
        System.out.println("--- RESPONSE ---");
        System.out.println(new String(responseBytes, StandardCharsets.UTF_8));
    }

    private static byte[] readFully(InputStream in, int length) throws Exception {
        byte[] data = new byte[length];
        int offset = 0;
        while (offset < length) {
            int read = in.read(data, offset, length - offset);
            if (read == -1) {
                throw new IllegalStateException("Connection closed while reading response");
            }
            offset += read;
        }
        return data;
    }

    private static final class ClientOptions {
        private final String host;
        private final int port;
        private final String trustStorePath;
        private final String trustStorePassword;
        private final String keyStorePath;
        private final String keyStorePassword;
        private final String from;
        private final String to;
        private final String profile;
        private final String priority;
        private final String channel;
        private final String subject;
        private final String bodyTemplate;
        private final int count;
        private final String messagePrefix;
        private final boolean retrieveAll;
        private final String retrieveMessageId;

        private ClientOptions(
            String host,
            int port,
            String trustStorePath,
            String trustStorePassword,
            String keyStorePath,
            String keyStorePassword,
            String from,
            String to,
            String profile,
            String priority,
            String channel,
            String subject,
            String bodyTemplate,
            int count,
            String messagePrefix,
            boolean retrieveAll,
            String retrieveMessageId
        ) {
            this.host = host;
            this.port = port;
            this.trustStorePath = trustStorePath;
            this.trustStorePassword = trustStorePassword;
            this.keyStorePath = keyStorePath;
            this.keyStorePassword = keyStorePassword;
            this.from = from;
            this.to = to;
            this.profile = profile;
            this.priority = priority;
            this.channel = channel;
            this.subject = subject;
            this.bodyTemplate = bodyTemplate;
            this.count = count;
            this.messagePrefix = messagePrefix;
            this.retrieveAll = retrieveAll;
            this.retrieveMessageId = retrieveMessageId;
        }

        private static ClientOptions fromArgs(String[] args) {
            Map<String, String> values = parseNamedArgs(args);

            if (values.containsKey("help")) {
                printUsageAndExit();
            }

            String host = values.getOrDefault("host", envOrDefault("AMHS_HOST", DEFAULT_HOST));
            int port = parseInt(values.get("port"), parseInt(envOrDefault("AMHS_PORT", String.valueOf(DEFAULT_PORT)), DEFAULT_PORT));

            String trustStorePath = values.getOrDefault(
                "truststore",
                envOrDefault("AMHS_TRUSTSTORE", DEFAULT_TRUSTSTORE_PATH)
            );
            String trustStorePassword = values.getOrDefault(
                "truststore-password",
                envOrDefault("AMHS_TRUSTSTORE_PASSWORD", DEFAULT_TRUSTSTORE_PASSWORD)
            );

            String keyStorePath = values.getOrDefault("keystore", envOrDefault("AMHS_KEYSTORE", ""));
            String keyStorePassword = values.getOrDefault("keystore-password", envOrDefault("AMHS_KEYSTORE_PASSWORD", "changeit"));

            String from = values.getOrDefault("from", envOrDefault("AMHS_FROM", "LIRRAAAA"));
            String to = values.getOrDefault("to", envOrDefault("AMHS_TO", "LIRRBBBB"));
            String profile = values.getOrDefault("profile", envOrDefault("AMHS_PROFILE", "P3"));
            String priority = values.getOrDefault("priority", envOrDefault("AMHS_PRIORITY", "GG"));
            String channel = values.getOrDefault("channel", envOrDefault("AMHS_CHANNEL", DEFAULT_CHANNEL));
            String subject = values.getOrDefault("subject", envOrDefault("AMHS_SUBJECT", "AMHS TEST"));
            String bodyTemplate = values.getOrDefault(
                "body",
                envOrDefault("AMHS_BODY", "Test payload #{seq} for channel {channel} ({messageId})")
            );
            int count = parseInt(values.get("count"), parseInt(envOrDefault("AMHS_COUNT", "1"), 1));
            String messagePrefix = values.getOrDefault("message-prefix", envOrDefault("AMHS_MESSAGE_PREFIX", "MSG"));

            boolean retrieveAll = values.containsKey("retrieve-all");
            String retrieveMessageId = values.get("retrieve");

            if (values.containsKey("from-or")) {
                from = values.get("from-or");
            }
            if (values.containsKey("to-or")) {
                to = values.get("to-or");
            }

            return new ClientOptions(
                host,
                port,
                trustStorePath,
                trustStorePassword,
                keyStorePath,
                keyStorePassword,
                from,
                to,
                profile,
                priority,
                channel,
                subject,
                bodyTemplate,
                count,
                messagePrefix,
                retrieveAll,
                retrieveMessageId
            );
        }

        private static Map<String, String> parseNamedArgs(String[] args) {
            Map<String, String> values = new LinkedHashMap<>();
            for (int i = 0; i < args.length; i++) {
                String arg = args[i];
                if (!arg.startsWith("--")) {
                    continue;
                }

                String key = arg.substring(2);
                if ("retrieve-all".equals(key) || "help".equals(key)) {
                    values.put(key, "true");
                    continue;
                }

                if (i + 1 >= args.length) {
                    throw new IllegalArgumentException("Missing value for argument --" + key);
                }
                values.put(key, args[++i]);
            }
            return values;
        }

        private static int parseInt(String value, int defaultValue) {
            if (value == null || value.isBlank()) {
                return defaultValue;
            }
            return Integer.parseInt(value.trim());
        }

        private static String envOrDefault(String key, String defaultValue) {
            String value = System.getenv(key);
            return value == null || value.isBlank() ? defaultValue : value;
        }

        private static void printUsageAndExit() {
            System.out.println("Usage: java it.amhs.test.AMHSTestClient [options]\n" +
                "Options:\n" +
                "  --host <host>                      Default: localhost\n" +
                "  --port <port>                      Default: 102\n" +
                "  --truststore <path>                Default: src/main/resources/certs/client-truststore.jks\n" +
                "  --truststore-password <pwd>        Default: changeit\n" +
                "  --keystore <path.p12>              Optional client cert for mTLS\n" +
                "  --keystore-password <pwd>          Default: changeit\n" +
                "  --from <8-char or O/R>             Default: LIRRAAAA\n" +
                "  --to <8-char or O/R>               Default: LIRRBBBB\n" +
                "  --from-or <O/R address>            Override from using O/R form\n" +
                "  --to-or <O/R address>              Override to using O/R form\n" +
                "  --profile <P1|P3|P7>               Default: P3\n" +
                "  --priority <SS|DD|FF|GG|KK>        Default: GG\n" +
                "  --channel <name>                   Default: " + DEFAULT_CHANNEL + "\n" +
                "  --subject <text>                   Default: AMHS TEST\n" +
                "  --body <template>                  Variables: {seq}, {channel}, {messageId}\n" +
                "  --count <n>                        Default: 1\n" +
                "  --message-prefix <prefix>          Default: MSG\n" +
                "  --retrieve-all                     Send RETRIEVE ALL command\n" +
                "  --retrieve <messageId>             Send RETRIEVE <messageId> command\n" +
                "  --help\n");
            System.exit(0);
        }
    }
}
