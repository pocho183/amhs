package it.amhs.test;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.EOFException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;

/**
 * AMHS RFC1006/TLS test client aligned with this AMHS server implementation.
 */
public class AMHSTestClient {

    private static final Logger logger = LoggerFactory.getLogger(AMHSTestClient.class);

    private static final String DEFAULT_HOST = "localhost";
    private static final int DEFAULT_PORT = 102;
    private static final String DEFAULT_TRUSTSTORE_PATH = "src/main/resources/certs/client-truststore.jks";
    private static final String DEFAULT_TRUSTSTORE_PASSWORD = "changeit";
    private static final String DEFAULT_CHANNEL = "ATFM";
    private static final int DEFAULT_TIMEOUT_MS = 10_000;
    private static final byte TPKT_VERSION = 0x03;
    private static final byte TPKT_RESERVED = 0x00;
    private static final byte[] COTP_DATA_HEADER = new byte[] {0x02, (byte) 0xF0, (byte) 0x80};
    private static final int MAX_TPKT_LENGTH = 65_535;
    private static final byte COTP_PDU_CR = (byte) 0xE0;
    private static final byte COTP_PDU_CC = (byte) 0xD0;
    private static final byte COTP_PDU_DT = (byte) 0xF0;
    private static final int MAX_DT_USER_DATA_PER_FRAME = 16_384;

    public static void main(String[] args) {
        ClientOptions options = ClientOptions.fromArgs(args);

        try {
            if (options.negativeSuite) {
                runNegativeSuite(options);
                return;
            }

            try (SSLSocket socket = createSocket(options)) {
                OutputStream out = socket.getOutputStream();
                InputStream in = socket.getInputStream();
                performCotpHandshake(out, in);

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
            }

            if (options.concurrency > 1) {
                runConcurrentHappyPath(options);
            }
        } catch (Exception e) {
            logger.error("AMHS test client failed: {}", e.getMessage(), e);
            System.exit(1);
        }
    }

    private static void runNegativeSuite(ClientOptions options) throws InterruptedException {
        logger.info("Running negative test suite (invalid profile, corrupted frame, oversized message)");

        List<Runnable> tests = List.of(
            () -> runSingleNegativeCase(options, "invalid-profile", buildNegativePayload(options, "ZZZ", "NEG-PROFILE"), false),
            () -> runSingleNegativeCase(options, "corrupted-length", buildNegativePayload(options, options.profile, "NEG-LENGTH"), true),
            () -> runSingleNegativeCase(options, "oversized-message", buildOversizedPayload(options), false)
        );

        for (Runnable test : tests) {
            test.run();
        }
    }

    private static void runSingleNegativeCase(ClientOptions options, String caseName, String payload, boolean corruptLength) {
        try (SSLSocket socket = createSocket(options)) {
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();
            performCotpHandshake(out, in);
            sendWithOptionalCorruptLength(out, payload, corruptLength);
            byte[] response = readRFC1006Payload(in);
            logger.info("Negative case '{}' response:\n{}", caseName, new String(response, StandardCharsets.UTF_8));
        } catch (Exception ex) {
            logger.info("Negative case '{}' failed as expected: {}", caseName, ex.getMessage());
        }
    }

    private static void runConcurrentHappyPath(ClientOptions options) throws InterruptedException {
        logger.info("Running concurrency test with {} clients", options.concurrency);
        CountDownLatch latch = new CountDownLatch(options.concurrency);
        List<Thread> workers = new ArrayList<>();

        for (int i = 0; i < options.concurrency; i++) {
            final int idx = i + 1;
            Thread t = new Thread(() -> {
                try (SSLSocket socket = createSocket(options)) {
                    OutputStream out = socket.getOutputStream();
                    InputStream in = socket.getInputStream();
                    performCotpHandshake(out, in);
                    String messageId = options.messagePrefix + "-C" + idx + "-" + Instant.now().toEpochMilli();
                    sendAndPrint(out, in, buildMessagePayload(options, messageId, idx));
                } catch (Exception ex) {
                    logger.warn("Concurrency worker {} failed: {}", idx, ex.getMessage());
                } finally {
                    latch.countDown();
                }
            }, "amhs-test-worker-" + idx);
            workers.add(t);
            t.start();
        }

        latch.await();
        logger.info("Concurrency test completed");
    }

    private static String buildNegativePayload(ClientOptions options, String profile, String messagePrefix) {
        String messageId = messagePrefix + "-" + Instant.now().toEpochMilli();
        return "Message-ID: " + messageId + "\n" +
            "From: " + options.from + "\n" +
            "To: " + options.to + "\n" +
            "Profile: " + profile + "\n" +
            "Priority: " + options.priority + "\n" +
            "Channel: " + options.channel + "\n" +
            "Filing-Time: " + Instant.now() + "\n" +
            "Subject: NEGATIVE TEST\n" +
            "Body: Negative test payload\n";
    }

    private static String buildOversizedPayload(ClientOptions options) {
        String messageId = "NEG-OVERSIZED-" + Instant.now().toEpochMilli();
        return "Message-ID: " + messageId + "\n" +
            "From: " + options.from + "\n" +
            "To: " + options.to + "\n" +
            "Profile: " + options.profile + "\n" +
            "Priority: " + options.priority + "\n" +
            "Channel: " + options.channel + "\n" +
            "Filing-Time: " + Instant.now() + "\n" +
            "Subject: NEGATIVE TEST\n" +
            "Body: " + "X".repeat(70_000) + "\n";
    }

    private static SSLSocket createSocket(ClientOptions options) throws Exception {
        validateTrustStore(options);
        warnOnDefaultSecrets(options);

        TrustManagerFactory tmf = buildTrustManagers(options);
        KeyManagerFactory kmf = buildKeyManagers(options);

        SSLContext context = SSLContext.getInstance("TLS");
        context.init(kmf == null ? null : kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        SSLSocketFactory factory = context.getSocketFactory();
        SSLSocket socket = (SSLSocket) factory.createSocket();
        socket.connect(new InetSocketAddress(options.host, options.port), options.connectTimeoutMs);
        socket.setSoTimeout(options.readTimeoutMs);
        socket.setEnabledProtocols(new String[] { "TLSv1.3", "TLSv1.2" });
        socket.startHandshake();
        logger.info("Connected to {}:{} (channel={})", options.host, options.port, options.channel);
        logger.info("Expecting server-side trace hop injection as {}@{}", options.localMtaName, options.localRoutingDomain);
        return socket;
    }

    private static void validateTrustStore(ClientOptions options) {
        Path trustStorePath = Path.of(options.trustStorePath);
        if (!Files.exists(trustStorePath)) {
            throw new IllegalArgumentException("Truststore not found at: " + trustStorePath);
        }
    }

    private static void warnOnDefaultSecrets(ClientOptions options) {
        if (DEFAULT_TRUSTSTORE_PASSWORD.equals(options.trustStorePassword)) {
            logger.warn("Using default truststore password '{}'. Override with --truststore-password or AMHS_TRUSTSTORE_PASSWORD.", DEFAULT_TRUSTSTORE_PASSWORD);
        }
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
        sendWithOptionalCorruptLength(out, payload, false);
        byte[] responseBytes = readRFC1006Payload(in);

        logger.info("--- REQUEST ---\n{}", payload);
        logger.info("--- RESPONSE ---\n{}", new String(responseBytes, StandardCharsets.UTF_8));
    }

    private static void sendWithOptionalCorruptLength(OutputStream out, String payload, boolean corruptLength) throws Exception {
        byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);
        int maxPayloadPerFrame = MAX_DT_USER_DATA_PER_FRAME;
        int offset = 0;

        while (offset < payloadBytes.length || payloadBytes.length == 0) {
            int chunkLength = Math.min(maxPayloadPerFrame, payloadBytes.length - offset);
            boolean eot = offset + chunkLength >= payloadBytes.length;

            int userDataLength = chunkLength;
            if (corruptLength && eot && userDataLength > 0) {
                userDataLength -= 1;
            }

            int tpktLength = 4 + COTP_DATA_HEADER.length + userDataLength;
            if (tpktLength > MAX_TPKT_LENGTH) {
                throw new IllegalArgumentException("TPKT frame exceeds maximum allowed length: " + tpktLength);
            }

            ByteBuffer packet = ByteBuffer.allocate(tpktLength);
            packet.put(TPKT_VERSION);
            packet.put(TPKT_RESERVED);
            packet.putShort((short) tpktLength);
            packet.put(COTP_DATA_HEADER[0]);
            packet.put(COTP_DATA_HEADER[1]);
            packet.put(eot ? (byte) 0x80 : 0x00);
            if (userDataLength > 0) {
                packet.put(payloadBytes, offset, userDataLength);
            }

            out.write(packet.array());
            offset += chunkLength;
            if (payloadBytes.length == 0) {
                break;
            }
        }
        out.flush();
    }

    private static byte[] readRFC1006Payload(InputStream in) throws Exception {
        ByteArrayOutputStream message = new ByteArrayOutputStream();

        while (true) {
            byte[] tpkt = readFully(in, 4);
            if (tpkt[0] != TPKT_VERSION || tpkt[1] != TPKT_RESERVED) {
                throw new IllegalArgumentException("Unexpected TPKT header");
            }

            int tpktLength = ((tpkt[2] & 0xFF) << 8) | (tpkt[3] & 0xFF);
            if (tpktLength < 7 || tpktLength > MAX_TPKT_LENGTH) {
                throw new IllegalArgumentException("Invalid TPKT length: " + tpktLength);
            }

            byte[] cotpTpdu = readFully(in, tpktLength - 4);
            int li = cotpTpdu[0] & 0xFF;
            if (li + 1 > cotpTpdu.length) {
                throw new IllegalArgumentException("Invalid COTP length indicator: " + li);
            }

            byte pduType = (byte) (cotpTpdu[1] & (byte) 0xF0);
            if (pduType != COTP_PDU_DT) {
                throw new IllegalArgumentException("Unexpected COTP TPDU type in response: " + String.format("0x%02X", pduType));
            }
            if (cotpTpdu[1] != COTP_DATA_HEADER[1]) {
                throw new IllegalArgumentException("Unexpected COTP DT code in response: " + String.format("0x%02X", cotpTpdu[1]));
            }

            boolean eot = (cotpTpdu[2] & (byte) 0x80) != 0;
            int dataOffset = li + 1;
            if (dataOffset < cotpTpdu.length) {
                message.write(cotpTpdu, dataOffset, cotpTpdu.length - dataOffset);
            }

            if (eot) {
                return message.toByteArray();
            }
        }
    }

    private static void performCotpHandshake(OutputStream out, InputStream in) throws Exception {
        byte[] crTpdu = new byte[] {
            0x06,
            COTP_PDU_CR,
            0x00,
            0x00,
            0x00,
            0x01,
            0x00
        };

        sendTpktWithTpdu(out, crTpdu);
        out.flush();

        byte[] tpkt = readFully(in, 4);
        if (tpkt[0] != TPKT_VERSION || tpkt[1] != TPKT_RESERVED) {
            throw new IllegalArgumentException("Unexpected TPKT header while waiting for COTP CC");
        }

        int tpktLength = ((tpkt[2] & 0xFF) << 8) | (tpkt[3] & 0xFF);
        if (tpktLength < 11 || tpktLength > MAX_TPKT_LENGTH) {
            throw new IllegalArgumentException("Invalid TPKT length for COTP CC: " + tpktLength);
        }

        byte[] cotpTpdu = readFully(in, tpktLength - 4);
        int li = cotpTpdu[0] & 0xFF;
        if (li + 1 > cotpTpdu.length) {
            throw new IllegalArgumentException("Invalid COTP CC length indicator: " + li);
        }

        byte pduType = (byte) (cotpTpdu[1] & (byte) 0xF0);
        if (pduType != COTP_PDU_CC) {
            throw new IllegalArgumentException("Expected COTP CC, received: " + String.format("0x%02X", cotpTpdu[1]));
        }
    }

    private static void sendTpktWithTpdu(OutputStream out, byte[] cotpTpdu) throws Exception {
        int tpktLength = 4 + cotpTpdu.length;
        if (tpktLength > MAX_TPKT_LENGTH) {
            throw new IllegalArgumentException("TPKT frame exceeds maximum allowed length: " + tpktLength);
        }
        ByteBuffer packet = ByteBuffer.allocate(tpktLength);
        packet.put(TPKT_VERSION);
        packet.put(TPKT_RESERVED);
        packet.putShort((short) tpktLength);
        packet.put(cotpTpdu);
        out.write(packet.array());
    }

    private static byte[] readFully(InputStream in, int length) throws Exception {
        byte[] data = new byte[length];
        int offset = 0;
        while (offset < length) {
            int read = in.read(data, offset, length - offset);
            if (read == -1) {
                throw new EOFException("Connection closed while reading response");
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
        private final int connectTimeoutMs;
        private final int readTimeoutMs;
        private final boolean negativeSuite;
        private final int concurrency;
        private final String localMtaName;
        private final String localRoutingDomain;

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
            String retrieveMessageId,
            int connectTimeoutMs,
            int readTimeoutMs,
            boolean negativeSuite,
            int concurrency,
            String localMtaName,
            String localRoutingDomain
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
            this.connectTimeoutMs = connectTimeoutMs;
            this.readTimeoutMs = readTimeoutMs;
            this.negativeSuite = negativeSuite;
            this.concurrency = concurrency;
            this.localMtaName = localMtaName;
            this.localRoutingDomain = localRoutingDomain;
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
            int connectTimeoutMs = parseInt(values.get("connect-timeout-ms"), parseInt(envOrDefault("AMHS_CONNECT_TIMEOUT_MS", String.valueOf(DEFAULT_TIMEOUT_MS)), DEFAULT_TIMEOUT_MS));
            int readTimeoutMs = parseInt(values.get("read-timeout-ms"), parseInt(envOrDefault("AMHS_READ_TIMEOUT_MS", String.valueOf(DEFAULT_TIMEOUT_MS)), DEFAULT_TIMEOUT_MS));
            boolean negativeSuite = values.containsKey("negative-suite");
            int concurrency = parseInt(values.get("concurrency"), parseInt(envOrDefault("AMHS_CONCURRENCY", "1"), 1));
            String localMtaName = values.getOrDefault("local-mta-name", envOrDefault("AMHS_MTA_LOCAL_NAME", "LOCAL-MTA"));
            String localRoutingDomain = values.getOrDefault("routing-domain", envOrDefault("AMHS_MTA_ROUTING_DOMAIN", "LOCAL"));

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
                retrieveMessageId,
                connectTimeoutMs,
                readTimeoutMs,
                negativeSuite,
                concurrency,
                localMtaName,
                localRoutingDomain
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
                if ("retrieve-all".equals(key) || "help".equals(key) || "negative-suite".equals(key)) {
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
                "  --connect-timeout-ms <ms>          Default: " + DEFAULT_TIMEOUT_MS + "\n" +
                "  --read-timeout-ms <ms>             Default: " + DEFAULT_TIMEOUT_MS + "\n" +
                "  --concurrency <n>                  Default: 1 (parallel happy-path clients)\n" +
                "  --local-mta-name <name>            Expected server local MTA (for trace checks/logging)\n" +
                "  --routing-domain <domain>          Expected server routing domain (for trace checks/logging)\n" +
                "  --negative-suite                   Run invalid/corrupted/oversized tests\n" +
                "  --retrieve-all                     Send RETRIEVE ALL command\n" +
                "  --retrieve <messageId>             Send RETRIEVE <messageId> command\n" +
                "  --help\n");
            System.exit(0);
        }
    }
}
