package it.amhs.test;

import javax.net.ssl.*;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

public class AMHSTestClient {

    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 102;
    private static final String TRUSTSTORE_PATH = "/Users/manuel/workspace/amhs/src/main/resources/certs/client-truststore.jks";
    private static final String TRUSTSTORE_PASSWORD = "changeit";

    public static void main(String[] args) {
        SSLSocket socket = null;

        try {
            // Trust server certificate
            KeyStore trustStore = KeyStore.getInstance("JKS");
            try (InputStream tsStream = new java.io.FileInputStream(TRUSTSTORE_PATH)) {
                trustStore.load(tsStream, TRUSTSTORE_PASSWORD.toCharArray());
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(trustStore);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), null);

            SSLSocketFactory factory = sslContext.getSocketFactory();
            socket = (SSLSocket) factory.createSocket(SERVER_HOST, SERVER_PORT);
            socket.setEnabledProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
            System.out.println("Connected to AMHS server at " + SERVER_HOST + ":" + SERVER_PORT);

            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();

            // Send multiple AMHS messages
            for (int i = 1; i <= 5; i++) {
                String messageId = "MSG-" + i;
                String amhsMessage = "Message-ID: " + messageId + "\n" +
                                     "From: AMHSClient\n" +
                                     "To: AMHSServer\n" +
                                     "Body: This is AMHS test message #" + i + "\n";

                byte[] msgBytes = amhsMessage.getBytes(StandardCharsets.UTF_8);
                ByteBuffer bb = ByteBuffer.allocate(2 + msgBytes.length);
                bb.putShort((short) msgBytes.length);
                bb.put(msgBytes);

                out.write(bb.array());
                out.flush();
                System.out.println("Sent AMHS message " + messageId);

                // Receive ACK
                byte[] lenBytes = new byte[2];
                in.read(lenBytes);
                int respLen = ByteBuffer.wrap(lenBytes).getShort() & 0xFFFF;
                byte[] respBytes = new byte[respLen];
                in.read(respBytes);
                System.out.println("Received ACK:\n" + new String(respBytes, StandardCharsets.UTF_8));
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (socket != null) try { socket.close(); } catch (Exception ignored) {}
        }
    }
}