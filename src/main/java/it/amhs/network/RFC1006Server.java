package it.amhs.network;

import it.amhs.dao.AMHSDao;

import javax.net.ssl.*;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class RFC1006Server {

    private final int port;
    private final SSLContext tls;
    private final AMHSDao dao;

    public RFC1006Server(int port, SSLContext tls, AMHSDao dao) {
        this.port = port;
        this.tls = tls;
        this.dao = dao;
    }

    public void start() throws Exception {
        SSLServerSocket server = (SSLServerSocket) tls.getServerSocketFactory().createServerSocket(port);
        server.setEnabledProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
        server.setNeedClientAuth(false);

        System.out.println("AMHS RFC1006 TLS Server listening on " + port);

        while (true) {
            SSLSocket socket = (SSLSocket) server.accept();
            System.out.println("AMHS Connection from " + socket.getInetAddress());
            new Thread(() -> handleClient(socket)).start();
        }
    }

    private void handleClient(SSLSocket socket) {
        try (InputStream in = socket.getInputStream(); OutputStream out = socket.getOutputStream()) {
            while (true) {
                byte[] lenBytes = new byte[2];
                int read = in.read(lenBytes);
                if (read != 2) break;

                int length = ByteBuffer.wrap(lenBytes).getShort() & 0xFFFF;
                byte[] payload = new byte[length];
                int totalRead = 0;
                while (totalRead < length) {
                    int r = in.read(payload, totalRead, length - totalRead);
                    if (r == -1) break;
                    totalRead += r;
                }

                String message = new String(payload, "UTF-8").trim();

                if (message.startsWith("RETRIEVE")) {
                    handleRetrieve(message, out);
                    continue;
                }

                Map<String, String> headers = new HashMap<>();
                String body = "";

                // 1. Split by comma or newline depending on your client's format
                String[] parts = message.split(",|\\n"); 

                for (String part : parts) {
                    if (part.contains(":")) {
                        String[] kv = part.split(":", 2);
                        String key = kv[0].trim();
                        String value = kv[1].trim();
                        
                        if (key.equalsIgnoreCase("Body")) {
                            body = value; // Capture the body if it's labeled "Body:"
                        } else {
                            headers.put(key, value);
                        }
                    }
                }

                String messageId = headers.getOrDefault("Message-ID", java.util.UUID.randomUUID().toString());
                String from = headers.getOrDefault("From", "UNKNOWN");
                String to = headers.getOrDefault("To", "UNKNOWN");

                // Now 'body' will contain "This is AMHS test message #1"
                dao.saveMessage(messageId, from, to, body);

                String ack = "Message-ID: " + messageId + "\n" +
                             "From: " + to + "\n" +
                             "To: " + from + "\n" +
                             "Status: RECEIVED\n";
                sendRFC1006(out, ack);
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try { socket.close(); } catch (Exception ignored) {}
        }
    }

    private void handleRetrieve(String command, OutputStream out) throws Exception {
        String response;
        if (command.equalsIgnoreCase("RETRIEVE ALL")) {
            List<String> msgs = dao.retrieveAllMessages();
            response = msgs.isEmpty() ? "No messages.\n" : String.join("\n---\n", msgs);
        } else if (command.toUpperCase().startsWith("RETRIEVE ")) {
            String messageId = command.substring("RETRIEVE ".length()).trim();
            String msg = dao.retrieveMessage(messageId);
            response = msg != null ? msg : "Message-ID " + messageId + " not found.\n";
        } else {
            response = "Unknown command.\n";
        }
        sendRFC1006(out, response);
    }

    private void sendRFC1006(OutputStream out, String message) throws Exception {
        byte[] msgBytes = message.getBytes("UTF-8");
        ByteBuffer bb = ByteBuffer.allocate(2 + msgBytes.length);
        bb.putShort((short) msgBytes.length);
        bb.put(msgBytes);
        out.write(bb.array());
        out.flush();
    }
}