package it.amhs.service;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLSocket;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import it.amhs.domain.AMHSMessage;
import it.amhs.repository.AMHSMessageRepository;

@Service
public class RFC1006Service {
	
	private static final Logger logger = LoggerFactory.getLogger(RFC1006Service.class);

	@Autowired
	private AMHSMessageRepository amhsMessagesRepository;


	public void handleClient(SSLSocket socket) {
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
                // TODO : Utilizzare un formato standard, modificare questa parte
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
                // SAVE
                AMHSMessage amhsMex = new AMHSMessage();
                amhsMex.setMessageId(messageId);
                amhsMex.setSender(from);
                amhsMex.setRecipient(to);
                amhsMex.setBody(body);
                amhsMessagesRepository.save(amhsMex);
                // ACKWNOLEDGE MESSAGE RETURN
                String ack = "Message-ID: " + messageId + "\n" + "From: " + to + "\n" + "To: " + from + "\n" + "Status: RECEIVED\n";
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
	        List<AMHSMessage> allMsgs = amhsMessagesRepository.findAll();
	        if (allMsgs.isEmpty()) {
	            response = "No messages.\n";
	        } else {
	            response = allMsgs.stream().map(m -> String.format("ID: %s | From: %s | Body: %s", 
	            		m.getMessageId(), m.getSender(), m.getBody())).collect(java.util.stream.Collectors.joining("\n---\n")) + "\n";
	        }
	    } else if (command.toUpperCase().startsWith("RETRIEVE ")) {
	        String messageId = command.substring("RETRIEVE ".length()).trim();
	        response = amhsMessagesRepository.findByMessageId(messageId)
	                .map(m -> String.format("From: %s\nTo: %s\nBody: %s\n",  m.getSender(), m.getRecipient(), m.getBody()))
	                .orElse("Message-ID " + messageId + " not found.\n");
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
