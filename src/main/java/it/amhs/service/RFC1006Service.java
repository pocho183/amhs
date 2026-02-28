package it.amhs.service;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.EOFException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import it.amhs.domain.AMHSMessage;
import it.amhs.domain.AMHSPriority;
import it.amhs.domain.AMHSProfile;
import it.amhs.repository.AMHSMessageRepository;

@Service
public class RFC1006Service {

    private static final Logger logger = LoggerFactory.getLogger(RFC1006Service.class);
    private static final byte TPKT_VERSION = 0x03;
    private static final byte TPKT_RESERVED = 0x00;
    private static final byte[] COTP_DATA_HEADER = new byte[] { 0x02, (byte) 0xF0, (byte) 0x80 };

    private final AMHSMessageRepository amhsMessagesRepository;
    private final MTAService mtaService;
    private final ThreadPoolExecutor priorityExecutor;

    public RFC1006Service(AMHSMessageRepository amhsMessagesRepository, MTAService mtaService) {
        this.amhsMessagesRepository = amhsMessagesRepository;
        this.mtaService = mtaService;
        this.priorityExecutor = new ThreadPoolExecutor(
            1,
            1,
            0L,
            TimeUnit.MILLISECONDS,
            new PriorityBlockingQueue<>()
        );
    }

    public void handleClient(SSLSocket socket) {
        try (InputStream in = socket.getInputStream(); OutputStream out = socket.getOutputStream()) {
            CertificateIdentity identity = extractCertificateIdentity(socket);

            while (true) {
                byte[] payload = readFramedPayload(in);
                if (payload == null) {
                    break;
                }

                String message = new String(payload, StandardCharsets.UTF_8).trim();

                if (message.startsWith("RETRIEVE")) {
                    handleRetrieve(message, out);
                    continue;
                }

                IncomingMessage incoming = parseIncomingMessage(message, identity);
                try {
                    storeWithStrictPriority(incoming);
                    String ack = "Message-ID: " + incoming.messageId + "\n"
                        + "From: " + incoming.to + "\n"
                        + "To: " + incoming.from + "\n"
                        + "Status: RECEIVED\n";
                    sendRFC1006(out, ack);
                } catch (IllegalArgumentException ex) {
                    logger.warn("AMHS message rejected: {}", ex.getMessage());
                    String nack = "Message-ID: " + incoming.messageId + "\n"
                        + "Status: REJECTED\n"
                        + "Error: " + ex.getMessage() + "\n";
                    sendRFC1006(out, nack);
                }
            }
        } catch (Exception e) {
            logger.error("RFC1006 handling error", e);
        } finally {
            try {
                socket.close();
            } catch (Exception ignored) {
            }
        }
    }

    private void storeWithStrictPriority(IncomingMessage incoming) {
        PriorityFutureTask task = new PriorityFutureTask(incoming, () -> mtaService.storeMessage(
            incoming.from,
            incoming.to,
            incoming.body,
            incoming.messageId,
            incoming.profile,
            incoming.priority,
            incoming.subject,
            incoming.channel,
            incoming.certificateCn,
            incoming.certificateOu,
            incoming.filingTime
        ));
        priorityExecutor.execute(task);
        try {
            task.get();
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("AMHS message interrupted while waiting for priority queue", ex);
        } catch (ExecutionException ex) {
            Throwable cause = ex.getCause();
            if (cause instanceof IllegalArgumentException iae) {
                throw iae;
            }
            throw new IllegalStateException("Failed to process AMHS message", cause);
        }
    }

    private IncomingMessage parseIncomingMessage(String message, CertificateIdentity identity) {
        Map<String, String> headers = new HashMap<>();
        String body = "";

        String[] parts = message.split(",|\\n");
        for (String part : parts) {
            if (!part.contains(":")) {
                continue;
            }
            String[] kv = part.split(":", 2);
            String key = kv[0].trim();
            String value = kv[1].trim();

            if (key.equalsIgnoreCase("Body")) {
                body = value;
            } else {
                headers.put(key, value);
            }
        }

        String messageId = headers.getOrDefault("Message-ID", UUID.randomUUID().toString());
        String from = headers.getOrDefault("From", "UNKNOWN");
        String to = headers.getOrDefault("To", "UNKNOWN");
        AMHSProfile profile = parseProfile(headers.getOrDefault("Profile", "P3"));
        AMHSPriority priority = parsePriority(headers.getOrDefault("Priority", "GG"));
        String subject = headers.getOrDefault("Subject", "");
        String channel = headers.getOrDefault("Channel", AMHSChannelService.DEFAULT_CHANNEL_NAME);
        Date filingTime = parseFilingTime(headers.get("Filing-Time"));

        return new IncomingMessage(
            messageId,
            from,
            to,
            body,
            profile,
            priority,
            subject,
            channel,
            identity.cn(),
            identity.ou(),
            filingTime,
            System.nanoTime()
        );
    }

    private void handleRetrieve(String command, OutputStream out) throws Exception {
        String response;
        if (command.equalsIgnoreCase("RETRIEVE ALL")) {
            List<AMHSMessage> allMsgs = amhsMessagesRepository.findAll();
            if (allMsgs.isEmpty()) {
                response = "No messages.\n";
            } else {
                response = allMsgs.stream().map(m -> String.format(
                    "ID: %s | From: %s | Channel: %s | Priority: %s | Filing-Time: %s | Body: %s",
                    m.getMessageId(),
                    m.getSender(),
                    m.getChannelName(),
                    m.getPriority(),
                    m.getFilingTime(),
                    m.getBody()
                )).collect(java.util.stream.Collectors.joining("\n---\n")) + "\n";
            }
        } else if (command.toUpperCase().startsWith("RETRIEVE ")) {
            String messageId = command.substring("RETRIEVE ".length()).trim();
            response = amhsMessagesRepository.findByMessageId(messageId)
                .map(m -> String.format(
                    "From: %s\nTo: %s\nChannel: %s\nProfile: %s\nPriority: %s\nFiling-Time: %s\nBody: %s\n",
                    m.getSender(),
                    m.getRecipient(),
                    m.getChannelName(),
                    m.getProfile(),
                    m.getPriority(),
                    m.getFilingTime(),
                    m.getBody()
                ))
                .orElse("Message-ID " + messageId + " not found.\n");
        } else {
            response = "Unknown command.\n";
        }
        sendRFC1006(out, response);
    }

    private AMHSProfile parseProfile(String value) {
        try {
            return AMHSProfile.valueOf(value.trim().toUpperCase());
        } catch (Exception ex) {
            logger.warn("Unsupported profile '{}', defaulting to P3", value);
            return AMHSProfile.P3;
        }
    }

    private AMHSPriority parsePriority(String value) {
        try {
            return AMHSPriority.valueOf(value.trim().toUpperCase());
        } catch (Exception ex) {
            logger.warn("Unsupported priority '{}', defaulting to GG", value);
            return AMHSPriority.GG;
        }
    }

    private Date parseFilingTime(String filingTimeHeader) {
        if (filingTimeHeader == null || filingTimeHeader.isBlank()) {
            return Date.from(Instant.now());
        }

        try {
            return Date.from(Instant.parse(filingTimeHeader.trim()));
        } catch (Exception ignored) {
        }

        try {
            SimpleDateFormat format = new SimpleDateFormat("yyyyMMddHHmmss");
            format.setTimeZone(TimeZone.getTimeZone("UTC"));
            return format.parse(filingTimeHeader.trim());
        } catch (ParseException ex) {
            logger.warn("Invalid Filing-Time '{}', defaulting to now", filingTimeHeader);
            return Date.from(Instant.now());
        }
    }

    private CertificateIdentity extractCertificateIdentity(SSLSocket socket) {
        try {
            Principal principal = socket.getSession().getPeerPrincipal();
            return parseDn(principal.getName());
        } catch (SSLPeerUnverifiedException ex) {
            logger.info("Client certificate not provided");
            return new CertificateIdentity(null, null);
        } catch (Exception ex) {
            logger.warn("Failed to parse client certificate identity", ex);
            return new CertificateIdentity(null, null);
        }
    }

    private CertificateIdentity parseDn(String dn) throws Exception {
        String cn = null;
        String ou = null;
        LdapName ldapName = new LdapName(dn);
        for (Rdn rdn : ldapName.getRdns()) {
            if ("CN".equalsIgnoreCase(rdn.getType())) {
                cn = String.valueOf(rdn.getValue());
            }
            if ("OU".equalsIgnoreCase(rdn.getType())) {
                ou = String.valueOf(rdn.getValue());
            }
        }
        return new CertificateIdentity(cn, ou);
    }

    private byte[] readFramedPayload(InputStream in) throws Exception {
        int first = in.read();
        if (first == -1) {
            return null;
        }

        int second = in.read();
        if (second == -1) {
            throw new EOFException("Connection closed while reading frame header");
        }

        if (first == TPKT_VERSION && second == TPKT_RESERVED) {
            int lenHi = in.read();
            int lenLo = in.read();
            if (lenHi == -1 || lenLo == -1) {
                throw new EOFException("Connection closed while reading TPKT length");
            }
            int tpktLength = ((lenHi & 0xFF) << 8) | (lenLo & 0xFF);
            if (tpktLength < 7) {
                throw new IllegalArgumentException("Invalid TPKT frame length: " + tpktLength);
            }

            byte[] cotp = readFully(in, 3);
            if (cotp[0] != COTP_DATA_HEADER[0] || cotp[1] != COTP_DATA_HEADER[1] || cotp[2] != COTP_DATA_HEADER[2]) {
                throw new IllegalArgumentException("Unsupported COTP header in RFC1006 payload");
            }

            return readFully(in, tpktLength - 7);
        }

        int legacyLength = ((first & 0xFF) << 8) | (second & 0xFF);
        return readFully(in, legacyLength);
    }

    private byte[] readFully(InputStream in, int length) throws Exception {
        byte[] data = new byte[length];
        int offset = 0;
        while (offset < length) {
            int read = in.read(data, offset, length - offset);
            if (read == -1) {
                throw new EOFException("Connection closed while reading payload");
            }
            offset += read;
        }
        return data;
    }

    private void sendRFC1006(OutputStream out, String message) throws Exception {
        byte[] msgBytes = message.getBytes(StandardCharsets.UTF_8);
        int tpktLength = 4 + COTP_DATA_HEADER.length + msgBytes.length;
        ByteBuffer bb = ByteBuffer.allocate(tpktLength);
        bb.put(TPKT_VERSION);
        bb.put(TPKT_RESERVED);
        bb.putShort((short) tpktLength);
        bb.put(COTP_DATA_HEADER);
        bb.put(msgBytes);
        out.write(bb.array());
        out.flush();
    }

    private record CertificateIdentity(String cn, String ou) {
    }

    private record IncomingMessage(
        String messageId,
        String from,
        String to,
        String body,
        AMHSProfile profile,
        AMHSPriority priority,
        String subject,
        String channel,
        String certificateCn,
        String certificateOu,
        Date filingTime,
        long sequence
    ) {
    }

    private static final class PriorityFutureTask extends FutureTask<AMHSMessage> implements Comparable<PriorityFutureTask> {

        private final IncomingMessage incoming;

        private PriorityFutureTask(IncomingMessage incoming, java.util.concurrent.Callable<AMHSMessage> callable) {
            super(callable);
            this.incoming = incoming;
        }

        @Override
        public int compareTo(PriorityFutureTask other) {
            int byPriority = Integer.compare(priorityWeight(this.incoming.priority), priorityWeight(other.incoming.priority));
            if (byPriority != 0) {
                return byPriority;
            }
            int byFilingTime = this.incoming.filingTime.compareTo(other.incoming.filingTime);
            if (byFilingTime != 0) {
                return byFilingTime;
            }
            return Long.compare(this.incoming.sequence, other.incoming.sequence);
        }

        private static int priorityWeight(AMHSPriority priority) {
            return switch (priority) {
                case SS -> 0;
                case DD -> 1;
                case FF -> 2;
                case GG -> 3;
                case KK -> 4;
            };
        }
    }
}
