package it.amhs.service;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Optional;
import java.util.TimeZone;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.springframework.stereotype.Component;

import it.amhs.asn1.BerCodec;
import it.amhs.asn1.BerTlv;
import it.amhs.domain.AMHSMessage;

@Component
public class Rfc1006OutboundP1Client implements OutboundP1Client {

    private final P1AssociationProtocol p1AssociationProtocol;

    public Rfc1006OutboundP1Client(P1AssociationProtocol p1AssociationProtocol) {
        this.p1AssociationProtocol = p1AssociationProtocol;
    }

    private static final byte TPKT_VERSION = 0x03;
    private static final byte TPKT_RESERVED = 0x00;
    private static final byte COTP_LENGTH_DT = 0x02;
    private static final byte COTP_PDU_CR = (byte) 0xE0;
    private static final byte COTP_PDU_CC = (byte) 0xD0;
    private static final byte COTP_PDU_DT = (byte) 0xF0;
    private static final byte COTP_TPDU_SIZE_65531 = 0x0A;

    @Override
    public RelayTransferOutcome relay(String endpoint, AMHSMessage message) {
        String[] hostPort = endpoint.split(":", 2);
        String host = hostPort[0];
        int port = Integer.parseInt(hostPort.length > 1 ? hostPort[1] : "102");

        try (SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket(host, port);
             OutputStream out = socket.getOutputStream();
             InputStream in = socket.getInputStream()) {

            sendFrame(out, buildConnectionRequestTpdu());
            COTPFrame connectResponse = readFrame(in);
            if (connectResponse.type != COTP_PDU_CC) {
                throw new IllegalStateException("Expected COTP CC after CR, got TPDU type 0x" + Integer.toHexString(connectResponse.type & 0xFF));
            }

            sendDataFrame(out, encodeBind(message));
            P1AssociationProtocol.Pdu bindResult = p1AssociationProtocol.decode(readFrame(in).payload());
            if (!(bindResult instanceof P1AssociationProtocol.BindResultPdu bind) || !bind.accepted()) {
                throw new IllegalStateException("P1 bind rejected by peer");
            }

            byte[] payload = encodeMessage(message);
            byte[] transfer = BerCodec.encode(new BerTlv(2, true, 1, 0, payload.length, payload));
            sendDataFrame(out, transfer);
            P1AssociationProtocol.Pdu transferResult = p1AssociationProtocol.decode(readFrame(in).payload());
            RelayTransferOutcome outcome = mapTransferOutcome(message, transferResult);

            sendDataFrame(out, BerCodec.encode(new BerTlv(2, true, 2, 0, 0, new byte[0])));
            readFrame(in);
            return outcome;
        } catch (Exception ex) {
            throw new IllegalStateException("Outbound relay failure to endpoint " + endpoint, ex);
        }
    }

    private RelayTransferOutcome mapTransferOutcome(AMHSMessage message, P1AssociationProtocol.Pdu pdu) {
        if (!(pdu instanceof P1AssociationProtocol.TransferResultPdu transferResult)) {
            throw new IllegalStateException("Expected P1 transfer-result but received " + pdu.getClass().getSimpleName());
        }

        LinkedHashMap<String, RelayTransferOutcome.RecipientOutcome> recipients = new LinkedHashMap<>();
        for (P1AssociationProtocol.RecipientTransferResult recipient : transferResult.recipientResults()) {
            recipients.put(recipient.recipient(), new RelayTransferOutcome.RecipientOutcome(
                recipient.status(),
                recipient.diagnostic().orElse(null)
            ));
        }

        String mtsIdentifier = transferResult.mtsIdentifier()
            .orElseGet(() -> Optional.ofNullable(message.getMtsIdentifier()).orElse(message.getMessageId()));
        return new RelayTransferOutcome(transferResult.accepted(), mtsIdentifier, transferResult.diagnostic(), recipients);
    }

    private byte[] encodeBind(AMHSMessage message) {
        return p1AssociationProtocol.encodeBind(
            Optional.ofNullable(message.getSender()).map(String::trim).filter(s -> !s.isEmpty()),
            Optional.ofNullable(message.getRecipient()).map(String::trim).filter(s -> !s.isEmpty()),
            Optional.empty(),
            Optional.empty()
        );
    }

    private byte[] buildConnectionRequestTpdu() {
        byte[] tpdu = new byte[7];
        tpdu[0] = 0x06;
        tpdu[1] = COTP_PDU_CR;
        tpdu[2] = 0x00;
        tpdu[3] = 0x01;
        tpdu[4] = 0x00;
        tpdu[5] = 0x00;
        tpdu[6] = COTP_TPDU_SIZE_65531;
        return tpdu;
    }

    private byte[] encodeMessage(AMHSMessage message) {
        byte[] from = contextIa5(0, message.getSender());
        byte[] to = contextIa5(1, message.getRecipient());
        byte[] body = contextUtf8(2, message.getBody());
        byte[] profile = contextEnumerated(3, message.getProfile() == null ? 0 : switch (message.getProfile()) {
            case P1 -> 0;
            case P3 -> 1;
            case P7 -> 2;
        });
        byte[] priority = contextEnumerated(4, message.getPriority() == null ? 3 : switch (message.getPriority()) {
            case SS -> 0;
            case DD -> 1;
            case FF -> 2;
            case GG -> 3;
            case KK -> 4;
        });
        byte[] subject = optionalContextUtf8(5, message.getSubject());
        byte[] messageId = optionalContextIa5(6, message.getMessageId());
        byte[] filingTime = optionalGeneralizedTime(8, message.getFilingTime());

        byte[] envelope = transferEnvelope(message);
        byte[] seqValue = concat(from, to, body, profile, priority, subject, messageId, filingTime, envelope);
        return BerCodec.encode(new BerTlv(0, true, 16, 0, seqValue.length, seqValue));
    }

    private byte[] transferEnvelope(AMHSMessage message) {
        byte[] mtsIdentifierValue = concat(
            optionalContextIa5(0, Optional.ofNullable(message.getMtsIdentifier()).orElse(message.getMessageId())),
            optionalGeneralizedTime(1, message.getFilingTime())
        );
        byte[] mtsIdentifier = BerCodec.encode(new BerTlv(2, true, 0, 0, mtsIdentifierValue.length, mtsIdentifierValue));

        byte[] recipientEntryValue = optionalContextIa5(0, message.getRecipient());
        byte[] recipientEntry = BerCodec.encode(new BerTlv(2, true, 0, 0, recipientEntryValue.length, recipientEntryValue));
        byte[] perRecipientFields = BerCodec.encode(new BerTlv(2, true, 1, 0, recipientEntry.length, recipientEntry));

        byte[] contentType = optionalContextIa5(3, message.getTransferContentTypeOid());
        byte[] originator = optionalContextIa5(4, message.getSender());
        byte[] envelopeValue = concat(mtsIdentifier, perRecipientFields, contentType, originator);
        return BerCodec.encode(new BerTlv(2, true, 9, 0, envelopeValue.length, envelopeValue));
    }

    private byte[] contextIa5(int tag, String value) {
        byte[] bytes = value == null ? new byte[0] : value.getBytes(StandardCharsets.US_ASCII);
        return BerCodec.encode(new BerTlv(2, false, tag, 0, bytes.length, bytes));
    }

    private byte[] optionalContextIa5(int tag, String value) {
        if (value == null || value.isBlank()) {
            return new byte[0];
        }
        byte[] bytes = value.trim().getBytes(StandardCharsets.US_ASCII);
        return BerCodec.encode(new BerTlv(2, false, tag, 0, bytes.length, bytes));
    }

    private byte[] contextUtf8(int tag, String value) {
        byte[] bytes = value == null ? new byte[0] : value.getBytes(StandardCharsets.UTF_8);
        return BerCodec.encode(new BerTlv(2, false, tag, 0, bytes.length, bytes));
    }

    private byte[] optionalContextUtf8(int tag, String value) {
        if (value == null || value.isBlank()) {
            return new byte[0];
        }
        byte[] bytes = value.trim().getBytes(StandardCharsets.UTF_8);
        return BerCodec.encode(new BerTlv(2, false, tag, 0, bytes.length, bytes));
    }

    private byte[] contextEnumerated(int tag, int value) {
        return BerCodec.encode(new BerTlv(2, false, tag, 0, 1, new byte[] {(byte) value}));
    }

    private byte[] optionalGeneralizedTime(int tag, java.util.Date value) {
        if (value == null) {
            return new byte[0];
        }
        SimpleDateFormat format = new SimpleDateFormat("yyyyMMddHHmmss'Z'", Locale.ROOT);
        format.setTimeZone(TimeZone.getTimeZone("UTC"));
        byte[] bytes = format.format(value).getBytes(StandardCharsets.US_ASCII);
        return BerCodec.encode(new BerTlv(2, false, tag, 0, bytes.length, bytes));
    }

    private byte[] concat(byte[]... chunks) {
        int len = 0;
        for (byte[] chunk : chunks) {
            len += chunk.length;
        }
        byte[] out = new byte[len];
        int offset = 0;
        for (byte[] chunk : chunks) {
            System.arraycopy(chunk, 0, out, offset, chunk.length);
            offset += chunk.length;
        }
        return out;
    }

    private void sendFrame(OutputStream out, byte[] cotpTpdu) throws Exception {
        int length = 4 + cotpTpdu.length;
        byte[] tpkt = new byte[length];
        tpkt[0] = TPKT_VERSION;
        tpkt[1] = TPKT_RESERVED;
        tpkt[2] = (byte) ((length >> 8) & 0xFF);
        tpkt[3] = (byte) (length & 0xFF);
        System.arraycopy(cotpTpdu, 0, tpkt, 4, cotpTpdu.length);
        out.write(tpkt);
        out.flush();
    }

    private void sendDataFrame(OutputStream out, byte[] payload) throws Exception {
        byte[] tpdu = new byte[3 + payload.length];
        tpdu[0] = COTP_LENGTH_DT;
        tpdu[1] = COTP_PDU_DT;
        tpdu[2] = (byte) 0x80;
        System.arraycopy(payload, 0, tpdu, 3, payload.length);
        sendFrame(out, tpdu);
    }

    private COTPFrame readFrame(InputStream in) throws Exception {
        byte[] hdr = in.readNBytes(4);
        if (hdr.length < 4) {
            throw new IllegalStateException("No RFC1006 response");
        }
        int length = ((hdr[2] & 0xFF) << 8) | (hdr[3] & 0xFF);
        byte[] body = in.readNBytes(length - 4);
        if (body.length != length - 4) {
            throw new IllegalStateException("Short RFC1006 response");
        }
        if (body.length < 2) {
            throw new IllegalStateException("Short COTP TPDU");
        }

        byte type = (byte) (body[1] & (byte) 0xF0);
        if (type == COTP_PDU_DT) {
            if (body.length < 3) {
                throw new IllegalStateException("Short COTP DT TPDU");
            }
            return new COTPFrame(type, Arrays.copyOfRange(body, 3, body.length));
        }
        return new COTPFrame(type, body);
    }

    private record COTPFrame(byte type, byte[] payload) {
    }

}
