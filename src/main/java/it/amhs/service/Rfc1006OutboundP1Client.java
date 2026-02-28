package it.amhs.service;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;

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
    public void relay(String endpoint, AMHSMessage message) {
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
            readFrame(in);

            byte[] payload = encodeMessage(message);
            byte[] transfer = BerCodec.encode(new BerTlv(2, true, 1, 0, payload.length, payload));
            sendDataFrame(out, transfer);
            readFrame(in);

            sendDataFrame(out, BerCodec.encode(new BerTlv(2, true, 2, 0, 0, new byte[0])));
        } catch (Exception ex) {
            throw new IllegalStateException("Outbound relay failure to endpoint " + endpoint, ex);
        }
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
        return message.getBody().getBytes(StandardCharsets.UTF_8);
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
