package it.amhs.service;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.springframework.stereotype.Component;

import it.amhs.asn1.BerCodec;
import it.amhs.asn1.BerTlv;
import it.amhs.domain.AMHSMessage;

@Component
public class Rfc1006OutboundP1Client implements OutboundP1Client {

    private static final byte TPKT_VERSION = 0x03;
    private static final byte TPKT_RESERVED = 0x00;
    private static final byte[] COTP_DATA_HEADER = new byte[] { 0x02, (byte) 0xF0, (byte) 0x80 };

    @Override
    public void relay(String endpoint, AMHSMessage message) {
        String[] hostPort = endpoint.split(":", 2);
        String host = hostPort[0];
        int port = Integer.parseInt(hostPort.length > 1 ? hostPort[1] : "102");

        try (SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket(host, port);
             OutputStream out = socket.getOutputStream();
             InputStream in = socket.getInputStream()) {

            sendFrame(out, encodeBind(message));
            readFrame(in);

            byte[] payload = encodeMessage(message);
            byte[] transfer = BerCodec.encode(new BerTlv(2, true, 1, 0, payload.length, payload));
            sendFrame(out, transfer);
            readFrame(in);

            sendFrame(out, BerCodec.encode(new BerTlv(2, true, 2, 0, 0, new byte[0])));
        } catch (Exception ex) {
            throw new IllegalStateException("Outbound relay failure to endpoint " + endpoint, ex);
        }
    }

    private byte[] encodeBind(AMHSMessage message) {
        byte[] calling = message.getSender().getBytes(StandardCharsets.US_ASCII);
        byte[] called = message.getRecipient().getBytes(StandardCharsets.US_ASCII);
        byte[] oidValue = new byte[] { 0x56, 0x00, 0x01, 0x06, 0x01 }; // 2.6.0.1.6.1
        byte[] oidTlv = BerCodec.encode(new BerTlv(0, false, 6, 0, oidValue.length, oidValue));

        byte[] fields = concat(
            BerCodec.encode(new BerTlv(2, false, 0, 0, calling.length, calling)),
            BerCodec.encode(new BerTlv(2, false, 1, 0, called.length, called)),
            BerCodec.encode(new BerTlv(2, true, 2, 0, oidTlv.length, oidTlv))
        );
        return BerCodec.encode(new BerTlv(2, true, 0, 0, fields.length, fields));
    }

    private byte[] encodeMessage(AMHSMessage message) {
        return message.getBody().getBytes(StandardCharsets.UTF_8);
    }

    private void sendFrame(OutputStream out, byte[] payload) throws Exception {
        int length = 4 + COTP_DATA_HEADER.length + payload.length;
        byte[] tpkt = new byte[length];
        tpkt[0] = TPKT_VERSION;
        tpkt[1] = TPKT_RESERVED;
        tpkt[2] = (byte) ((length >> 8) & 0xFF);
        tpkt[3] = (byte) (length & 0xFF);
        System.arraycopy(COTP_DATA_HEADER, 0, tpkt, 4, COTP_DATA_HEADER.length);
        System.arraycopy(payload, 0, tpkt, 4 + COTP_DATA_HEADER.length, payload.length);
        out.write(tpkt);
        out.flush();
    }

    private byte[] readFrame(InputStream in) throws Exception {
        byte[] hdr = in.readNBytes(4);
        if (hdr.length < 4) {
            throw new IllegalStateException("No RFC1006 response");
        }
        int length = ((hdr[2] & 0xFF) << 8) | (hdr[3] & 0xFF);
        byte[] body = in.readNBytes(length - 4);
        if (body.length != length - 4) {
            throw new IllegalStateException("Short RFC1006 response");
        }
        return Arrays.copyOfRange(body, 3, body.length);
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
}
