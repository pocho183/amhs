package it.amhs.test;

import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class P3TestClient {

    private static final String HOST = "127.0.0.1";
    private static final int PORT = 102;

    private static final String SUBMIT_PACKET_9_FULL_HEX =
    	    "e48d8ce5f0a16c92cf04a52d08004500024b89ab4000800600000a63011fc0a81a0ff9210066aa24e94ab37d7d0f501803fee8760000" +
    	    "0300022302f08001000103190103618202113082020d020103a0820206a1820202020101020103308201f831818f603d3028610413025858620613044943414fa20a130843414d424f444941830456445046a6061304564454493111300f800101a10a13085644544941544953650480020520460116a1453143603d3028610413025858620613044943414fa20a130843414d424f444941830456445046a6061304564450503111300f800101a10a130856445050434154538002030804820162a082015e3181b06b1360023000130d31373735373238383330363239a03f603d3028610413025858620613044943414fa20a130843414d424f444941830456445046a6061304564454493111300f800101a10a13085644544941544953a2473145a03f603d3028610413025858620613044943414fa20a130843414d424f444941830456445046a6061304564450503111300f800101a10a13085644505043415453810206c0a80f140d4441544953204d6573736167653081a8a081a5310380010516819d414420564454492f4f5320444131303030200d0a56445449204152522f444550204420313030305a200d0a52575920494e20555345203233200d0a544c203735200d0a57494e442054445a203136302f31314b54204d4944202f2f2f2f2f2f4b5420454e44203135302f31324b54200d0a4341564f4b200d0a5433352044503232200d0a514e482031303038485041200d0a5146452031303037485041";

    public static void main(String[] args) throws Exception {
        try (Socket socket = new Socket(HOST, PORT)) {
            socket.setTcpNoDelay(false);

            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();

            System.out.println("Connected to " + HOST + ":" + PORT);

            sendTpkt(out, hex(
                "0E E0 00 00 00 01 00 C0 01 0A C1 02 01 00 C2 02 01 02"
            ));
            System.out.println("COTP CC: " + toHex(readTpkt(in)));

            byte[] bindSpdu = buildBindSpdu();
            sendCotpDt(out, bindSpdu);

            byte[] bindResponse = readTpkt(in);
            System.out.println("Bind response:");
            System.out.println(toHex(bindResponse));

            byte[] submitSpdu = buildFakeSubmitSpduFromCapturedPacket();
            sendCotpDt(out, submitSpdu);

            byte[] submitResponse = readTpkt(in);
            System.out.println("Submit response:");
            System.out.println(toHex(submitResponse));

            SubmitResult result = P3SubmitResultDecoder.decodeFromTpktBody(submitResponse);
            System.out.println("Submit accepted:");
            System.out.println("  originator       = " + result.originator);
            System.out.println("  submission-id    = " + result.submissionIdentifier);
            System.out.println("  submission-time  = " + result.submissionTime);

            printSubmissionId(submitResponse);

            Thread.sleep(1000);

            System.out.println("Socket closed.");
        }
    }

    private static byte[] buildBindSpdu() {
        // Your captured bind already contains password "changeit".
        // USER is not encoded in this native bind; authenticatedIdentity is empty.
        return hex(
            "0D FF 01 00 01 26 0A 13 04 11 54 53 4E 42 4B 31 30 32 37 35 2E 31 35 64 38 2E 31 " +
            "0B 0F 17 0D 32 36 30 34 32 35 31 36 32 39 31 30 5A 05 0C 13 01 00 15 04 1F FD 1F FD " +
            "16 01 01 14 02 00 02 C1 C4 31 81 C1 A0 03 80 01 01 A2 81 B9 A4 55 30 0F 02 01 01 " +
            "06 04 52 01 00 01 30 04 06 02 51 01 30 0F 02 01 03 06 04 56 00 02 01 30 04 06 02 " +
            "51 01 30 0F 02 01 05 06 04 56 00 02 02 30 04 06 02 51 01 30 0F 02 01 07 06 04 56 " +
            "00 02 06 30 04 06 02 51 01 30 0F 02 01 09 06 04 56 00 02 0B 30 04 06 02 51 01 " +
            "61 60 30 5E 02 01 01 A0 59 60 57 A1 06 06 04 56 00 01 00 BE 4D 28 4B 06 02 51 01 " +
            "02 01 09 A0 42 B0 40 31 3E 60 30 30 2E 61 04 13 02 4B 48 62 06 13 04 49 43 41 4F " +
            "A2 07 13 05 4C 6F 63 61 6C 83 09 74 65 63 68 6E 6F 73 6B 79 A6 0A 13 08 56 44 " +
            "54 49 41 53 52 56 A2 0A 16 08 63 68 61 6E 67 65 69 74"
        );
    }
    
    private static byte[] buildFakeSubmitSpduFromCapturedPacket() {
        byte[] spdu = extractOsiPayloadFromCapturedTpkt(SUBMIT_PACKET_9_FULL_HEX);

        int c = patchAsciiAll(spdu, "XX", "IT");
        int atis = patchAsciiAll(spdu, "VDTIATIS", "LIRFATIS");
        int cats = patchAsciiAll(spdu, "VDPPCATS", "LIRFCATS");
        int o1 = patchAsciiAll(spdu, "VDPF", "LIRF");
        int o2 = patchAsciiAll(spdu, "VDPP", "LIRF");

        System.out.println("patch counts: XX=" + c +
            " VDTIATIS=" + atis +
            " VDPPCATS=" + cats +
            " VDPF=" + o1 +
            " VDPP=" + o2);

        String oldBody =
            "AD VDTI/OS DA1000 \r\n" +
            "VDTI ARR/DEP D 1000Z \r\n" +
            "RWY IN USE 23 \r\n" +
            "TL 75 \r\n" +
            "WIND TDZ 160/11KT MID //////KT END 150/12KT \r\n" +
            "CAVOK \r\n" +
            "T35 DP22 \r\n" +
            "QNH 1008HPA \r\n" +
            "QFE 1007HPA";

        String cleanBody =
            "AD LIRF/TEST PA2026\r\n" +
            "ITALIAN FAKE MESSAGE\r\n" +
            "ROMA TEST\r\n" +
            "QNH 1013HPA\r\n" +
            "END OF TEST MESSAGE";

        patchAsciiSameLength(spdu, oldBody, cleanBody);

        System.out.println("oldBody len=" + oldBody.length()
            + " cleanBody len=" + cleanBody.length());

        return spdu;
    }
    
    private static String cleanBody() {
        return "AD LIRF/TEST PA2026\r\n" +
               "ITALIAN FAKE MESSAGE\r\n" +
               "ROMA TEST\r\n" +
               "QNH 1013HPA\r\n" +
               "END OF TEST MESSAGE";
    }
    
    private static byte[] extractOsiPayloadFromCapturedTpkt(String fullHex) {
        byte[] all = hex(fullHex);

        for (int i = 0; i < all.length - 7; i++) {
            if ((all[i] & 0xFF) == 0x03
                && (all[i + 1] & 0xFF) == 0x00
                && (all[i + 4] & 0xFF) == 0x02
                && (all[i + 5] & 0xFF) == 0xF0
                && (all[i + 6] & 0xFF) == 0x80) {

                return java.util.Arrays.copyOfRange(all, i + 7, all.length);
            }
        }

        throw new IllegalArgumentException("Could not find TPKT+COTP DT header 03 00 xx xx 02 F0 80");
    }

    private static int patchAsciiAll(byte[] data, String oldValue, String newValue) {
        if (oldValue.length() != newValue.length()) {
            throw new IllegalArgumentException("Patch must keep same length");
        }

        byte[] oldBytes = oldValue.getBytes(StandardCharsets.US_ASCII);
        byte[] newBytes = newValue.getBytes(StandardCharsets.US_ASCII);

        int count = 0;
        int pos = 0;

        while ((pos = indexOf(data, oldBytes, pos)) >= 0) {
            System.arraycopy(newBytes, 0, data, pos, newBytes.length);
            pos += newBytes.length;
            count++;
        }

        return count;
    }

    private static int indexOf(byte[] data, byte[] needle, int from) {
        outer:
        for (int i = from; i <= data.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (data[i + j] != needle[j]) continue outer;
            }
            return i;
        }
        return -1;
    }

    private static void patchAsciiSameLength(byte[] data, String oldValue, String newValue) {
        byte[] oldBytes = oldValue.getBytes(StandardCharsets.US_ASCII);
        byte[] newBytes = fitAscii(newValue, oldBytes.length);

        int pos = indexOf(data, oldBytes);
        if (pos < 0) {
            System.out.println("WARNING: old body not found in submit SPDU; body not patched.");
            return;
        }

        System.arraycopy(newBytes, 0, data, pos, newBytes.length);
    }

    private static byte[] fitAscii(String value, int length) {
        byte[] raw = value.getBytes(StandardCharsets.US_ASCII);
        byte[] out = new byte[length];
        Arrays.fill(out, (byte) ' ');
        System.arraycopy(raw, 0, out, 0, Math.min(raw.length, length));
        return out;
    }

    private static int indexOf(byte[] data, byte[] needle) {
        outer:
        for (int i = 0; i <= data.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (data[i + j] != needle[j]) continue outer;
            }
            return i;
        }
        return -1;
    }

    private static void sendCotpDt(OutputStream out, byte[] userData) throws IOException {
        byte[] tpdu = new byte[3 + userData.length];
        tpdu[0] = 0x02;
        tpdu[1] = (byte) 0xF0;
        tpdu[2] = (byte) 0x80;
        System.arraycopy(userData, 0, tpdu, 3, userData.length);
        sendTpkt(out, tpdu);
    }

    private static void sendTpkt(OutputStream out, byte[] tpdu) throws IOException {
        int len = 4 + tpdu.length;
        byte[] frame = new byte[len];

        frame[0] = 0x03;
        frame[1] = 0x00;
        frame[2] = (byte) ((len >> 8) & 0xFF);
        frame[3] = (byte) (len & 0xFF);

        System.arraycopy(tpdu, 0, frame, 4, tpdu.length);

        out.write(frame);
        out.flush();

        System.out.println("Sent TPKT len=" + len + " payload=" + tpdu.length);
    }

    private static byte[] readTpkt(InputStream in) throws IOException {
        byte[] header = in.readNBytes(4);
        if (header.length < 4) throw new EOFException("No TPKT header");

        if ((header[0] & 0xFF) != 0x03 || (header[1] & 0xFF) != 0x00) {
            throw new IOException("Invalid TPKT header: " + toHex(header));
        }

        int len = ((header[2] & 0xFF) << 8) | (header[3] & 0xFF);
        byte[] body = in.readNBytes(len - 4);
        if (body.length != len - 4) throw new EOFException("Truncated TPKT body");

        return body;
    }

    private static byte[] hex(String s) {
        String clean = s.replaceAll("[^0-9A-Fa-f]", "");
        if ((clean.length() % 2) != 0) throw new IllegalArgumentException("Odd hex length");

        byte[] out = new byte[clean.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            if (sb.length() > 0) sb.append(' ');
            sb.append(String.format("%02X", b & 0xFF));
        }
        return sb.toString();
    }
    
    private static void printSubmissionId(byte[] tpktBody) {
        // skip COTP header (02 F0 80)
        int offset = 3;

        // skip OSI session header (01 00 01 03 19 01 03)
        offset += 7;

        // now we are at presentation (61 ...)
        // find IA5String tag (0x16)
        for (int i = offset; i < tpktBody.length - 2; i++) {
            if ((tpktBody[i] & 0xFF) == 0x16) {
                int len = tpktBody[i + 1] & 0xFF;

                if (i + 2 + len <= tpktBody.length) {
                    String value = new String(
                        tpktBody,
                        i + 2,
                        len,
                        StandardCharsets.US_ASCII
                    );

                    if (value.contains("it-")) {
                        System.out.println("Submission-ID = " + value);
                        return;
                    }
                }
            }
        }

        System.out.println("Submission-ID not found");
    }
    
    
    private record SubmitResult(
    	    String originator,
    	    String submissionIdentifier,
    	    String submissionTime
    	) {}

    	private static final class P3SubmitResultDecoder {

    	    static SubmitResult decodeFromTpktBody(byte[] body) {
    	        byte[] payload = stripTransportAndSession(body);

    	        String originator = findOriginator(payload);
    	        String submissionId = findFirstIa5Containing(payload, "it-");
    	        String submissionTime = findLastUtcTime(payload);

    	        return new SubmitResult(originator, submissionId, submissionTime);
    	    }

    	    private static byte[] stripTransportAndSession(byte[] body) {
    	        int off = 0;

    	        // COTP DT: 02 F0 80
    	        if (body.length >= 3 &&
    	            (body[0] & 0xFF) == 0x02 &&
    	            (body[1] & 0xFF) == 0xF0 &&
    	            (body[2] & 0xFF) == 0x80) {
    	            off = 3;
    	        }

    	        // OSI session carrier used by your gateway:
    	        // 01 00 01 03 19 01 03
    	        if (body.length >= off + 7 &&
    	            (body[off] & 0xFF) == 0x01 &&
    	            (body[off + 1] & 0xFF) == 0x00 &&
    	            (body[off + 2] & 0xFF) == 0x01 &&
    	            (body[off + 3] & 0xFF) == 0x03 &&
    	            (body[off + 4] & 0xFF) == 0x19 &&
    	            (body[off + 5] & 0xFF) == 0x01 &&
    	            (body[off + 6] & 0xFF) == 0x03) {
    	            off += 7;
    	        }

    	        return Arrays.copyOfRange(body, off, body.length);
    	    }

    	    private static String findOriginator(byte[] data) {
    	        // In your SubmitResult:
    	        // 61 04 13 02 4B 48 62 06 13 04 49 43 41 4F 13 05 4C 6F 63 61 6C
    	        // means /C=KH/ADMD=ICAO/PRMD=Local
    	        String c = null;
    	        String admd = null;
    	        String prmd = null;

    	        for (int i = 0; i < data.length - 2; i++) {
    	            int tag = data[i] & 0xFF;

    	            if (tag == 0x61 && i + 5 < data.length && (data[i + 2] & 0xFF) == 0x13) {
    	                int len = data[i + 3] & 0xFF;
    	                if (i + 4 + len <= data.length) {
    	                    c = new String(data, i + 4, len, StandardCharsets.US_ASCII);
    	                }
    	            }

    	            if (tag == 0x62 && i + 5 < data.length && (data[i + 2] & 0xFF) == 0x13) {
    	                int len = data[i + 3] & 0xFF;
    	                if (i + 4 + len <= data.length) {
    	                    admd = new String(data, i + 4, len, StandardCharsets.US_ASCII);
    	                }
    	            }

    	            if (tag == 0x13) {
    	                int len = data[i + 1] & 0xFF;
    	                if (i + 2 + len <= data.length) {
    	                    String s = new String(data, i + 2, len, StandardCharsets.US_ASCII);
    	                    if ("Local".equalsIgnoreCase(s)) {
    	                        prmd = s;
    	                    }
    	                }
    	            }
    	        }

    	        if (c == null && admd == null && prmd == null) {
    	            return null;
    	        }

    	        return "/C=" + nullToEmpty(c)
    	            + "/ADMD=" + nullToEmpty(admd)
    	            + "/PRMD=" + nullToEmpty(prmd);
    	    }

    	    private static String findFirstIa5Containing(byte[] data, String needle) {
    	        for (int i = 0; i < data.length - 2; i++) {
    	            if ((data[i] & 0xFF) == 0x16) {
    	                int len = data[i + 1] & 0xFF;
    	                if (i + 2 + len <= data.length) {
    	                    String s = new String(data, i + 2, len, StandardCharsets.US_ASCII);
    	                    if (s.contains(needle)) {
    	                        return s;
    	                    }
    	                }
    	            }
    	        }
    	        return null;
    	    }

    	    private static String findLastUtcTime(byte[] data) {
    	        String last = null;

    	        for (int i = 0; i < data.length - 2; i++) {
    	            if ((data[i] & 0xFF) == 0x80) {
    	                int len = data[i + 1] & 0xFF;
    	                if (i + 2 + len <= data.length) {
    	                    String s = new String(data, i + 2, len, StandardCharsets.US_ASCII);
    	                    if (s.endsWith("Z")) {
    	                        last = s;
    	                    }
    	                }
    	            }
    	        }

    	        return last;
    	    }

    	    private static String nullToEmpty(String value) {
    	        return value == null ? "" : value;
    	    }
    	}
    
    
    	final class OsiAcseRoseClientWrapper {

    	    static byte[] wrapAarq(byte[] p3BindArgument) {
    	        byte[] acseUserData = ber(
    	            0xBE,
    	            ber(0x28,
    	                concat(
    	                    oid51(),
    	                    int1(9),
    	                    ber(0xA0,
    	                        ber(0xB0, p3BindArgument)
    	                    )
    	                )
    	            )
    	        );

    	        byte[] aarq = ber(
    	            0x60,
    	            concat(
    	                ber(0xA1, oid5600100()),
    	                acseUserData
    	            )
    	        );

    	        return wrapPresentationCp(aarq);
    	    }

    	    static byte[] wrapRoseInvoke(int invokeId, byte[] p3SubmitArgument) {
    	        byte[] roseInvoke = ber(
    	            0xA1,
    	            concat(
    	                int1(invokeId),
    	                int1(3),
    	                p3SubmitArgument
    	            )
    	        );

    	        return wrapPresentationUserData(roseInvoke);
    	    }

    	    private static byte[] wrapPresentationCp(byte[] acse) {
    	        return buildSessionConnect(
    	            ber(0x31,
    	                concat(
    	                    presentationContexts(),
    	                    ber(0x61,
    	                        ber(0x30,
    	                            concat(
    	                                int1(1),
    	                                ber(0xA0, acse)
    	                            )
    	                        )
    	                    )
    	                )
    	            )
    	        );
    	    }

    	    private static byte[] wrapPresentationUserData(byte[] rose) {
    	        byte[] userData = ber(
    	            0x61,
    	            ber(0x30,
    	                concat(
    	                    int1(3),
    	                    ber(0xA0, rose)
    	                )
    	            )
    	        );

    	        return concat(hex("01 00 01 03 19 01 03"), userData);
    	    }

    	    private static byte[] buildSessionConnect(byte[] presentation) {
    	        return concat(
    	            hex("0D FF 01 00 01 26 0A 13 04 11 54 53 4E 42 4B 31 30 32 37 35 2E 31 35 64 38 2E 31 0B 0F 17 0D 32 36 30 34 32 35 31 36 32 39 31 30 5A 05 0C 13 01 00 15 04 1F FD 1F FD 16 01 01 14 02 00 02 C1"),
    	            lenOnly(presentation.length),
    	            presentation
    	        );
    	    }

    	    private static byte[] presentationContexts() {
    	        return hex(
    	            "A4 55 " +
    	            "30 0F 02 01 01 06 04 52 01 00 01 30 04 06 02 51 01 " +
    	            "30 0F 02 01 03 06 04 56 00 02 01 30 04 06 02 51 01 " +
    	            "30 0F 02 01 05 06 04 56 00 02 02 30 04 06 02 51 01 " +
    	            "30 0F 02 01 07 06 04 56 00 02 06 30 04 06 02 51 01 " +
    	            "30 0F 02 01 09 06 04 56 00 02 0B 30 04 06 02 51 01"
    	        );
    	    }

    	    private static byte[] oid51() {
    	        return hex("06 02 51 01");
    	    }

    	    private static byte[] oid5600100() {
    	        return hex("06 04 56 00 01 00");
    	    }

    	    private static byte[] int1(int value) {
    	        return new byte[] { 0x02, 0x01, (byte) value };
    	    }

    	    private static byte[] ber(int tag, byte[] value) {
    	        return concat(new byte[] { (byte) tag }, berLength(value.length), value);
    	    }

    	    private static byte[] berLength(int len) {
    	        if (len < 0x80) return new byte[] { (byte) len };
    	        if (len <= 0xFF) return new byte[] { (byte) 0x81, (byte) len };
    	        return new byte[] { (byte) 0x82, (byte) (len >> 8), (byte) len };
    	    }

    	    private static byte[] lenOnly(int len) {
    	        return len <= 0xFF
    	            ? new byte[] { (byte) len }
    	            : new byte[] { (byte) 0xFF, (byte) (len >> 8), (byte) len };
    	    }

    	    private static byte[] concat(byte[]... parts) {
    	        int len = 0;
    	        for (byte[] p : parts) len += p.length;
    	        byte[] out = new byte[len];
    	        int pos = 0;
    	        for (byte[] p : parts) {
    	            System.arraycopy(p, 0, out, pos, p.length);
    	            pos += p.length;
    	        }
    	        return out;
    	    }

    	    private static byte[] hex(String s) {
    	        String clean = s.replaceAll("[^0-9A-Fa-f]", "");
    	        byte[] out = new byte[clean.length() / 2];
    	        for (int i = 0; i < out.length; i++) {
    	            out[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
    	        }
    	        return out;
    	    }
    	}
}

