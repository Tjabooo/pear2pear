package pear2pear;

import java.security.SecureRandom;

class PasskeyUtil {

    private static final SecureRandom RAND = new SecureRandom();
    private static final char[] BASE32 = "ABCDEFGHJKMNPQRSTVWXYZ0123456789".toCharArray();

    static String generate() {
        byte[] b = new byte[10];
        RAND.nextBytes(b);
        String base32 = base32encode(b);
        return base32.substring(0, 4) + "-" + base32.substring(4, 8) + "-" + base32.substring(8, 12) + "-" + base32.substring(12, 16);
    }

    private static String base32encode(byte[] data) {

        StringBuilder sb = new StringBuilder(16);
        int buffer = 0, bitsLeft = 0, idx = 0;
        while (idx < data.length || bitsLeft > 0) {
            if (bitsLeft < 5) {
                if (idx < data.length) {
                    buffer <<= 8;
                    buffer |= (data[idx++] & 0xFF);
                    bitsLeft += 8;
                } else {
                    buffer <<= (5 - bitsLeft);
                    bitsLeft = 5;
                }
            }
            int val = (buffer >> (bitsLeft - 5)) & 0x1F;
            bitsLeft -= 5;
            sb.append(BASE32[val]);
            if (sb.length() == 16) break;
        }
        return sb.toString();

    }

    static boolean isValidCustom(String k) {
        if (k == null) return false;
        k = k.trim();
        if (k.length() < 8 || k.length() > 64) return false;
        return k.matches("[A-Za-z0-9_-]+" );
    }

}
