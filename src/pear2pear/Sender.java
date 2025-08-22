package pear2pear;

import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

class Sender {
    private static final String host = "57.128.212.68";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;
    private static final int PBKDF2_ITER = 100_000;
    private static final int KEY_LEN = 256;
    private static final int SALT_LEN = 16;

    void start() throws IOException {
        System.out.println("Attempting connection to relay server ...");
        try (Socket control = new Socket(host, RelayServer.CONTROL_PORT)) {
            System.out.println("Connected to relay.");
            Scanner sc = new Scanner(System.in);
            System.out.print("Path to file you want to send: ");
            String pathStr = sc.nextLine().trim();
            Path path = Path.of(pathStr);

            if (!Files.exists(path) || !Files.isRegularFile(path)) {
                System.out.println("File does not exist.");
                return;
            }

            System.out.print("Generate custom passkey (ENTER for auto-generated): ");
            String custom = sc.nextLine().trim();
            String passkey = custom.isEmpty() ? PasskeyUtil.generate() : custom;

            if (!PasskeyUtil.isValidCustom(passkey)) {
                System.out.println("Invalid passkey format. Use alphanumeric, dash or underscore (8-64 chars). Minimum 8 chars.");
                return;
            }

            long size = Files.size(path);
            if (size > 100 * 1024 * 1024) {
                System.out.println("File too large. Maximum file size is 100MB.");
                return;
            }

            SecureRandom rand = new SecureRandom();
            byte[] salt = new byte[SALT_LEN];
            byte[] iv = new byte[GCM_IV_LENGTH];
            rand.nextBytes(salt);
            rand.nextBytes(iv);
            SecretKeySpec key = deriveKey(passkey, salt);

            PrintWriter pw = new PrintWriter(new OutputStreamWriter(control.getOutputStream()), true);
            BufferedReader br = new BufferedReader(new InputStreamReader(control.getInputStream()));
            pw.println("ROLE SENDER");
            pw.println("KEY " + passkey);
            System.out.println("Passkey: " + passkey + " (share with the client)");

            String line;
            boolean ready = false;
            while ((line = br.readLine()) != null) {
                if (line.startsWith("READY")) {
                    ready = true;
                    break;
                }
                if (line.startsWith("ERR")) {
                    System.out.println("Relay error: " + line);
                    return;
                }
                if (line.startsWith("WAITING")) {
                    System.out.println("Waiting for receiver to connect...");
                }
            }

            if (!ready) {
                System.out.println("Disconnected before ready.");
                return;
            }

            try (Socket data = new Socket(host, RelayServer.DATA_PORT)) {
                OutputStream out = data.getOutputStream();
                PrintWriter dpw = new PrintWriter(new OutputStreamWriter(out), true);
                String fileName = path.getFileName().toString();
                String meta = String.format("META %s|%d|%s|%s", fileName, size,
                        Base64.getEncoder().encodeToString(salt),
                        Base64.getEncoder().encodeToString(iv));
                dpw.println("KEY " + passkey);
                dpw.println(meta);
                dpw.flush();
                System.out.println("Sending file: " + fileName + " (" + size + " bytes, encrypted)");

                try (InputStream fis = Files.newInputStream(path)) {
                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
                    cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
                    try (CipherOutputStream cos = new CipherOutputStream(out, cipher)) {
                        byte[] buf = new byte[8192];
                        int read;
                        while ((read = fis.read(buf)) != -1) {
                            cos.write(buf, 0, read);
                        }
                        cos.flush();
                    }
                } catch (Exception e) {
                    System.out.println("Encryption error: " + e.getMessage());
                    return;
                }
                try { data.shutdownOutput(); } catch (IOException ignored) {}
            }
            while ((line = br.readLine()) != null) {
                if (line.equals("DONE")) { System.out.println("File sent (encrypted)."); break; }
                if (line.equals("FAIL")) { System.out.println("Transfer failed."); break; }
                if (line.startsWith("PING")) continue;
            }
        }
    }

    private SecretKeySpec deriveKey(String passkey, byte[] salt) {
        try {
            PBEKeySpec spec = new PBEKeySpec(passkey.toCharArray(), salt, PBKDF2_ITER, KEY_LEN);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] keyBytes = skf.generateSecret(spec).getEncoded();
            return new SecretKeySpec(keyBytes, "AES");
        } catch (Exception e) {
            throw new RuntimeException("Key derivation failed", e);
        }
    }
}

