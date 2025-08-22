package pear2pear;

import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

class Receiver {

    private static final String host = "57.128.212.68";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;
    private static final int PBKDF2_ITER = 100_000;
    private static final int KEY_LEN = 256;
    private static final int SALT_LEN = 16;

    void start() throws IOException {

        Scanner sc = new Scanner(System.in);
        System.out.print("Enter passkey: ");
        String passkey = sc.nextLine().trim();

        if (!PasskeyUtil.isValidCustom(passkey)) {
            System.out.println("Invalid passkey format. Use alphanumeric, dash or underscore (8-64 chars). Minimum 8 chars.");
            return;
        }

        System.out.println("Connecting to relay...");

        try (Socket control = new Socket(host, RelayServer.CONTROL_PORT)) {
            PrintWriter pw = new PrintWriter(new OutputStreamWriter(control.getOutputStream()), true);
            BufferedReader br = new BufferedReader(new InputStreamReader(control.getInputStream()));

            pw.println("ROLE RECEIVER");
            pw.println("KEY " + passkey);
            boolean ready = false;
            String line;

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
                    System.out.println("Waiting for sender to connect...");
                }
            }

            if (!ready) {
                System.out.println("Disconnected before ready.");
                return;
            }

            System.out.print("Path to folder to save file (ENTER for current directory): ");
            String folder = sc.nextLine().trim();
            Path dir = folder.isEmpty() ? Path.of(".") : Path.of(folder);

            if (!Files.exists(dir)) {
                try {
                    Files.createDirectories(dir);
                } catch (IOException e) {
                    System.out.println("Could not create directory.");
                    return;
                }
            }

            if (!Files.isDirectory(dir)) {
                System.out.println("Not a directory.");
                return;
            }

            try (Socket data = new Socket(host, RelayServer.DATA_PORT)) {
                InputStream in = data.getInputStream();
                OutputStream out = data.getOutputStream();
                PrintWriter dpw = new PrintWriter(new OutputStreamWriter(out), true);

                dpw.println("KEY " + passkey);
                String meta = readLine(in);

                if (meta == null || !meta.startsWith("META ")) {
                    System.out.println("Failed to get file metadata.");
                    return;
                }

                String rest = meta.substring(5).trim();
                String[] parts = rest.split("\\|");
                if (parts.length != 4) {
                    System.out.println("Bad metadata format.");
                    return;
                }
                String fileName = parts[0];
                long size;
                try {
                    size = Long.parseLong(parts[1]);
                } catch (NumberFormatException e) {
                    System.out.println("Bad file size.");
                    return;
                }
                if (size > 100 * 1024 * 1024) {
                    System.out.println("File too large. Max allowed is 100MB.");
                    return;
                }
                byte[] salt, iv;
                try {
                    salt = Base64.getDecoder().decode(parts[2]);
                    iv = Base64.getDecoder().decode(parts[3]);
                } catch (Exception e) {
                    System.out.println("Failed to decode parameters.");
                    return;
                }
                if (salt.length != SALT_LEN || iv.length != GCM_IV_LENGTH) {
                    System.out.println("Invalid salt or IV length.");
                    return;
                }
                SecretKeySpec key = deriveKey(passkey, salt);
                Path outFile = dir.resolve(fileName);
                System.out.println("Receiving file: " + fileName + " (" + size + " bytes, encrypted)");
                try (CipherInputStream cis = new CipherInputStream(in, getDecryptCipher(key, iv));
                     OutputStream fos = Files.newOutputStream(outFile)) {
                    byte[] buf = new byte[8192];
                    int read;
                    long recvd = 0;
                    while ((read = cis.read(buf)) != -1) {
                        fos.write(buf, 0, read);
                        recvd += read;
                    }
                    fos.flush();
                    System.out.println("File received and decrypted. Size: " + recvd + " bytes.");
                } catch (Exception e) {
                    System.out.println("Decryption failed.");
                }
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

    private Cipher getDecryptCipher(SecretKeySpec key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        return cipher;
    }

    private String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int b;
        int count = 0;
        while ((b = in.read()) != -1) {
            if (b == '\n') break;
            if (b != '\r') baos.write(b);
            if (++count > 8192) throw new IOException("Line too long");
        }
        if (count == 0 && b == -1) return null;
        return baos.toString("UTF-8").trim();
    }

}
