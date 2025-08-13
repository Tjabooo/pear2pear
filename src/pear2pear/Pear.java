package pear2pear;

import java.io.*;
import java.net.*;

public class Pear {

    private static final int PORT = 5000;
    private static final String FILE_TO_SEND = "text.txt";

    public static void main(String[] args) throws IOException {

        if (args.length == 0) {
            System.out.println("Usage: java Pear [server|client <host>]");
            return;
        }

        if (args[0].equalsIgnoreCase("server")) {
            startServer();
        } else if (args[0].equalsIgnoreCase("client")) {
            if (args.length < 2) {
                System.out.println("Usage: java Pear client <host>");
                return;
            }
            startClient(args[1]);
        }

    }


    // Server listens for one client and sends a file
    private static void startServer() throws IOException {

        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("Server listening on port " + PORT);

        Socket socket = serverSocket.accept();
        System.out.println("Client connected: " + socket.getInetAddress());

        try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(FILE_TO_SEND))) {
            OutputStream os = socket.getOutputStream();

            byte[] buffer = new byte[4096];
            int bytesRead;

            while ((bytesRead = bis.read(buffer)) != -1) {
                os.write(buffer, 0, bytesRead);
            }
            os.flush();
            System.out.println("File sent.");
        }

        socket.close();
        serverSocket.close();

    }

    // Client connects and receives file
    private static void startClient(String host) throws IOException {
        Socket socket = new Socket(host, PORT);
        System.out.println("Connected to server: " + host);

        try (InputStream is = socket.getInputStream()) {
            BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(FILE_TO_SEND));

            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = is.read(buffer)) != -1) {
                bos.write(buffer, 0, bytesRead);
            }
            bos.flush();
            System.out.println("File received and saved as " + FILE_TO_SEND);
        }

        socket.close();

    }

}