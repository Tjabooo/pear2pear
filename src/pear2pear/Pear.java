package pear2pear;

import java.io.*;
import java.net.*;
import java.util.Scanner;

public class Pear {

    private static final int PORT = 5000;

    // Start the server or client based on command line arguments
    public static void main(String[] args) throws IOException {

        if (args.length == 0) {
            System.out.println("Usage: java pear2pear/Pear.java [server|client <host>]");
            return;
        }

        if (args[0].equalsIgnoreCase("server")) {
            startServer();
        } else if (args[0].equalsIgnoreCase("client")) {
            if (args.length < 2) {
                System.out.println("Usage: java pear2pear/Pear.java client <host>");
                return;
            }
            startClient(args[1]);
        }

    }


    // Server listens for one client and sends a file
    private static void startServer() throws IOException {

        // Prompt for file path
        Scanner sc = new Scanner(System.in);
        System.out.print("Path to file: ");
        String path = sc.nextLine();
        File file = new File(path);

        // Check if file exists and is a file
        if (!file.exists() || !file.isFile()) {
            System.out.println("File does not exist.");
            return;
        }

        // Open server socket and wait for client connection
        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("Server listening on port " + PORT + " at " + InetAddress.getLocalHost().getHostAddress());

        Socket socket = serverSocket.accept(); // Self-explanatory

        // Notify client that server is ready
        DataInputStream dis = new DataInputStream(socket.getInputStream());
        String clientReady = dis.readUTF();
        if (!clientReady.equals("READY")) {
            System.out.println("Client not ready, aborting.");
            socket.close();
            serverSocket.close();
            return;
        }

        // Send file name and size
        DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
        dos.writeUTF(file.getName());
        dos.writeLong(file.length());

        // Send the file
        try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(file))) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = bis.read(buffer)) != -1) {
                dos.write(buffer, 0, bytesRead);
            }
            dos.flush();
            System.out.println("File sent.");
        }

        // Self-explanatory
        socket.close();
        serverSocket.close();

    }

    // Client connects and receives file
    private static void startClient(String host) throws IOException {

        // Prompt for folder path to save the file
        Scanner sc = new Scanner(System.in);
        System.out.print("Folder path to save file: ");
        String savePath = sc.nextLine();
        File saveDir = new File(savePath);

        // Check if the folder exists and is a directory
        if (!saveDir.exists() || !saveDir.isDirectory()) {
            System.out.println("Invalid folder path.");
            return;
        }

        // Connect to the server and notify user
        Socket socket = new Socket(host, PORT);
        System.out.println("Connected to server: " + host);

        // Notify server that client is ready
        DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
        dos.writeUTF("READY");

        // Receive file name and data
        DataInputStream dis = new DataInputStream(socket.getInputStream());
        String fileName = dis.readUTF();
        long fileSize = dis.readLong();
        File newFile = new File(saveDir, fileName);

        // Receive the file
        try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(newFile))) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            long totalRead = 0;
            while (totalRead < fileSize && (bytesRead = dis.read(buffer, 0, (int)Math.min(buffer.length, fileSize - totalRead))) != -1) {
                bos.write(buffer, 0, bytesRead);
                totalRead += bytesRead;
            }
            bos.flush();
            System.out.println("File received and saved as " + newFile.getAbsolutePath());
        }

        socket.close(); // Again, self-explanatory lol

    }

}