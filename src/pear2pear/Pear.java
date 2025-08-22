package pear2pear;

public class Pear {

    public static void main(String[] args) throws Exception {

        if (args.length == 0) {
            printUsage();
            return;
        }
        String mode = args[0].trim().toLowerCase();
        switch (mode) {
            case "relay":
                new RelayServer().start();
                break;
            case "server":
                new Sender().start();
                break;
            case "client":
                new Receiver().start();
                break;
            default:
                printUsage();
        }

    }

    private static void printUsage() {
        System.out.println("Usage: java pear2pear/Pear.java [server|client]");
    }

}