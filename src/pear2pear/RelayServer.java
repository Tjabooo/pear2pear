package pear2pear;

import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.text.SimpleDateFormat;

public class RelayServer {

    public static final int CONTROL_PORT = 9009;
    public static final int DATA_PORT = 9010;

    private static class Pair {
        volatile Socket controlSender;
        volatile Socket controlReceiver;
        volatile Socket dataSender;
        volatile Socket dataReceiver;
        volatile String fileName;
        volatile long size = -1;
        volatile String salt;
        volatile String iv;
        volatile InputStream senderStream;
        final Instant created = Instant.now();
    }

    private final Map<String, Pair> pairs = new ConcurrentHashMap<>();
    private final ScheduledExecutorService cleaner = Executors.newSingleThreadScheduledExecutor();

    private final Map<String, ConcurrentLinkedQueue<Long>> ipConnectTimes = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> ipActive = new ConcurrentHashMap<>();
    private static final int MAX_CONN_PER_MIN = 5;
    private static final int MAX_CONCURRENT = 3;
    private static final long MAX_FILE_SIZE = 100 * 1024 * 1024L; // 100mb
    private static final int IDLE_TIMEOUT_MS = 2 * 60 * 1000; // 2min
    private static final int PAIR_CLEANUP_SEC = 300; // 5min
    private final File logFile = new File("relay-transfers.log");
    private final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    private final ExecutorService pool =
        new ThreadPoolExecutor(
                32, 
                100,
                60L, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(500),
                new ThreadPoolExecutor.AbortPolicy()
            );

    public void start() {
        System.out.println("Relay started on control:" + CONTROL_PORT + " data:" + DATA_PORT + ". Press Ctrl+C to stop.");
        cleaner.scheduleAtFixedRate(this::cleanup, 2, 2, TimeUnit.MINUTES);
        Thread control = new Thread(this::runControl, "relay-control");
        Thread data = new Thread(this::runData, "relay-data");
        control.setDaemon(true);
        data.setDaemon(true);
        control.start();
        data.start();
        try { control.join(); } catch (InterruptedException ignored) {}
    }

    private void runControl() {

        try (ServerSocket ss = new ServerSocket(CONTROL_PORT, 50, InetAddress.getByName("0.0.0.0"))) {
            while (true) {
                Socket s = ss.accept();
                String ip = s.getInetAddress().getHostAddress();
                if (!allowConnection(ip)) {
                    s.close();
                    continue;
                }
                try {
                    pool.execute(() -> {
                        try {
                            handleControl(s);
                        } finally {
                            decActive(ip);
                            closeQuiet(s);
                        }
                    });
                } catch (RejectedExecutionException e) {
                    decActive(ip);
                    closeQuiet(s);
                }
            }
        } catch (IOException e) {
            System.err.println("Control server stopped: " + e.getMessage());
        }

    }

    private void runData() {

        try (ServerSocket ss = new ServerSocket(DATA_PORT, 50, InetAddress.getByName("0.0.0.0"))) {
            while (true) {
                Socket s = ss.accept();
                String ip = s.getInetAddress().getHostAddress();
                if (!allowConnection(ip)) { s.close(); continue; }
                try {
                    pool.execute(() -> {
                        try {
                            handleData(s);
                        } finally {
                            decActive(ip);
                            closeQuiet(s);
                        }
                    });
                } catch (RejectedExecutionException e) {
                    decActive(ip);
                    closeQuiet(s);
                }
            }
        } catch (IOException e) {
            System.err.println("Data server stopped: " + e.getMessage());
        }

    }

    private boolean allowConnection(String ip) {

        long now = System.currentTimeMillis();
        ipConnectTimes.putIfAbsent(ip, new ConcurrentLinkedQueue<>());
        ipActive.putIfAbsent(ip, new AtomicInteger(0));
        ConcurrentLinkedQueue<Long> times = ipConnectTimes.get(ip);
        AtomicInteger active = ipActive.get(ip);
        times.add(now);
        while (!times.isEmpty() && now - times.peek() > 60_000) times.poll();
        if (times.size() > MAX_CONN_PER_MIN) {
            System.out.println("[relay] REJECT: " + ip + " rate limit");
            return false;
        }
        if (active.incrementAndGet() > MAX_CONCURRENT) {
            System.out.println("[relay] REJECT: " + ip + " concurrent limit");
            active.decrementAndGet();
            return false;
        }
        return true;

    }

    private void decActive(String ip) { AtomicInteger a = ipActive.get(ip); if (a != null) a.decrementAndGet(); }

    private void handleControl(Socket s) {

        try {
            s.setSoTimeout(IDLE_TIMEOUT_MS);
            System.out.println("[relay] control connect from " + s.getRemoteSocketAddress());

            BufferedReader br = new BufferedReader(new InputStreamReader(s.getInputStream()));
            PrintWriter pw = new PrintWriter(new OutputStreamWriter(s.getOutputStream()), true);

            String roleLine = br.readLine();
            String keyLine = br.readLine();
            if (roleLine == null || keyLine == null) { closeQuiet(s); return; }
            if (!roleLine.startsWith("ROLE ") || !keyLine.startsWith("KEY ")) { pw.println("ERR protocol"); closeQuiet(s); return; }
            String role = roleLine.substring(5).trim().toUpperCase();
            String key = keyLine.substring(4).trim();
            if (!PasskeyUtil.isValidCustom(key)) { pw.println("ERR badkey"); closeQuiet(s); return; }

            Pair pair;
            if ("SENDER".equals(role)) {
                pair = pairs.computeIfAbsent(key, k -> new Pair());
            } else {
                pair = pairs.get(key);
                if (pair == null) { pw.println("ERR nopair"); closeQuiet(s); return; }
            }
            boolean ready;
            synchronized (pair) {
                if ("SENDER".equals(role)) { if (pair.controlSender != null) { pw.println("ERR duplicate"); return; } pair.controlSender = s; }
                else if ("RECEIVER".equals(role)) { if (pair.controlReceiver != null) { pw.println("ERR duplicate"); return; } pair.controlReceiver = s; }
                else { pw.println("ERR role"); return; }
                ready = pair.controlSender != null && pair.controlReceiver != null;
            }

            if (ready) notifyReady(pair); else pw.println("WAITING");

            while (!s.isClosed()) {
                try { Thread.sleep(30000); } catch (InterruptedException ignored) {}
                if (s.isClosed()) break;
                pw.println("PING");
            }
        } catch (IOException ignored) {}

    }

    private void notifyReady(Pair pair) {
        try { new PrintWriter(pair.controlSender.getOutputStream(), true).println("READY"); } catch (Exception ignored) {}
        try { new PrintWriter(pair.controlReceiver.getOutputStream(), true).println("READY"); } catch (Exception ignored) {}
    }

    private void handleData(Socket s) {

        String ip = s.getInetAddress().getHostAddress();
        try {
            System.out.println("[relay] data connect from " + s.getRemoteSocketAddress());
            s.setSoTimeout(IDLE_TIMEOUT_MS);
            InputStream in = s.getInputStream();
            String keyLine = readLine(in);
            if (keyLine == null || !keyLine.startsWith("KEY ")) { System.out.println("[relay] REJECT: " + ip + " key"); closeQuiet(s); return; }
            String key = keyLine.substring(4).trim();
            if (!PasskeyUtil.isValidCustom(key)) { System.out.println("[relay] REJECT: " + ip + " passkey"); closeQuiet(s); return; }
            Pair pair = pairs.get(key);
            if (pair == null) { System.out.println("[relay] REJECT: " + ip + " no pair"); closeQuiet(s); return; }
            boolean isSender;
            synchronized (pair) {
                if (pair.dataSender == null && pair.senderStream == null) { isSender = true; pair.dataSender = s; }
                else if (pair.dataReceiver == null) { isSender = false; pair.dataReceiver = s; }
                else { System.out.println("[relay] REJECT: " + ip + " extra data"); closeQuiet(s); return; }
            }
            if (isSender) {
                String meta = readLine(in);
                if (meta == null || !meta.startsWith("META ")) { System.out.println("[relay] REJECT: " + ip + " meta"); closeQuiet(s); return; }
                String[] parts = meta.substring(5).trim().split("\\|");
                if (parts.length != 4) { System.out.println("[relay] REJECT: " + ip + " meta fmt"); closeQuiet(s); return; }
                String fileName = parts[0];
                long size;
                try { size = Long.parseLong(parts[1]); } catch (NumberFormatException e) { System.out.println("[relay] REJECT: " + ip + " size"); closeQuiet(s); return; }
                if (size > MAX_FILE_SIZE) { System.out.println("[relay] REJECT: " + ip + " big"); closeQuiet(s); return; }
                synchronized (pair) {
                    pair.fileName = fileName; pair.size = size; pair.salt = parts[2]; pair.iv = parts[3]; pair.senderStream = in;
                    if (pair.dataReceiver != null) { logTransfer(fileName, size, s.getInetAddress().getHostAddress(), pair.dataReceiver.getInetAddress().getHostAddress()); sendMetaAndPipe(key, pair); }
                }
            } else {
                synchronized (pair) {
                    if (pair.fileName != null && pair.dataSender != null) { logTransfer(pair.fileName, pair.size, pair.dataSender.getInetAddress().getHostAddress(), s.getInetAddress().getHostAddress()); sendMetaAndPipe(key, pair); }
                }
                while (!s.isClosed()) { try { Thread.sleep(1000); } catch (InterruptedException ignored) {} if (pair.size == -1 && pair.dataSender == null) break; }
            }
        } catch (IOException e) { System.out.println("[relay] ERROR: " + ip + " " + e); }

    }

    private void sendMetaAndPipe(String key, Pair pair) {

        new Thread(() -> {
            boolean ok = false;
            try {
                PrintWriter rPw = new PrintWriter(pair.dataReceiver.getOutputStream(), true);
                rPw.println("META " + pair.fileName + '|' + pair.size + '|' + pair.salt + '|' + pair.iv);
                rPw.flush();
                byte[] buf = new byte[8192];
                int read;
                while ((read = pair.senderStream.read(buf)) != -1) {
                    pair.dataReceiver.getOutputStream().write(buf, 0, read);
                }
                pair.dataReceiver.getOutputStream().flush();
                ok = true;
            } catch (IOException ignored) {
            } finally {
                PrintWriter cs = null, cr = null;
                try { if (pair.controlSender != null) cs = new PrintWriter(pair.controlSender.getOutputStream(), true); } catch (Exception ignored) {}
                try { if (pair.controlReceiver != null) cr = new PrintWriter(pair.controlReceiver.getOutputStream(), true); } catch (Exception ignored) {}
                if (cs != null) cs.println(ok ? "DONE" : "FAIL");
                if (cr != null) cr.println(ok ? "DONE" : "FAIL");
                closeQuiet(pair.dataSender); closeQuiet(pair.dataReceiver); pairs.remove(key);
            }
        }, "pipe-" + pair.fileName).start();

    }

    private String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int b; int count = 0;
        while ((b = in.read()) != -1) { if (b == '\n') break; if (b != '\r') baos.write(b); if (++count > 8192) throw new IOException("Line too long"); }
        if (b == -1 && baos.size() == 0) return null; return baos.toString().trim();
    }

    private void logTransfer(String fileName, long size, String senderIp, String receiverIp) {
        String log = String.format("%s | file=%s | size=%d | sender=%s | receiver=%s", sdf.format(System.currentTimeMillis()), fileName, size, senderIp, receiverIp);
        System.out.println("[relay-log] " + log);
        try (FileWriter fw = new FileWriter(logFile, true)) { fw.write(log + "\n"); } catch (IOException ignored) {}
    }

    private void cleanup() { Instant now = Instant.now(); pairs.entrySet().removeIf(e -> now.isAfter(e.getValue().created.plusSeconds(PAIR_CLEANUP_SEC))); }

    private void closeQuiet(Socket s) { if (s!=null) try { s.close(); } catch (IOException ignored) {} }
}
