package com.inframonitor.agent;

import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.*;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

/**
 * InfraMonitor Remote Agent
 *
 * Deploy on any machine/server that has access to the networks you want to monitor.
 * The agent connects back to the InfraMonitor backend and executes monitoring checks
 * on behalf of the backend — no inbound ports required on the agent host.
 *
 * Usage:
 *   java -jar inframonitor-agent.jar --server=ws://your-backend:9875/ws/agents \
 *                                    --name=office-network-agent \
 *                                    --key=ima_xxxxxxxxxxxx
 *
 * Optional:
 *   --heartbeat=30          (seconds between heartbeats, default 30)
 *   --reconnect-delay=5     (seconds between reconnect attempts, default 5)
 */
public class InfraMonitorAgent {

    private static final String VERSION = "1.0.0";
    private static final int DEFAULT_TIMEOUT_MS = 5000;
    private static final int MIN_TIMEOUT_MS = 2000;
    private static final int MAX_TIMEOUT_MS = 10000;

    /**
     * C: Adaptive timeout — tracks the exponential moving average (EMA) of latency
     * per target. The effective timeout = max(MIN_TIMEOUT, avg * 3), capped at MAX_TIMEOUT.
     * Services that respond fast (e.g. 30ms) get a tight 2s timeout so DOWN is detected
     * in 2s instead of 5s. Services that are legitimately slow (e.g. 2s) get 6–10s.
     */
    private static final java.util.concurrent.ConcurrentHashMap<String, Long> avgLatencyByTarget
            = new java.util.concurrent.ConcurrentHashMap<>();

    private static int adaptiveTimeout(String target, int requestedTimeoutMs) {
        Long avg = avgLatencyByTarget.get(target);
        if (avg == null || avg <= 0) return requestedTimeoutMs; // no history yet
        int adaptive = (int) Math.max(MIN_TIMEOUT_MS, Math.min(MAX_TIMEOUT_MS, avg * 3));
        // Use the smaller of adaptive vs requested (backend may cap it already)
        return Math.min(adaptive, requestedTimeoutMs);
    }

    private static void recordLatency(String target, long latencyMs) {
        if (latencyMs <= 0) return;
        avgLatencyByTarget.compute(target, (k, prev) ->
                prev == null ? latencyMs : (prev * 7 + latencyMs) / 8  // EMA alpha=0.125
        );
    }

    private static SSLSocketFactory trustAllSocketFactory;
    private static HostnameVerifier trustAllHostnameVerifier;
    private static final ExecutorService checkExecutor = Executors.newVirtualThreadPerTaskExecutor();

    static {
        try {
            TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                }
            };
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new SecureRandom());
            trustAllSocketFactory = sc.getSocketFactory();
            trustAllHostnameVerifier = (hostname, session) -> true;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public static void main(String[] args) throws Exception {
        // ── Parse args ────────────────────────────────────────────────────────
        String serverUrl    = null;
        String agentName    = null;
        String apiKey       = null;
        int heartbeatSec    = 30;
        int reconnectDelaySec = 5;

        for (String arg : args) {
            if (arg.startsWith("--server="))          serverUrl = arg.substring(9);
            else if (arg.startsWith("--name="))       agentName = arg.substring(7);
            else if (arg.startsWith("--key="))        apiKey = arg.substring(6);
            else if (arg.startsWith("--heartbeat="))  heartbeatSec = Integer.parseInt(arg.substring(12));
            else if (arg.startsWith("--reconnect-delay=")) reconnectDelaySec = Integer.parseInt(arg.substring(18));
        }

        if (serverUrl == null || agentName == null || apiKey == null) {
            System.err.println("Usage: java -jar inframonitor-agent.jar " +
                    "--server=ws://host:9875/ws/agents --name=AGENT_NAME --key=API_KEY");
            System.exit(1);
        }

        String wsUrl = serverUrl + "?name=" + agentName + "&key=" + apiKey;
        log("InfraMonitor Agent v" + VERSION + " starting...");
        log("Agent name : " + agentName);
        log("Backend    : " + serverUrl);

        int finalReconnectDelaySec = reconnectDelaySec;
        int finalHeartbeatSec = heartbeatSec;

        // ── Main reconnect loop ───────────────────────────────────────────────
        while (!Thread.currentThread().isInterrupted()) {
            try {
                runSession(wsUrl, agentName, finalHeartbeatSec);
            } catch (Exception e) {
                log("Session ended: " + e.getMessage());
            }
            log("Reconnecting in " + finalReconnectDelaySec + "s...");
            Thread.sleep(finalReconnectDelaySec * 1000L);
        }
    }

    private static void runSession(String wsUrl, String agentName, int heartbeatSec) throws Exception {
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<WebSocket> wsRef = new AtomicReference<>();
        StringBuilder messageBuffer = new StringBuilder();

        ScheduledExecutorService heartbeatScheduler = Executors.newSingleThreadScheduledExecutor();

        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();

        WebSocket ws = client.newWebSocketBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .buildAsync(URI.create(wsUrl), new WebSocket.Listener() {

                    @Override
                    public void onOpen(WebSocket webSocket) {
                        log("Connected to backend");
                        wsRef.set(webSocket);
                        webSocket.request(1);

                        // Start heartbeat scheduler
                        heartbeatScheduler.scheduleAtFixedRate(() -> {
                            try {
                                WebSocket w = wsRef.get();
                                if (w != null) {
                                    synchronized (w) {
                                        w.sendText("{\"type\":\"HEARTBEAT\"}", true);
                                    }
                                }
                            } catch (Exception e) {
                                latch.countDown();
                            }
                        }, heartbeatSec, heartbeatSec, TimeUnit.SECONDS);
                    }

                    @Override
                    public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
                        messageBuffer.append(data);
                        webSocket.request(1);
                        if (last) {
                            String msg = messageBuffer.toString();
                            messageBuffer.setLength(0);
                            checkExecutor.submit(() -> handleMessage(webSocket, msg, agentName));
                        }
                        return null;
                    }

                    @Override
                    public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
                        log("Connection closed: " + statusCode + " " + reason);
                        heartbeatScheduler.shutdownNow();
                        latch.countDown();
                        return null;
                    }

                    @Override
                    public void onError(WebSocket webSocket, Throwable error) {
                        log("WS error: " + error.getMessage());
                        heartbeatScheduler.shutdownNow();
                        latch.countDown();
                    }
                }).join();

        latch.await();
        if (ws.isInputClosed()) ws.abort();
        heartbeatScheduler.shutdownNow();
    }

    // ── Message handling ──────────────────────────────────────────────────────

    private static void handleMessage(WebSocket ws, String json, String agentName) {
        String type = extractString(json, "type");
        if (type == null) return;

        switch (type) {
            case "WELCOME" -> log("Registered with backend (agentId=" + extractString(json, "agentId") + ")");
            case "PONG"    -> {} // ignore
            case "CHECK"   -> handleCheck(ws, json);
            default        -> log("Unknown message type: " + type);
        }
    }

    private static void handleCheck(WebSocket ws, String json) {
        String checkId     = extractString(json, "id");
        String monitorType = extractString(json, "monitorType");
        String target      = extractString(json, "target");
        String portStr     = extractString(json, "port");
        String url         = extractString(json, "url");
        String toStr       = extractString(json, "timeoutMs");

        Integer port    = (portStr != null && !portStr.equals("null")) ? Integer.parseInt(portStr) : null;
        int requestedTimeout = (toStr != null && !toStr.equals("null")) ? Integer.parseInt(toStr) : DEFAULT_TIMEOUT_MS;
        // C: Use adaptive timeout based on historical latency for this target
        int timeoutMs = adaptiveTimeout(target != null ? target : "", requestedTimeout);

        log("Executing " + monitorType + " check → " + target + (port != null ? ":" + port : "")
                + (timeoutMs != requestedTimeout ? " (adaptive timeout: " + timeoutMs + "ms)" : ""));

        CheckResult result;
        try {
            result = executeCheck(monitorType, target, port, url, timeoutMs);
            // C: Record latency for adaptive timeout learning (only for successful checks)
            if ("UP".equals(result.status) && result.latencyMs > 0) {
                recordLatency(target != null ? target : "", result.latencyMs);
            }
        } catch (Exception e) {
            result = new CheckResult("DOWN", 0, "Check error: " + e.getMessage());
        }

        String response = String.format(
                "{\"type\":\"RESULT\",\"id\":\"%s\",\"status\":\"%s\",\"latencyMs\":%d,\"message\":\"%s\"}",
                checkId,
                result.status,
                result.latencyMs,
                result.message.replace("\"", "'").replace("\n", " ")
        );

        synchronized (ws) {
            ws.sendText(response, true);
        }
        log("Result: " + result.status + " (" + result.latencyMs + "ms) " + result.message);
    }

    // ── Local check execution ─────────────────────────────────────────────────

    private static CheckResult executeCheck(String monitorType, String target, Integer port,
                                            String url, int timeoutMs) {
        long start = System.currentTimeMillis();
        try {
            return switch (monitorType != null ? monitorType.toUpperCase() : "") {
                case "PING" -> {
                    boolean ok = pingHost(target, timeoutMs);
                    long latency = System.currentTimeMillis() - start;
                    yield new CheckResult(ok ? "UP" : "DOWN", latency,
                            ok ? "PING OK (" + latency + "ms)" : "Host unreachable");
                }
                case "TCP" -> {
                    int p = port != null ? port : 80;
                    try (Socket s = new Socket()) {
                        s.connect(new InetSocketAddress(target, p), timeoutMs);
                        long latency = System.currentTimeMillis() - start;
                        yield new CheckResult("UP", latency, "TCP " + p + " open (" + latency + "ms)");
                    }
                }
                case "HTTP" -> {
                    String rawUrl = (url != null && !url.equals("null") && !url.isBlank())
                            ? url
                            : "http://" + target + (port != null ? ":" + port : "");
                    if (!rawUrl.startsWith("http")) rawUrl = "http://" + rawUrl;
                    yield executeHttpAgentCheck(rawUrl, timeoutMs);
                }
                case "DNS" -> {
                    InetAddress addr = InetAddress.getByName(target);
                    long latency = System.currentTimeMillis() - start;
                    yield new CheckResult("UP", latency, "DNS resolved to " + addr.getHostAddress());
                }
                case "IMAP" -> {
                    int p = port != null ? port : 143;
                    yield checkImapAgent(target, p, timeoutMs);
                }
                case "LDAP" -> {
                    int p = port != null ? port : 389;
                    yield checkLdapAgent(target, p, timeoutMs);
                }
                case "SIP" -> {
                    int p = port != null ? port : 5060;
                    yield checkSipAgent(target, p, timeoutMs);
                }
                default -> new CheckResult("UNKNOWN", 0, "Unsupported monitor type: " + monitorType);
            };
        } catch (java.net.SocketTimeoutException e) {
            long latency = System.currentTimeMillis() - start;
            return new CheckResult("DOWN", latency, "Timeout after " + latency + "ms");
        } catch (Exception e) {
            long latency = System.currentTimeMillis() - start;
            return new CheckResult("DOWN", latency, e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private static boolean pingHost(String target, int timeoutMs) {
        // We bypass InetAddress.isReachable because it defaults to TCP port 7 when
        // privileges are missing, which drops packets and blocks for the full timeout
        // (e.g. 15 seconds) before failing. System ping is much faster and reliable.
        try {
            boolean isWindows = System.getProperty("os.name").toLowerCase().contains("win");
            ProcessBuilder pb;
            if (isWindows) {
                // Windows: -n is count, default no reverse DNS
                pb = new ProcessBuilder("ping", "-n", "1", "-w", String.valueOf(timeoutMs), target);
            } else {
                // Linux/Mac: -c is count, -W is timeout. IMPORTANT: -n disables reverse DNS lookup,
                // without -n, ping might block for 5-10s doing a PTR lookup even if the host replies in 5ms.
                int timeoutSec = Math.max(1, timeoutMs / 1000);
                pb = new ProcessBuilder("ping", "-n", "-c", "1", "-W", String.valueOf(timeoutSec), target);
            }
            Process process = pb.start();
            boolean finished = process.waitFor(timeoutMs + 1000, TimeUnit.MILLISECONDS);
            return finished && process.exitValue() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    private static CheckResult executeHttpAgentCheck(String rawUrl, int timeoutMs) {
        long start = System.currentTimeMillis();
        try {
            int code = tryHttpAgentConnect(rawUrl, "HEAD", false, timeoutMs);
            long latency = System.currentTimeMillis() - start;
            boolean ok = code >= 200 && code < 400;
            return new CheckResult(ok ? "UP" : "DOWN", latency, "HTTP " + code + " (" + latency + "ms)");
        } catch (javax.net.ssl.SSLException | java.security.cert.CertificateException e) {
            // SSL verification failed, try with trust-all
            try {
                int code = tryHttpAgentConnect(rawUrl, "HEAD", true, timeoutMs);
                long latency = System.currentTimeMillis() - start;
                boolean ok = code >= 200 && code < 400;
                return new CheckResult(ok ? "WARNING" : "DOWN", latency, 
                        ok ? "Insecure SSL: " + e.getMessage() : "HTTP " + code + " (" + latency + "ms)");
            } catch (Exception ex) {
                // If HEAD fails, try GET with trust-all
                try {
                    int code = tryHttpAgentConnect(rawUrl, "GET", true, timeoutMs);
                    long latency = System.currentTimeMillis() - start;
                    boolean ok = code >= 200 && code < 400;
                    return new CheckResult(ok ? "WARNING" : "DOWN", latency, 
                            ok ? "Insecure SSL: " + e.getMessage() : "HTTP " + code + " (" + latency + "ms)");
                } catch (Exception ignored) {
                    long latency = System.currentTimeMillis() - start;
                    return new CheckResult("DOWN", latency, "SSL error: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            // General exception (maybe 405 Method Not Allowed), retry with GET
            try {
                int code = tryHttpAgentConnect(rawUrl, "GET", false, timeoutMs);
                long latency = System.currentTimeMillis() - start;
                boolean ok = code >= 200 && code < 400;
                return new CheckResult(ok ? "UP" : "DOWN", latency, "HTTP " + code + " (" + latency + "ms)");
            } catch (javax.net.ssl.SSLException | java.security.cert.CertificateException se) {
                // GET failed due to SSL, try with trust-all
                try {
                    int code = tryHttpAgentConnect(rawUrl, "GET", true, timeoutMs);
                    long latency = System.currentTimeMillis() - start;
                    boolean ok = code >= 200 && code < 400;
                    return new CheckResult(ok ? "WARNING" : "DOWN", latency, 
                            ok ? "Insecure SSL: " + se.getMessage() : "HTTP " + code + " (" + latency + "ms)");
                } catch (Exception ignored) {
                    long latency = System.currentTimeMillis() - start;
                    return new CheckResult("DOWN", latency, "SSL error: " + se.getMessage());
                }
            } catch (Exception ex) {
                long latency = System.currentTimeMillis() - start;
                return new CheckResult("DOWN", latency, e.getClass().getSimpleName() + ": " + e.getMessage());
            }
        }
    }

    private static int tryHttpAgentConnect(String rawUrl, String method, boolean trustAll, int timeoutMs) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(rawUrl).openConnection();
        if (trustAll && conn instanceof javax.net.ssl.HttpsURLConnection httpsConn) {
            httpsConn.setSSLSocketFactory(trustAllSocketFactory);
            httpsConn.setHostnameVerifier(trustAllHostnameVerifier);
        }
        conn.setConnectTimeout(timeoutMs);
        conn.setReadTimeout(timeoutMs);
        conn.setRequestMethod(method);
        conn.setInstanceFollowRedirects(true);
        try {
            return conn.getResponseCode();
        } finally {
            try {
                if (conn.getInputStream() != null) conn.getInputStream().close();
            } catch (Exception ignored) {}
            conn.disconnect();
        }
    }

    // ── IMAP check (agent) ────────────────────────────────────────────────────
    private static CheckResult checkImapAgent(String host, int port, int timeoutMs) {
        long start = System.currentTimeMillis();
        boolean useSSL = (port == 993);
        try {
            java.net.Socket socket;
            if (useSSL) {
                javax.net.ssl.SSLSocket sslSocket = (javax.net.ssl.SSLSocket) trustAllSocketFactory.createSocket();
                sslSocket.connect(new InetSocketAddress(host, port), timeoutMs);
                sslSocket.setSoTimeout(timeoutMs);
                sslSocket.startHandshake();
                socket = sslSocket;
            } else {
                socket = new java.net.Socket();
                socket.connect(new InetSocketAddress(host, port), timeoutMs);
                socket.setSoTimeout(timeoutMs);
            }
            try (socket) {
                java.io.BufferedReader reader = new java.io.BufferedReader(
                        new java.io.InputStreamReader(socket.getInputStream()));
                String banner = reader.readLine();
                long latency = System.currentTimeMillis() - start;
                if (banner != null && banner.startsWith("* OK")) {
                    return new CheckResult("UP", latency,
                            "IMAP OK" + (useSSL ? " (SSL)" : "") + " | " + banner.substring(0, Math.min(banner.length(), 60)));
                }
                return new CheckResult("DOWN", latency, "Unexpected IMAP banner: " + banner);
            }
        } catch (java.net.SocketTimeoutException e) {
            return new CheckResult("DOWN", timeoutMs, "IMAP timeout on port " + port);
        } catch (Exception e) {
            long latency = System.currentTimeMillis() - start;
            return new CheckResult("DOWN", latency, "IMAP error: " + e.getMessage());
        }
    }

    // ── LDAP check (agent) ────────────────────────────────────────────────────
    // Sends a minimal LDAPv3 bind request (anonymous) and checks for a valid response.
    // Uses raw sockets to avoid JNDI dependency in the agent JAR.
    private static CheckResult checkLdapAgent(String host, int port, int timeoutMs) {
        long start = System.currentTimeMillis();
        // LDAPv3 anonymous BIND request (pre-built bytes):
        // messageId=1, BIND_REQUEST, version=3, dn="", simple auth, password=""
        byte[] bindRequest = {
            0x30, 0x0c,             // SEQUENCE (12 bytes)
            0x02, 0x01, 0x01,       // INTEGER messageId=1
            0x60, 0x07,             // BIND_REQUEST (7 bytes)
            0x02, 0x01, 0x03,       // INTEGER version=3
            0x04, 0x00,             // OCTET STRING dn="" (empty)
            (byte) 0x80, 0x00       // [0] simple password="" (empty)
        };
        try (java.net.Socket socket = new java.net.Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            socket.setSoTimeout(timeoutMs);
            socket.getOutputStream().write(bindRequest);
            socket.getOutputStream().flush();

            // Read response: expect at least 7 bytes (SEQUENCE + messageId + BIND_RESPONSE)
            byte[] buf = new byte[64];
            int read = socket.getInputStream().read(buf);
            long latency = System.currentTimeMillis() - start;

            if (read >= 7 && buf[0] == 0x30) {
                // Check result code byte (offset varies, but 0x00 = success)
                // Simplified: any valid LDAP response envelope means the server is alive
                return new CheckResult("UP", latency, "LDAP OK (anonymous bind accepted or restricted) | port " + port);
            }
            return new CheckResult("DOWN", latency, "Invalid LDAP response");
        } catch (java.net.SocketTimeoutException e) {
            return new CheckResult("DOWN", timeoutMs, "LDAP timeout on port " + port);
        } catch (Exception e) {
            long latency = System.currentTimeMillis() - start;
            return new CheckResult("DOWN", latency, "LDAP error: " + e.getMessage());
        }
    }

    // ── SIP check (agent) ─────────────────────────────────────────────────────
    private static CheckResult checkSipAgent(String host, int port, int timeoutMs) {
        long start = System.currentTimeMillis();
        String callId = java.util.UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        String request =
                "OPTIONS sip:" + host + " SIP/2.0\r\n" +
                "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK" + callId + "\r\n" +
                "Max-Forwards: 70\r\n" +
                "From: <sip:agent@inframonitor.local>;tag=" + callId + "\r\n" +
                "To: <sip:" + host + ">\r\n" +
                "Call-ID: " + callId + "@inframonitor.local\r\n" +
                "CSeq: 1 OPTIONS\r\n" +
                "Contact: <sip:agent@127.0.0.1>\r\n" +
                "Content-Length: 0\r\n\r\n";
        try (java.net.DatagramSocket socket = new java.net.DatagramSocket()) {
            socket.setSoTimeout(timeoutMs);
            java.net.InetAddress addr = java.net.InetAddress.getByName(host);
            byte[] data = request.getBytes();
            socket.send(new java.net.DatagramPacket(data, data.length, addr, port));

            byte[] buf = new byte[2048];
            java.net.DatagramPacket response = new java.net.DatagramPacket(buf, buf.length);
            socket.receive(response);
            long latency = System.currentTimeMillis() - start;
            String resp = new String(buf, 0, response.getLength());
            if (resp.startsWith("SIP/2.0")) {
                String[] parts = resp.split(" ", 3);
                int code = parts.length >= 2 ? Integer.parseInt(parts[1].trim()) : 0;
                String reason = parts.length >= 3 ? parts[2].split("\r\n")[0].trim() : "";
                String status = (code >= 200 && code < 400) ? "UP" : "WARNING";
                return new CheckResult(status, latency, "SIP " + code + " " + reason);
            }
            return new CheckResult("DOWN", latency, "Invalid SIP response");
        } catch (java.net.SocketTimeoutException e) {
            return new CheckResult("DOWN", timeoutMs, "SIP timeout — no response on UDP/" + port);
        } catch (Exception e) {
            long latency = System.currentTimeMillis() - start;
            return new CheckResult("DOWN", latency, "SIP error: " + e.getMessage());
        }
    }


    // ── Minimal JSON extractor (no external libs) ─────────────────────────────

    private static String extractString(String json, String key) {
        String search = "\"" + key + "\"";
        int idx = json.indexOf(search);
        if (idx < 0) return null;
        int colon = json.indexOf(':', idx + search.length());
        if (colon < 0) return null;
        int valStart = colon + 1;
        while (valStart < json.length() && json.charAt(valStart) == ' ') valStart++;
        if (valStart >= json.length()) return null;
        char first = json.charAt(valStart);
        if (first == '"') {
            int end = json.indexOf('"', valStart + 1);
            return end < 0 ? null : json.substring(valStart + 1, end);
        }
        // number or null/true/false
        int end = valStart;
        while (end < json.length() && ",} \n\r\t".indexOf(json.charAt(end)) < 0) end++;
        String val = json.substring(valStart, end).trim();
        return val.equals("null") ? null : val;
    }

    private static void log(String msg) {
        System.out.println("[InfraMonitor-Agent] " + msg);
    }

    record CheckResult(String status, long latencyMs, String message) {}
}
