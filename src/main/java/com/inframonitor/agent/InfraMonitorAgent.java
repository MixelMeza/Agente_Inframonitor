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
    private static int DEFAULT_TIMEOUT_MS = 5000;

    private static SSLSocketFactory trustAllSocketFactory;
    private static HostnameVerifier trustAllHostnameVerifier;

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
                                    w.sendText("{\"type\":\"HEARTBEAT\"}", true);
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
                            handleMessage(webSocket, msg, agentName);
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
        int timeoutMs   = (toStr != null && !toStr.equals("null")) ? Integer.parseInt(toStr) : DEFAULT_TIMEOUT_MS;

        log("Executing " + monitorType + " check → " + target + (port != null ? ":" + port : ""));

        CheckResult result;
        try {
            result = executeCheck(monitorType, target, port, url, timeoutMs);
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

        ws.sendText(response, true);
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
        try {
            InetAddress addr = InetAddress.getByName(target);
            if (addr.isReachable(timeoutMs)) {
                return true;
            }
        } catch (Exception ignored) {}

        // Fallback to system ping command
        try {
            boolean isWindows = System.getProperty("os.name").toLowerCase().contains("win");
            ProcessBuilder pb;
            if (isWindows) {
                pb = new ProcessBuilder("ping", "-n", "1", "-w", String.valueOf(timeoutMs), target);
            } else {
                int timeoutSec = Math.max(1, timeoutMs / 1000);
                pb = new ProcessBuilder("ping", "-c", "1", "-W", String.valueOf(timeoutSec), target);
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
        return conn.getResponseCode();
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
