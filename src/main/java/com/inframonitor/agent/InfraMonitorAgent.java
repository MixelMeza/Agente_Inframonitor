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
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
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
 *   java -jar inframonitor-agent.jar --allow-console --server=ws://your-backend:9875/ws/agents \
 *                                    --name=office-network-agent \
 *                                    --key=ima_xxxxxxxxxxxx
 *
 * Optional:
 *   --heartbeat=30          (seconds between heartbeats, default 30)
 *   --reconnect-delay=5     (seconds between reconnect attempts, default 5)
 *   --allow-console         enable remote terminal commands from InfraMonitor ADMIN users
 */
public class InfraMonitorAgent {

    private static final String VERSION = "1.0.4";
    private static final int DEFAULT_TIMEOUT_MS = 5000;
    private static final int MIN_TIMEOUT_MS = 2000;
    private static final int MAX_TIMEOUT_MS = 8000;  // Reduced from 10s to prevent runaway delays
    private static volatile boolean debugEnabled =
            Boolean.parseBoolean(System.getenv().getOrDefault("INFRAMONITOR_AGENT_DEBUG", "false"));
    private static volatile boolean consoleEnabled =
            Boolean.parseBoolean(System.getenv().getOrDefault("INFRAMONITOR_AGENT_CONSOLE", "false"));
    private static final Map<String, ShellSession> shellSessions = new ConcurrentHashMap<>();
    private static final Map<Long, OfflineService> offlineServices = new ConcurrentHashMap<>();
    private static final AtomicBoolean backendConnected = new AtomicBoolean(false);
    private static final Path offlineConfigPath = Path.of("inframonitor-agent-services.cache");
    private static final Path offlineQueuePath = Path.of("inframonitor-agent-results.queue");
    private static ScheduledExecutorService offlineScheduler;

    /**
     * C: Adaptive timeout — tracks the exponential moving average (EMA) of latency
     * per target. The effective timeout = avg + 3s (not 3x multiplier), capped at MAX_TIMEOUT.
     * This prevents DNS or network hiccups from snowballing into huge timeouts.
     * 
     * Example:
     * - Fast service (20ms latency): avg + 3s = 3.02s
     * - Slow service (2s latency): avg + 3s = 5s
     */
    private static final java.util.concurrent.ConcurrentHashMap<String, Long> avgLatencyByTarget
            = new java.util.concurrent.ConcurrentHashMap<>();

    private static int adaptiveTimeout(String target, int requestedTimeoutMs) {
        Long avg = avgLatencyByTarget.get(target);
        if (avg == null || avg <= 0) return requestedTimeoutMs; // no history yet
        
        // Add 3 seconds buffer instead of multiplying (prevents exponential growth)
        int adaptive = (int) (avg + 3000);
        adaptive = Math.max(MIN_TIMEOUT_MS, Math.min(MAX_TIMEOUT_MS, adaptive));
        
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
    // Bounded pool: each check spawns an OS process (ping/etc.) on top of the thread, so an
    // unbounded cached pool could spawn unbounded processes if many checks arrive at once
    // (e.g. backend dispatching a burst after a reconnect). Capped at 64 concurrent checks;
    // excess work queues rather than spawning unbounded threads/processes.
    // (Virtual threads would be ideal on Java 21+, but we target 17)
    private static final ExecutorService checkExecutor = new ThreadPoolExecutor(
            8, 64, 60L, TimeUnit.SECONDS, new java.util.concurrent.LinkedBlockingQueue<>());

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
            if (arg.equals("--debug")) {
                debugEnabled = true;
            } else if (arg.equals("--allow-console")) {
                consoleEnabled = true;
            }
        }

        for (String arg : args) {
            if (arg.startsWith("--server="))          serverUrl = arg.substring(9);
            else if (arg.startsWith("--name="))       agentName = arg.substring(7);
            else if (arg.startsWith("--key="))        apiKey = arg.substring(6);
            else if (arg.startsWith("--heartbeat="))  heartbeatSec = Integer.parseInt(arg.substring(12));
            else if (arg.startsWith("--reconnect-delay=")) reconnectDelaySec = Integer.parseInt(arg.substring(18));
            else if (arg.startsWith("--test-ping=")) {
                String target = arg.substring(12);
                long rtt = pingHost(target, DEFAULT_TIMEOUT_MS);
                if (rtt >= 0) {
                    System.out.println("PING " + target + " OK: " + rtt + "ms");
                    System.exit(0);
                }
                System.err.println("PING " + target + " failed or timed out");
                System.exit(2);
            }
        }

        if (serverUrl == null || agentName == null || apiKey == null) {
            System.err.println("Usage: java -jar inframonitor-agent.jar " +
                    "--server=ws://host:9875/ws/agents --name=AGENT_NAME --key=API_KEY [--debug] [--allow-console]");
            System.exit(1);
        }

        String wsUrl = serverUrl + "?name=" + agentName + "&key=" + apiKey;
        log("InfraMonitor Agent v" + VERSION + " starting...");
        log("Agent name : " + agentName);
        log("Backend    : " + serverUrl);
        log("Console   : " + (consoleEnabled ? "enabled" : "disabled"));
        loadOfflineConfig();
        startOfflineMonitor();

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
                        backendConnected.set(true);
                        wsRef.set(webSocket);
                        webSocket.request(1);
                        flushOfflineResults(webSocket);

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
                        backendConnected.set(false);
                        heartbeatScheduler.shutdownNow();
                        latch.countDown();
                        return null;
                    }

                    @Override
                    public void onError(WebSocket webSocket, Throwable error) {
                        log("WS error: " + error.getMessage());
                        backendConnected.set(false);
                        heartbeatScheduler.shutdownNow();
                        latch.countDown();
                    }
                }).join();

        latch.await();
        backendConnected.set(false);
        if (ws.isInputClosed()) ws.abort();
        heartbeatScheduler.shutdownNow();
    }

    // ── Message handling ──────────────────────────────────────────────────────

    private static void handleMessage(WebSocket ws, String json, String agentName) {
        String type = extractString(json, "type");
        if (type == null) return;

        switch (type) {
            case "WELCOME":
                log("Registered with backend (agentId=" + extractString(json, "agentId") + ")");
                break;
            case "PONG":
                break;
            case "CHECK":
                handleCheck(ws, json);
                break;
            case "CONFIG":
                handleConfig(json);
                break;
            case "OFFLINE_ACK":
                clearOfflineQueue();
                break;
            case "SHELL_START":
                handleShellStart(ws, json, agentName);
                break;
            case "SHELL_INPUT":
                handleShellInput(ws, json);
                break;
            case "SHELL_STOP":
                handleShellStop(ws, json);
                break;
            default:
                log("Unknown message type: " + type);
                break;
        }
    }

    private static void handleShellStart(WebSocket ws, String json, String agentName) {
        String sessionId = extractString(json, "sessionId");
        String shell = extractString(json, "shell");
        if (sessionId == null || sessionId.isBlank()) return;
        if (!consoleEnabled) {
            sendShellError(ws, sessionId, "Remote console is disabled. Start the agent with --allow-console.");
            return;
        }
        try {
            ShellSession previous = shellSessions.remove(sessionId);
            if (previous != null) previous.stop();

            ShellSession session = new ShellSession(sessionId, shell, ws);
            shellSessions.put(sessionId, session);
            session.start();
            sendJson(ws, "{\"type\":\"SHELL_READY\",\"sessionId\":\"" + jsonEscape(sessionId) +
                    "\",\"agentName\":\"" + jsonEscape(agentName) +
                    "\",\"shell\":\"" + jsonEscape(session.shellName()) + "\"}");
            log("Remote console opened session=" + sessionId + " shell=" + session.shellName());
        } catch (Exception e) {
            sendShellError(ws, sessionId, "Could not start shell: " + e.getMessage());
        }
    }

    private static void handleShellInput(WebSocket ws, String json) {
        String sessionId = extractString(json, "sessionId");
        String input = extractString(json, "input");
        ShellSession session = sessionId != null ? shellSessions.get(sessionId) : null;
        if (session == null) {
            if (sessionId != null) sendShellError(ws, sessionId, "Shell session not found");
            return;
        }
        try {
            session.write(input != null ? input : "");
        } catch (Exception e) {
            sendShellError(ws, sessionId, "Shell input failed: " + e.getMessage());
        }
    }

    private static void handleShellStop(WebSocket ws, String json) {
        String sessionId = extractString(json, "sessionId");
        ShellSession session = sessionId != null ? shellSessions.remove(sessionId) : null;
        if (session != null) {
            session.stop();
        }
    }

    private static void handleConfig(String json) {
        String encoded = extractString(json, "data");
        if (encoded == null || encoded.isBlank()) return;
        try {
            String data = new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8);
            offlineServices.clear();
            for (String line : data.split("\\R")) {
                if (line.isBlank()) continue;
                OfflineService svc = OfflineService.parse(line);
                if (svc != null) {
                    offlineServices.put(svc.id, svc);
                }
            }
            Files.writeString(
                    offlineConfigPath,
                    data,
                    StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING);
            log("Received offline config: " + offlineServices.size() + " service(s)");
        } catch (Exception e) {
            log("Could not apply offline config: " + e.getMessage());
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
        requestedTimeout = Math.max(MIN_TIMEOUT_MS, Math.min(MAX_TIMEOUT_MS, requestedTimeout));
        // C: Use adaptive timeout based on historical latency for this target
        int timeoutMs = adaptiveTimeout(target != null ? target : "", requestedTimeout);
        debug("CHECK id=" + checkId
                + " type=" + monitorType
                + " target=" + target
                + " port=" + port
                + " requestedTimeoutMs=" + requestedTimeout
                + " effectiveTimeoutMs=" + timeoutMs
                + " os=" + System.getProperty("os.name"));

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
            String normalizedType = monitorType != null ? monitorType.toUpperCase() : "";
            switch (normalizedType) {
                case "PING": {
                    long rtt = pingHost(target, timeoutMs);
                    boolean ok = rtt >= 0;
                    return new CheckResult(ok ? "UP" : "DOWN", ok ? rtt : 0,
                            ok ? "PING OK (" + rtt + "ms)" : "Host unreachable / timeout");
                }
                case "TCP": {
                    int p = port != null ? port : 80;
                    try (Socket s = new Socket()) {
                        s.connect(new InetSocketAddress(target, p), timeoutMs);
                        long latency = System.currentTimeMillis() - start;
                        return new CheckResult("UP", latency, "TCP " + p + " open (" + latency + "ms)");
                    }
                }
                case "HTTP": {
                    String rawUrl = (url != null && !url.equals("null") && !url.isBlank())
                            ? url
                            : "http://" + target + (port != null ? ":" + port : "");
                    if (!rawUrl.startsWith("http")) rawUrl = "http://" + rawUrl;
                    return executeHttpAgentCheck(rawUrl, timeoutMs);
                }
                case "DNS": {
                    InetAddress addr = InetAddress.getByName(target);
                    long latency = System.currentTimeMillis() - start;
                    return new CheckResult("UP", latency, "DNS resolved to " + addr.getHostAddress());
                }
                case "IMAP": {
                    int p = port != null ? port : 143;
                    return checkImapAgent(target, p, timeoutMs);
                }
                case "LDAP": {
                    int p = port != null ? port : 389;
                    return checkLdapAgent(target, p, timeoutMs);
                }
                case "SIP": {
                    int p = port != null ? port : 5060;
                    return checkSipAgent(target, p, timeoutMs);
                }
                default:
                    return new CheckResult("UNKNOWN", 0, "Unsupported monitor type: " + monitorType);
            }
        } catch (java.net.SocketTimeoutException e) {
            long latency = System.currentTimeMillis() - start;
            return new CheckResult("DOWN", latency, "Timeout after " + latency + "ms");
        } catch (java.net.UnknownHostException e) {
            // The agent always resolves DNS using its own network/resolver (not the backend's).
            // This means the host could not be resolved from the agent's network — surface that
            // clearly instead of the raw exception name, which reads confusingly as "needs DNS".
            long latency = System.currentTimeMillis() - start;
            return new CheckResult("DOWN", latency,
                    "No se pudo resolver el host '" + target + "' usando el DNS del agente");
        } catch (Exception e) {
            long latency = System.currentTimeMillis() - start;
            return new CheckResult("DOWN", latency, e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    // Matches "time=12ms" / "time<1ms" / "tiempo=12ms" / "tiempo<1ms" (Windows EN/ES)
    // and "time=12.3 ms" (Linux/Mac).
    private static final java.util.regex.Pattern PING_RTT_PATTERN = java.util.regex.Pattern.compile(
            "(?i)(?:time|tiempo)[=<]\\s*([\\d.]+)\\s*ms");

    /**
     * Returns the real round-trip time in ms to the target, or -1 if unreachable/timeout.
     * We bypass InetAddress.isReachable because it defaults to TCP port 7 when
     * privileges are missing, which drops packets and blocks for the full timeout
     * before failing. System ping is much faster and reliable.
     *
     * DNS Resolution: Always done by the agent using local /etc/resolv.conf or system resolver.
     * This allows the agent to use DNS from its own network environment, not the backend's.
     *
     * The latency reported is parsed from the ping output's real RTT ("time=Xms"),
     * not the wall-clock time of the whole process (which includes process spawn,
     * DNS resolution and OS scheduling overhead and is not representative of the
     * actual network latency to the target).
     */
    private static long pingHost(String target, int timeoutMs) {
        try {
            boolean isWindows = System.getProperty("os.name").toLowerCase().contains("win");
            java.util.List<String> command;

            if (isWindows) {
                // Windows: -n (count), -w (timeout ms), -4 (IPv4 only, speeds up resolution)
                command = java.util.List.of("ping", "-n", "1", "-w", String.valueOf(timeoutMs), "-4", target);
            } else {
                // Linux/Mac: Prevent slow PTR (reverse DNS) lookups
                // - -c: count
                // - -n: disable name resolution (critical!)
                // - -W: timeout in SECONDS (convert from ms)
                // - -4: IPv4 only (faster)
                // Some systems may not support all flags, but they're additive/safe to ignore.

                int timeoutSec = Math.max(1, (timeoutMs + 500) / 1000);  // Round up
                command = java.util.List.of("ping", "-c", "1", "-n", "-W", String.valueOf(timeoutSec), "-4", target);
            }

            debug("PING command: " + String.join(" ", command));
            long processStartNs = System.nanoTime();
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(true);
            Process process = pb.start();

            // Java's waitFor() is the actual timeout guarantee (not the OS ping flags).
            boolean finished = process.waitFor(timeoutMs + 1000, TimeUnit.MILLISECONDS);
            long processElapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - processStartNs);
            if (!finished) {
                process.destroyForcibly();
                process.waitFor(500, TimeUnit.MILLISECONDS);
                debug("PING timed out after processElapsedMs=" + processElapsedMs
                        + " javaTimeoutMs=" + (timeoutMs + 1000));
                return -1;  // Timeout exceeded
            }

            String output = new String(process.getInputStream().readAllBytes());
            int exitCode = process.exitValue();
            // Require both exit code 0 AND a TTL in the response — on Windows, "ping"
            // can return 0 even for "Destination host unreachable" replies.
            boolean hasTtl = output.toLowerCase().contains("ttl=");
            debug("PING finished processElapsedMs=" + processElapsedMs
                    + " exitCode=" + exitCode
                    + " hasTtl=" + hasTtl
                    + " output=\"" + compact(output) + "\"");
            if (exitCode != 0 || !hasTtl) {
                return -1;
            }

            java.util.regex.Matcher m = PING_RTT_PATTERN.matcher(output);
            if (m.find()) {
                long parsed = (long) Double.parseDouble(m.group(1));
                debug("PING parsedRttMs=" + parsed);
                return parsed;
            }
            // TTL present but couldn't parse RTT (unexpected format) — treat as 0ms rather
            // than fabricating a number from wall-clock time.
            debug("PING had TTL but RTT could not be parsed; returning 0ms");
            return 0;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            debug("PING interrupted: " + e.getMessage());
            return -1;
        } catch (Exception e) {
            // DNS resolution failed, network error, etc.
            debug("PING failed: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            return -1;
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
                if (e instanceof java.net.UnknownHostException) {
                    return new CheckResult("DOWN", latency,
                            "No se pudo resolver el host de '" + rawUrl + "' usando el DNS del agente");
                }
                return new CheckResult("DOWN", latency, e.getClass().getSimpleName() + ": " + e.getMessage());
            }
        }
    }

    private static int tryHttpAgentConnect(String rawUrl, String method, boolean trustAll, int timeoutMs) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(rawUrl).openConnection();
        if (trustAll && conn instanceof javax.net.ssl.HttpsURLConnection) {
            javax.net.ssl.HttpsURLConnection httpsConn = (javax.net.ssl.HttpsURLConnection) conn;
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

    private static void loadOfflineConfig() {
        try {
            if (!Files.exists(offlineConfigPath)) return;
            List<String> lines = Files.readAllLines(offlineConfigPath, StandardCharsets.UTF_8);
            for (String line : lines) {
                OfflineService svc = OfflineService.parse(line);
                if (svc != null) offlineServices.put(svc.id, svc);
            }
            log("Loaded offline config: " + offlineServices.size() + " service(s)");
        } catch (Exception e) {
            log("Could not load offline config: " + e.getMessage());
        }
    }

    private static void startOfflineMonitor() {
        offlineScheduler = Executors.newSingleThreadScheduledExecutor();
        offlineScheduler.scheduleAtFixedRate(() -> {
            try {
                if (backendConnected.get() || offlineServices.isEmpty()) return;
                long now = System.currentTimeMillis();
                for (OfflineService svc : offlineServices.values()) {
                    if (now - svc.lastRunAt < svc.intervalSeconds * 1000L) continue;
                    svc.lastRunAt = now;
                    checkExecutor.submit(() -> runOfflineCheck(svc));
                }
            } catch (Exception e) {
                debug("offline scheduler error: " + e.getMessage());
            }
        }, 2, 1, TimeUnit.SECONDS);
    }

    private static void runOfflineCheck(OfflineService svc) {
        if (backendConnected.get()) return;
        CheckResult result = executeCheck(svc.monitorType, svc.target, svc.port, svc.url, DEFAULT_TIMEOUT_MS);
        if ("UP".equals(result.status) && result.latencyMs > 0) {
            recordLatency(svc.target != null ? svc.target : "", result.latencyMs);
        }
        appendOfflineResult(svc.id, System.currentTimeMillis(), result);
        log("Offline result: " + svc.name + " " + result.status + " (" + result.latencyMs + "ms) " + result.message);
    }

    private static synchronized void appendOfflineResult(long serviceId, long checkedAtMs, CheckResult result) {
        try {
            String line = serviceId + "|" + checkedAtMs + "|" + result.status + "|" + result.latencyMs + "|" +
                    b64(result.message != null ? result.message : "") + "\n";
            Files.writeString(offlineQueuePath, line, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (Exception e) {
            debug("could not append offline result: " + e.getMessage());
        }
    }

    private static synchronized void flushOfflineResults(WebSocket ws) {
        try {
            if (!Files.exists(offlineQueuePath)) return;
            String data = Files.readString(offlineQueuePath, StandardCharsets.UTF_8);
            if (data.isBlank()) return;
            String encoded = Base64.getEncoder().encodeToString(data.getBytes(StandardCharsets.UTF_8));
            sendJson(ws, "{\"type\":\"OFFLINE_RESULTS\",\"data\":\"" + encoded + "\"}");
            log("Sent offline results for sync (" + data.lines().count() + " record(s))");
        } catch (Exception e) {
            log("Could not flush offline results: " + e.getMessage());
        }
    }

    private static synchronized void clearOfflineQueue() {
        try {
            Files.deleteIfExists(offlineQueuePath);
            log("Offline result queue acknowledged by backend");
        } catch (Exception e) {
            debug("could not clear offline queue: " + e.getMessage());
        }
    }

    private static String b64(String text) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(text.getBytes(StandardCharsets.UTF_8));
    }

    private static String unb64(String text) {
        if (text == null || text.isEmpty()) return "";
        return new String(Base64.getUrlDecoder().decode(text), StandardCharsets.UTF_8);
    }

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

    private static void debug(String msg) {
        if (debugEnabled) {
            System.out.println("[InfraMonitor-Agent][debug] " + msg);
        }
    }

    private static void sendJson(WebSocket ws, String json) {
        synchronized (ws) {
            ws.sendText(json, true);
        }
    }

    private static void sendShellOutput(WebSocket ws, String sessionId, String stream, String data) {
        if (data == null || data.isEmpty()) return;
        sendJson(ws, "{\"type\":\"SHELL_OUTPUT\",\"sessionId\":\"" + jsonEscape(sessionId) +
                "\",\"stream\":\"" + jsonEscape(stream) +
                "\",\"data\":\"" + jsonEscape(data) + "\"}");
    }

    private static void sendShellError(WebSocket ws, String sessionId, String message) {
        sendJson(ws, "{\"type\":\"SHELL_ERROR\",\"sessionId\":\"" + jsonEscape(sessionId) +
                "\",\"message\":\"" + jsonEscape(message) + "\"}");
    }

    private static void sendShellExit(WebSocket ws, String sessionId, int exitCode) {
        sendJson(ws, "{\"type\":\"SHELL_EXIT\",\"sessionId\":\"" + jsonEscape(sessionId) +
                "\",\"exitCode\":" + exitCode + "}");
    }

    private static String compact(String text) {
        if (text == null) return "";
        String oneLine = text.replace('\r', ' ').replace('\n', ' ').replaceAll("\\s+", " ").trim();
        return oneLine.length() > 500 ? oneLine.substring(0, 500) + "..." : oneLine;
    }

    private static String jsonEscape(String text) {
        if (text == null) return "";
        StringBuilder sb = new StringBuilder(text.length() + 16);
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '\\':
                    sb.append("\\\\");
                    break;
                case '"':
                    sb.append("\\\"");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    if (c < 32) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                    break;
            }
        }
        return sb.toString();
    }

    private static final class CheckResult {
        final String status;
        final long latencyMs;
        final String message;

        CheckResult(String status, long latencyMs, String message) {
            this.status = status;
            this.latencyMs = latencyMs;
            this.message = message;
        }
    }

    private static final class OfflineService {
        final long id;
        final String name;
        final String monitorType;
        final String target;
        final Integer port;
        final String url;
        final int intervalSeconds;
        volatile long lastRunAt;

        OfflineService(long id, String name, String monitorType, String target,
                       Integer port, String url, int intervalSeconds) {
            this.id = id;
            this.name = name;
            this.monitorType = monitorType;
            this.target = target;
            this.port = port;
            this.url = url;
            this.intervalSeconds = Math.max(1, intervalSeconds);
        }

        static OfflineService parse(String line) {
            try {
                String[] p = line.split("\\|", -1);
                if (p.length < 7) return null;
                Integer port = p[4].isBlank() ? null : Integer.parseInt(p[4]);
                return new OfflineService(
                        Long.parseLong(p[0]),
                        unb64(p[1]),
                        p[2],
                        unb64(p[3]),
                        port,
                        unb64(p[5]),
                        Integer.parseInt(p[6]));
            } catch (Exception e) {
                return null;
            }
        }
    }

    private static final class ShellSession {
        private final String sessionId;
        private final String requestedShell;
        private final WebSocket ws;
        private Process process;

        ShellSession(String sessionId, String requestedShell, WebSocket ws) {
            this.sessionId = sessionId;
            this.requestedShell = requestedShell;
            this.ws = ws;
        }

        String shellName() {
            if (requestedShell != null && !requestedShell.isBlank()) return requestedShell;
            return isWindows() ? "cmd.exe" : "/bin/sh";
        }

        void start() throws Exception {
            ProcessBuilder pb = new ProcessBuilder(shellName());
            pb.redirectErrorStream(false);
            process = pb.start();

            Thread stdout = new Thread(() -> readLoop(process.getInputStream(), "stdout"),
                    "inframonitor-shell-stdout-" + sessionId);
            Thread stderr = new Thread(() -> readLoop(process.getErrorStream(), "stderr"),
                    "inframonitor-shell-stderr-" + sessionId);
            Thread waiter = new Thread(() -> {
                try {
                    int code = process.waitFor();
                    shellSessions.remove(sessionId);
                    sendShellExit(ws, sessionId, code);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }, "inframonitor-shell-wait-" + sessionId);
            stdout.setDaemon(true);
            stderr.setDaemon(true);
            waiter.setDaemon(true);
            stdout.start();
            stderr.start();
            waiter.start();
        }

        void write(String input) throws Exception {
            if (process == null || !process.isAlive()) {
                throw new IllegalStateException("Shell process is not running");
            }
            byte[] bytes = input.getBytes(Charset.defaultCharset());
            process.getOutputStream().write(bytes);
            process.getOutputStream().flush();
        }

        void stop() {
            if (process == null) return;
            try {
                process.destroy();
                if (!process.waitFor(1500, TimeUnit.MILLISECONDS)) {
                    process.destroyForcibly();
                }
            } catch (Exception ignored) {
                process.destroyForcibly();
            }
        }

        private void readLoop(java.io.InputStream input, String stream) {
            byte[] buffer = new byte[4096];
            try {
                int read;
                while ((read = input.read(buffer)) != -1) {
                    String text = new String(buffer, 0, read, Charset.defaultCharset());
                    sendShellOutput(ws, sessionId, stream, text);
                }
            } catch (Exception e) {
                if (process != null && process.isAlive()) {
                    sendShellOutput(ws, sessionId, "stderr", "Read error: " + e.getMessage() + "\n");
                }
            }
        }

        private static boolean isWindows() {
            return System.getProperty("os.name").toLowerCase().contains("win");
        }
    }
}
