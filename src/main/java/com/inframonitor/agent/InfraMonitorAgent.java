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
import java.util.LinkedHashMap;
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

    private static final String VERSION = "1.0.9";
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
            case "NETWORK_SCAN":
                handleNetworkScan(ws, json);
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

    // ── Network scan (LAN discovery) ────────────────────────────────────────────

    private static final int SCAN_HOST_TIMEOUT_MS = 250;
    private static final int SCAN_NETWORK_BUDGET_MS = 1800;
    private static final int SCAN_SUBNET_DISCOVERY_BUDGET_MS = 7000;
    private static final int SCAN_MAX_NETWORKS_PER_RUN = 64;
    // Bounds the active sweep so a misconfigured huge subnet (e.g. /8) only scans the local /24 window.
    private static final int SCAN_MAX_PREFIX_LENGTH = 24;
    private static final ExecutorService scanExecutor = new ThreadPoolExecutor(
            16, 64, 30L, TimeUnit.SECONDS, new java.util.concurrent.LinkedBlockingQueue<>());

    private static void handleNetworkScan(WebSocket ws, String json) {
        String scanId = extractString(json, "id");
        String toStr = extractString(json, "timeoutMs");
        int overallTimeoutMs = (toStr != null && !toStr.equals("null")) ? Integer.parseInt(toStr) : 20000;

        log("Starting network scan id=" + scanId);
        long start = System.currentTimeMillis();
        StringBuilder networksJson = new StringBuilder();
        String error = null;
        int scannedNetworks = 0;
        int totalNetworks = 0;
        try {
            List<ScanNetwork> networks = localScanNetworks();
            totalNetworks = Math.min(networks.size(), SCAN_MAX_NETWORKS_PER_RUN);
            if (networks.isEmpty()) {
                error = "No IPv4 LAN interfaces found on the agent host";
            }
            log("Network scan discovered " + networks.size() + " candidate subnet(s)");
            for (int i = 0; i < networks.size() && i < SCAN_MAX_NETWORKS_PER_RUN; i++) {
                long remainingMs = overallTimeoutMs - (System.currentTimeMillis() - start) - 1000;
                if (remainingMs <= 500) {
                    log("Network scan budget exhausted; returning partial result");
                    break;
                }
                String networkJson = scanOneNetwork(networks.get(i), (int) Math.min(remainingMs, SCAN_NETWORK_BUDGET_MS));
                if (networksJson.length() > 0) networksJson.append(',');
                networksJson.append(networkJson);
                scannedNetworks++;
                sendNetworkScanResult(ws, scanId, true, System.currentTimeMillis() - start, null,
                        networkJson, scannedNetworks, totalNetworks);
            }
        } catch (Exception e) {
            error = e.getClass().getSimpleName() + ": " + e.getMessage();
            log("Network scan failed: " + error);
        }
        long elapsed = System.currentTimeMillis() - start;
        log("Network scan id=" + scanId + " finished in " + elapsed + "ms");

        sendNetworkScanResult(ws, scanId, false, elapsed, error, networksJson.toString(),
                scannedNetworks, totalNetworks);
    }

    private static void sendNetworkScanResult(WebSocket ws, String scanId, boolean partial, long durationMs,
                                              String error, String networksJson,
                                              int scannedNetworks, int totalNetworks) {
        sendJson(ws, "{\"type\":\"NETWORK_SCAN_RESULT\",\"id\":\"" + jsonEscape(scanId) +
                "\",\"partial\":" + partial +
                ",\"durationMs\":" + durationMs +
                ",\"scannedNetworks\":" + scannedNetworks +
                ",\"totalNetworks\":" + totalNetworks +
                (error != null ? ",\"error\":\"" + jsonEscape(error) + "\"" : "") +
                ",\"networks\":[" + networksJson + "]}");
    }

    /** A local IPv4 network reachable from one of this host's interfaces. */
    private static final class ScanNetwork {
        final String interfaceName;
        final String baseIp;     // network address, e.g. 192.168.1.0
        final String localIp;
        final int prefixLength;  // CIDR prefix, capped at SCAN_MAX_PREFIX_LENGTH for the sweep

        ScanNetwork(String interfaceName, String baseIp, String localIp, int prefixLength) {
            this.interfaceName = interfaceName;
            this.baseIp = baseIp;
            this.localIp = localIp;
            this.prefixLength = prefixLength;
        }

        String cidr() { return baseIp + "/" + prefixLength; }
    }

    /**
     * Enumerates this host's up, non-loopback, non-virtual IPv4 interfaces and the
     * networks they're attached to. Large networks (prefix < /22) are clamped to the
     * /24 containing this host's address so the sweep stays fast.
     */
    private static List<ScanNetwork> localScanNetworks() throws Exception {
        List<ScanNetwork> result = new ArrayList<>();
        java.util.Enumeration<java.net.NetworkInterface> ifaces = java.net.NetworkInterface.getNetworkInterfaces();
        while (ifaces.hasMoreElements()) {
            java.net.NetworkInterface iface = ifaces.nextElement();
            if (!iface.isUp() || iface.isLoopback() || iface.isVirtual()) continue;

            for (java.net.InterfaceAddress ifAddr : iface.getInterfaceAddresses()) {
                InetAddress addr = ifAddr.getAddress();
                if (!(addr instanceof java.net.Inet4Address)) continue;
                int prefix = ifAddr.getNetworkPrefixLength();
                if (prefix <= 0 || prefix > 32) continue;

                // Clamp every broad network down to a /24 around this host's address.
                int scanPrefix = prefix < SCAN_MAX_PREFIX_LENGTH ? 24 : prefix;
                if (scanPrefix < prefix) scanPrefix = prefix; // never widen beyond the real network

                int ip = ipToInt(addr.getHostAddress());
                int mask = scanPrefix == 0 ? 0 : (int) (0xFFFFFFFFL << (32 - scanPrefix));
                int network = ip & mask;
                result.add(new ScanNetwork(iface.getName(), intToIp(network), addr.getHostAddress(), scanPrefix));
                debug("Network scan interface " + iface.getName() + " localIp=" + addr.getHostAddress()
                        + " cidr=" + intToIp(network) + "/" + scanPrefix);
            }
        }
        addDirectRouteNetworks(result);
        addSiblingRouteCandidates(result);
        return result;
    }

    private static void addSiblingRouteCandidates(List<ScanNetwork> result) {
        java.util.LinkedHashSet<String> candidates = new java.util.LinkedHashSet<>();
        for (ScanNetwork net : new ArrayList<>(result)) {
            addSiblingCandidateCidrs(candidates, net.localIp, net.cidr());
        }
        if (candidates.isEmpty()) return;

        long start = System.currentTimeMillis();
        java.util.concurrent.ConcurrentHashMap<String, String> alive = new java.util.concurrent.ConcurrentHashMap<>();
        List<CompletableFuture<Void>> probes = new ArrayList<>();

        for (String cidr : candidates) {
            if (System.currentTimeMillis() - start > SCAN_SUBNET_DISCOVERY_BUDGET_MS) break;
            String baseIp = cidr.substring(0, cidr.indexOf('/'));
            int base = ipToInt(baseIp);
            for (int host : new int[]{1, 254}) {
                String gatewayIp = intToIp(base + host);
                probes.add(CompletableFuture.runAsync(() -> {
                    if (isLikelyAlive(gatewayIp, 180)) {
                        alive.putIfAbsent(cidr, gatewayIp);
                    }
                }, scanExecutor));
            }
        }

        try {
            CompletableFuture.allOf(probes.toArray(new CompletableFuture[0]))
                    .get(SCAN_SUBNET_DISCOVERY_BUDGET_MS, TimeUnit.MILLISECONDS);
        } catch (Exception e) {
            debug("Sibling subnet discovery returned partial results: " + e.getMessage());
        }

        int added = 0;
        for (Map.Entry<String, String> entry : alive.entrySet()) {
            if (added >= SCAN_MAX_NETWORKS_PER_RUN) break;
            String cidr = entry.getKey();
            if (hasNetwork(result, cidr)) continue;
            String baseIp = cidr.substring(0, cidr.indexOf('/'));
            result.add(new ScanNetwork("routed", baseIp, entry.getValue(), 24));
            added++;
        }
        if (added > 0) {
            log("Network scan found " + added + " routed sibling subnet(s)");
        }
    }

    private static void addSiblingCandidateCidrs(java.util.LinkedHashSet<String> out, String localIp, String currentCidr) {
        if (localIp == null || localIp.isBlank()) return;
        String[] p = localIp.split("\\.");
        if (p.length != 4) return;
        try {
            int a = Integer.parseInt(p[0]);
            int b = Integer.parseInt(p[1]);
            int c = Integer.parseInt(p[2]);

            if (a == 192 && b == 168) {
                for (int third = 0; third <= 255; third++) addCandidate(out, "192.168." + third + ".0/24", currentCidr);
            } else if (a == 172 && b >= 16 && b <= 31) {
                for (int third = 0; third <= 255; third++) addCandidate(out, "172." + b + "." + third + ".0/24", currentCidr);
            } else if (a == 10) {
                for (int third = 0; third <= 255; third++) addCandidate(out, "10." + b + "." + third + ".0/24", currentCidr);
            } else {
                int from = Math.max(0, c - 8);
                int to = Math.min(255, c + 8);
                for (int third = from; third <= to; third++) addCandidate(out, a + "." + b + "." + third + ".0/24", currentCidr);
            }
        } catch (Exception ignored) {
            // Ignore malformed local addresses.
        }
    }

    private static void addCandidate(java.util.LinkedHashSet<String> out, String cidr, String currentCidr) {
        if (!cidr.equals(currentCidr)) out.add(cidr);
    }

    private static boolean hasNetwork(List<ScanNetwork> networks, String cidr) {
        for (ScanNetwork n : networks) {
            if (n.cidr().equals(cidr)) return true;
        }
        return false;
    }

    private static boolean isLikelyAlive(String ip, int timeoutMs) {
        if (pingHostQuiet(ip, timeoutMs) >= 0) return true;
        return tcpProbe(ip, 80, timeoutMs) || tcpProbe(ip, 443, timeoutMs) || tcpProbe(ip, 22, timeoutMs);
    }

    private static boolean tcpProbe(String ip, int port, int timeoutMs) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(ip, port), timeoutMs);
            return true;
        } catch (java.net.ConnectException e) {
            String msg = e.getMessage() != null ? e.getMessage().toLowerCase() : "";
            return msg.contains("refused");
        } catch (Exception e) {
            return false;
        }
    }

    private static void addDirectRouteNetworks(List<ScanNetwork> result) {
        if (System.getProperty("os.name").toLowerCase().contains("win")) return;
        try {
            ProcessBuilder pb = new ProcessBuilder("sh", "-c", "ip -4 route show scope link 2>/dev/null");
            pb.redirectErrorStream(true);
            Process process = pb.start();
            if (!process.waitFor(1200, TimeUnit.MILLISECONDS)) {
                process.destroyForcibly();
                return;
            }
            for (String line : new String(process.getInputStream().readAllBytes()).split("\\R")) {
                addDirectRouteNetworkLine(result, line.trim());
            }
        } catch (Exception e) {
            debug("Route network discovery failed: " + e.getMessage());
        }
    }

    private static void addDirectRouteNetworkLine(List<ScanNetwork> result, String line) {
        if (line.isBlank() || line.startsWith("default ")) return;
        String[] parts = line.split("\\s+");
        if (parts.length == 0 || !parts[0].contains("/")) return;

        String cidr = parts[0];
        String dev = "";
        String src = "";
        for (int i = 1; i < parts.length - 1; i++) {
            if ("dev".equals(parts[i])) dev = parts[i + 1];
            if ("src".equals(parts[i])) src = parts[i + 1];
        }
        if (src.isBlank()) return;

        try {
            String[] c = cidr.split("/", 2);
            int routePrefix = Integer.parseInt(c[1]);
            if (routePrefix <= 0 || routePrefix > 32) return;
            int scanPrefix = routePrefix < SCAN_MAX_PREFIX_LENGTH ? SCAN_MAX_PREFIX_LENGTH : routePrefix;
            int ip = ipToInt(src);
            int mask = scanPrefix == 0 ? 0 : (int) (0xFFFFFFFFL << (32 - scanPrefix));
            String baseIp = intToIp(ip & mask);
            String key = baseIp + "/" + scanPrefix;
            for (ScanNetwork existing : result) {
                if (existing.cidr().equals(key)) return;
            }
            result.add(new ScanNetwork(dev.isBlank() ? "route" : dev, baseIp, src, scanPrefix));
            debug("Network scan direct route localIp=" + src + " cidr=" + key);
        } catch (Exception ignored) {
            // Ignore route lines that don't look like IPv4 CIDR + src.
        }
    }

    private static String scanOneNetwork(ScanNetwork net, int timeoutMs) {
        int network = ipToInt(net.baseIp);
        int hostBits = 32 - net.prefixLength;
        long totalHosts = hostBits >= 31 ? 1 : (1L << hostBits) - 2; // exclude network+broadcast
        totalHosts = Math.max(totalHosts, 1);

        Map<String, Long> discovered = new java.util.concurrent.ConcurrentHashMap<>();
        discovered.put(net.localIp, 0L);

        Map<String, String> arpHosts = lookupArpTable(network, net.prefixLength);
        for (String ip : arpHosts.keySet()) {
            discovered.putIfAbsent(ip, 0L);
        }

        List<CompletableFuture<Void>> futures = new ArrayList<>();
        for (long h = 1; h <= totalHosts; h++) {
            int candidate = network + (int) h;
            String ip = intToIp(candidate);
            futures.add(CompletableFuture.runAsync(() -> {
                long rtt = pingHostQuiet(ip, SCAN_HOST_TIMEOUT_MS);
                if (rtt >= 0) {
                    discovered.put(ip, rtt);
                }
            }, scanExecutor));
        }

        try {
            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                    .get(Math.max(1200, timeoutMs), TimeUnit.MILLISECONDS);
        } catch (Exception e) {
            debug("Network scan ping sweep timed out/partial on " + net.cidr() + ": " + e.getMessage());
        }

        arpHosts = lookupArpTable(network, net.prefixLength);
        for (String ip : arpHosts.keySet()) {
            discovered.putIfAbsent(ip, 0L);
        }

        List<String> ips = new ArrayList<>(discovered.keySet());
        ips.sort(InfraMonitorAgent::compareIpv4);

        StringBuilder hostsJson = new StringBuilder();
        boolean first = true;
        for (String ip : ips) {
            try {
                String hostJson = hostJson(ip, discovered.getOrDefault(ip, 0L), arpHosts.get(ip));
                if (hostJson != null) {
                    if (!first) hostsJson.append(',');
                    hostsJson.append(hostJson);
                    first = false;
                }
            } catch (Exception ignored) {
                // timeout/unreachable — skip this host
            }
        }

        log("Network scan " + net.cidr() + " found " + ips.size() + " host(s)");
        return "{\"cidr\":\"" + jsonEscape(net.cidr()) +
                "\",\"interfaceName\":\"" + jsonEscape(net.interfaceName) +
                "\",\"hosts\":[" + hostsJson + "]}";
    }

    private static String hostJson(String ip, long latencyMs) {
        return hostJson(ip, latencyMs, null);
    }

    private static String hostJson(String ip, long latencyMs, String knownMac) {
        String mac = knownMac != null && !knownMac.isBlank() ? knownMac : lookupArpMac(ip);
        String hostname = resolveHostnameQuiet(ip);
        String vendor = mac != null ? lookupOuiVendor(mac) : "Unknown";
        String deviceType = classifyDeviceType(vendor, hostname);
        return "{\"ip\":\"" + jsonEscape(ip) +
                "\",\"mac\":\"" + jsonEscape(mac != null ? mac : "") +
                "\",\"vendor\":\"" + jsonEscape(vendor) +
                "\",\"deviceType\":\"" + jsonEscape(deviceType) +
                "\",\"hostname\":\"" + jsonEscape(hostname != null ? hostname : "") +
                "\",\"latencyMs\":" + latencyMs + "}";
    }

    // Keyword groups used to classify a discovered host beyond plain "computer", since a LAN
    // sweep also turns up routers/APs/switches, printers, cameras, phones, VMs and IoT/SBCs —
    // each needing different handling in the UI (e.g. routers shouldn't be flagged as rogue hosts).
    private static final String[] NETWORK_GEAR_VENDORS = {
            "ubiquiti", "tp-link", "d-link", "netgear", "cisco", "asustek", "mikrotik", "huawei"
    };
    private static final String[] PRINTER_VENDORS = {"brother", "hp", "canon", "epson", "lexmark"};
    private static final String[] MOBILE_VENDORS = {"apple", "samsung", "xiaomi", "huawei"};
    private static final String[] VM_VENDORS = {"vmware", "virtualbox", "hyper-v", "microsoft hyper-v"};
    private static final String[] IOT_VENDORS = {"raspberry pi"};

    /**
     * Best-effort classification combining vendor (OUI) and hostname keywords. Hostname hints
     * take priority since they're more specific than a generic vendor match (e.g. a Brother
     * vendor MAC with hostname "office-router" is unusual, but a hostname is rarely wrong).
     */
    private static String classifyDeviceType(String vendor, String hostname) {
        String v = vendor != null ? vendor.toLowerCase() : "";
        String h = hostname != null ? hostname.toLowerCase() : "";

        if (containsAny(h, "router", "gateway", "ap-", "access-point", "accesspoint", "switch", "modem")) {
            return "Network Equipment";
        }
        if (containsAny(h, "printer", "print-")) return "Printer";
        if (containsAny(h, "cam", "camera", "nvr", "dvr")) return "Camera";
        if (containsAny(h, "iphone", "android", "phone", "mobile")) return "Mobile Device";
        if (containsAny(h, "desktop", "laptop", "pc-", "workstation")) return "Computer";

        if (containsAny(v, NETWORK_GEAR_VENDORS)) return "Network Equipment";
        if (containsAny(v, PRINTER_VENDORS)) return "Printer";
        if (containsAny(v, VM_VENDORS)) return "Virtual Machine";
        if (containsAny(v, IOT_VENDORS)) return "IoT / Single-board Computer";
        if (containsAny(v, MOBILE_VENDORS)) return "Mobile Device";
        if (containsAny(v, "dell", "lenovo", "intel", "sony")) return "Computer";

        return "Unknown";
    }

    private static boolean containsAny(String haystack, String... needles) {
        for (String n : needles) {
            if (haystack.contains(n)) return true;
        }
        return false;
    }

    private static String resolveHostnameQuiet(String ip) {
        try {
            CompletableFuture<String> f = CompletableFuture.supplyAsync(() -> {
                try {
                    InetAddress addr = InetAddress.getByName(ip);
                    String host = addr.getCanonicalHostName();
                    return host.equals(ip) ? null : host; // no PTR record resolved
                } catch (Exception e) {
                    return null;
                }
            }, scanExecutor);
            return f.get(800, TimeUnit.MILLISECONDS);
        } catch (Exception e) {
            return null;
        }
    }

    private static final java.util.regex.Pattern MAC_PATTERN = java.util.regex.Pattern.compile(
            "([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}");
    private static final java.util.regex.Pattern IPV4_PATTERN = java.util.regex.Pattern.compile(
            "\\b((?:\\d{1,3}\\.){3}\\d{1,3})\\b");

    private static Map<String, String> lookupArpTable(int network, int prefixLength) {
        Map<String, String> hosts = new LinkedHashMap<>();
        try {
            boolean isWindows = System.getProperty("os.name").toLowerCase().contains("win");
            java.util.List<String> command = isWindows
                    ? java.util.List.of("arp", "-a")
                    : java.util.List.of("sh", "-c", "ip neigh show 2>/dev/null || arp -an");

            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            boolean finished = process.waitFor(1500, TimeUnit.MILLISECONDS);
            if (!finished) {
                process.destroyForcibly();
                return hosts;
            }
            parseArpOutput(new String(process.getInputStream().readAllBytes()), network, prefixLength, hosts);
        } catch (Exception e) {
            debug("ARP table lookup failed: " + e.getMessage());
        }
        return hosts;
    }

    private static void parseArpOutput(String output, int network, int prefixLength, Map<String, String> hosts) {
        for (String line : output.split("\\R")) {
            java.util.regex.Matcher ipMatcher = IPV4_PATTERN.matcher(line);
            java.util.regex.Matcher macMatcher = MAC_PATTERN.matcher(line);
            if (!ipMatcher.find() || !macMatcher.find()) continue;
            String ip = ipMatcher.group(1);
            if (!isIpInNetwork(ip, network, prefixLength)) continue;
            String mac = macMatcher.group().toUpperCase().replace('-', ':');
            if ("00:00:00:00:00:00".equals(mac)) continue;
            hosts.put(ip, mac);
        }
    }

    private static boolean isIpInNetwork(String ip, int network, int prefixLength) {
        try {
            int value = ipToInt(ip);
            int mask = prefixLength == 0 ? 0 : (int) (0xFFFFFFFFL << (32 - prefixLength));
            return (value & mask) == network;
        } catch (Exception e) {
            return false;
        }
    }

    private static int compareIpv4(String a, String b) {
        return Integer.compareUnsigned(ipToInt(a), ipToInt(b));
    }

    /** Reads the OS ARP/neighbor cache to find the MAC address already learned for an IP. */
    private static String lookupArpMac(String ip) {
        try {
            boolean isWindows = System.getProperty("os.name").toLowerCase().contains("win");
            java.util.List<String> command = isWindows
                    ? java.util.List.of("arp", "-a", ip)
                    : java.util.List.of("sh", "-c", "ip neigh show " + ip + " 2>/dev/null || arp -n " + ip);

            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            boolean finished = process.waitFor(1000, TimeUnit.MILLISECONDS);
            if (!finished) {
                process.destroyForcibly();
                return null;
            }
            String output = new String(process.getInputStream().readAllBytes());
            java.util.regex.Matcher m = MAC_PATTERN.matcher(output);
            if (m.find()) {
                return m.group().toUpperCase().replace('-', ':');
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    private static volatile Map<String, String> ouiVendorTable;

    /** Best-effort vendor lookup from the MAC's OUI prefix (first 3 octets). */
    private static String lookupOuiVendor(String mac) {
        Map<String, String> table = ouiVendorTable;
        if (table == null) {
            table = loadOuiVendorTable();
            ouiVendorTable = table;
        }
        String prefix = mac.replace(":", "").substring(0, Math.min(6, mac.replace(":", "").length())).toUpperCase();
        return table.getOrDefault(prefix, "Unknown");
    }

    private static Map<String, String> loadOuiVendorTable() {
        Map<String, String> table = new java.util.HashMap<>();
        try (java.io.InputStream in = InfraMonitorAgent.class.getResourceAsStream("/oui-vendors.txt")) {
            if (in == null) return table;
            for (String line : new String(in.readAllBytes(), StandardCharsets.UTF_8).split("\\R")) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                int idx = line.indexOf('=');
                if (idx <= 0) continue;
                table.put(line.substring(0, idx).trim().toUpperCase(), line.substring(idx + 1).trim());
            }
        } catch (Exception e) {
            debug("Could not load OUI vendor table: " + e.getMessage());
        }
        return table;
    }

    private static int ipToInt(String ip) {
        String[] parts = ip.split("\\.");
        int result = 0;
        for (String part : parts) {
            result = (result << 8) | (Integer.parseInt(part) & 0xFF);
        }
        return result;
    }

    private static String intToIp(int ip) {
        return ((ip >> 24) & 0xFF) + "." + ((ip >> 16) & 0xFF) + "." + ((ip >> 8) & 0xFF) + "." + (ip & 0xFF);
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
                case "TRACEROUTE":
                    return traceroute(target, timeoutMs);
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
        return pingHost(target, timeoutMs, true);
    }

    private static long pingHostQuiet(String target, int timeoutMs) {
        return pingHost(target, timeoutMs, false);
    }

    private static long pingHost(String target, int timeoutMs, boolean verbose) {
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

                int timeoutSec = Math.max(1, (timeoutMs + 500) / 1000);  // OS flag is coarse; Java waitFor is the real cap.
                command = java.util.List.of("ping", "-c", "1", "-n", "-W", String.valueOf(timeoutSec), "-4", target);
            }

            if (verbose) debug("PING command: " + String.join(" ", command));
            long processStartNs = System.nanoTime();
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(true);
            Process process = pb.start();

            // Java's waitFor() is the actual timeout guarantee (not the OS ping flags).
            boolean finished = process.waitFor(Math.max(250, timeoutMs + 250), TimeUnit.MILLISECONDS);
            long processElapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - processStartNs);
            if (!finished) {
                process.destroyForcibly();
                process.waitFor(500, TimeUnit.MILLISECONDS);
                if (verbose) {
                    debug("PING timed out after processElapsedMs=" + processElapsedMs
                            + " javaTimeoutMs=" + Math.max(250, timeoutMs + 250));
                }
                return -1;  // Timeout exceeded
            }

            String output = new String(process.getInputStream().readAllBytes());
            int exitCode = process.exitValue();
            // Require both exit code 0 AND a TTL in the response — on Windows, "ping"
            // can return 0 even for "Destination host unreachable" replies.
            boolean hasTtl = output.toLowerCase().contains("ttl=");
            if (verbose) {
                debug("PING finished processElapsedMs=" + processElapsedMs
                        + " exitCode=" + exitCode
                        + " hasTtl=" + hasTtl
                        + " output=\"" + compact(output) + "\"");
            }
            if (exitCode != 0 || !hasTtl) {
                return -1;
            }

            java.util.regex.Matcher m = PING_RTT_PATTERN.matcher(output);
            if (m.find()) {
                long parsed = (long) Double.parseDouble(m.group(1));
                if (verbose) debug("PING parsedRttMs=" + parsed);
                return parsed;
            }
            // TTL present but couldn't parse RTT (unexpected format) — treat as 0ms rather
            // than fabricating a number from wall-clock time.
            if (verbose) debug("PING had TTL but RTT could not be parsed; returning 0ms");
            return 0;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            if (verbose) debug("PING interrupted: " + e.getMessage());
            return -1;
        } catch (Exception e) {
            // DNS resolution failed, network error, etc.
            if (verbose) debug("PING failed: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            return -1;
        }
    }

    // Matches a hop line's RTT, e.g. "1  2 ms  1 ms  1 ms  10.0.0.1" (Windows) or
    // "1  10.0.0.1  0.456 ms  0.398 ms  0.412 ms" (Linux/Mac).
    private static final java.util.regex.Pattern TRACEROUTE_HOP_PATTERN = java.util.regex.Pattern.compile(
            "^\\s*(\\d+)\\s");

    /**
     * Runs the OS traceroute/tracert binary and summarizes the hop count and total time.
     * Unlike PING, a single RTT number doesn't capture a multi-hop route, so the message
     * carries the hop count and the full path is returned so the UI can show it as a log.
     */
    // Hard ceiling independent of the requested timeoutMs: a multi-hop route with several
    // filtered/unreachable hops can otherwise run for minutes (maxHops × probes-per-hop ×
    // per-hop timeout). This keeps the agent's reply comfortably inside the backend's
    // end-to-end deadline for TRACEROUTE checks (see RemoteAgentController / AgentRegistryService).
    private static final int TRACEROUTE_MAX_HOPS = 16;
    private static final int TRACEROUTE_PER_HOP_TIMEOUT_MS = 1200;
    private static final long TRACEROUTE_OVERALL_TIMEOUT_MS = 20000L;

    private static CheckResult traceroute(String target, int timeoutMs) {
        long start = System.currentTimeMillis();
        try {
            boolean isWindows = System.getProperty("os.name").toLowerCase().contains("win");
            java.util.List<String> command = isWindows
                    ? java.util.List.of("tracert", "-d", "-h", String.valueOf(TRACEROUTE_MAX_HOPS),
                            "-w", String.valueOf(TRACEROUTE_PER_HOP_TIMEOUT_MS), target)
                    : java.util.List.of("traceroute", "-n", "-m", String.valueOf(TRACEROUTE_MAX_HOPS),
                            "-w", "1", target);

            debug("TRACEROUTE command: " + String.join(" ", command));
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(true);
            Process process = pb.start();

            boolean finished = process.waitFor(TRACEROUTE_OVERALL_TIMEOUT_MS, TimeUnit.MILLISECONDS);
            if (!finished) {
                process.destroyForcibly();
                process.waitFor(500, TimeUnit.MILLISECONDS);
                long latency = System.currentTimeMillis() - start;
                return new CheckResult("DOWN", latency, "Traceroute timed out after " + latency + "ms");
            }

            String output = new String(process.getInputStream().readAllBytes());
            long latency = System.currentTimeMillis() - start;
            int hopCount = 0;
            for (String line : output.split("\\R")) {
                if (TRACEROUTE_HOP_PATTERN.matcher(line).find()) hopCount++;
            }

            if (hopCount == 0) {
                return new CheckResult("DOWN", latency, "No route found to " + target);
            }
            String trimmedOutput = output.length() > 2000 ? output.substring(0, 2000) + "..." : output;
            return new CheckResult("UP", latency,
                    "Traceroute OK — " + hopCount + " hop(s) in " + latency + "ms\n" + trimmedOutput);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            long latency = System.currentTimeMillis() - start;
            return new CheckResult("DOWN", latency, "Traceroute interrupted");
        } catch (Exception e) {
            long latency = System.currentTimeMillis() - start;
            return new CheckResult("DOWN", latency,
                    "Traceroute error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
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
            StringBuilder out = new StringBuilder();
            boolean escaped = false;
            for (int i = valStart + 1; i < json.length(); i++) {
                char c = json.charAt(i);
                if (escaped) {
                    switch (c) {
                        case 'n':
                            out.append('\n');
                            break;
                        case 'r':
                            out.append('\r');
                            break;
                        case 't':
                            out.append('\t');
                            break;
                        case 'b':
                            out.append('\b');
                            break;
                        case 'f':
                            out.append('\f');
                            break;
                        case '"':
                        case '\\':
                        case '/':
                            out.append(c);
                            break;
                        case 'u':
                            if (i + 4 < json.length()) {
                                try {
                                    out.append((char) Integer.parseInt(json.substring(i + 1, i + 5), 16));
                                    i += 4;
                                } catch (NumberFormatException e) {
                                    out.append("\\u");
                                }
                            } else {
                                out.append("\\u");
                            }
                            break;
                        default:
                            out.append(c);
                            break;
                    }
                    escaped = false;
                } else if (c == '\\') {
                    escaped = true;
                } else if (c == '"') {
                    return out.toString();
                } else {
                    out.append(c);
                }
            }
            return null;
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
            if (isWindows()) return "cmd.exe";
            return Files.isExecutable(Path.of("/bin/bash")) ? "/bin/bash" : "/bin/sh";
        }

        java.util.List<String> shellCommand() {
            if (requestedShell != null && !requestedShell.isBlank()) {
                return java.util.List.of(requestedShell);
            }
            if (isWindows()) {
                return java.util.List.of("cmd.exe");
            }
            String shell = shellName();
            if (shell.endsWith("bash")) {
                return java.util.List.of(shell, "--noprofile", "--norc");
            }
            return java.util.List.of(shell);
        }

        void start() throws Exception {
            ProcessBuilder pb = new ProcessBuilder(shellCommand());
            pb.redirectErrorStream(false);
            pb.environment().put("TERM", "dumb");
            pb.environment().put("NO_COLOR", "1");
            pb.environment().put("CLICOLOR", "0");
            if (!isWindows()) {
                pb.environment().put("PS1", "$ ");
                pb.environment().put("PROMPT_COMMAND", "");
            }
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
