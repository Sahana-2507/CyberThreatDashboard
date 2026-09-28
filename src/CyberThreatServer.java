import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;

// 1. Model: Represents a Network Packet
class NetworkPacket {
    String sourceIp;
    String destIp;
    int port;
    String protocol;
    String payload;

    public NetworkPacket(String sourceIp, String destIp, int port, String protocol, String payload) {
        this.sourceIp = sourceIp;
        this.destIp = destIp;
        this.port = port;
        this.protocol = protocol;
        this.payload = payload;
    }
}

// 2. Model: Threat Incident
class ThreatAlert {
    String id;
    String timestamp;
    String threatType;
    String sourceIp;
    String severity;
    String description;
    String payload;

    public ThreatAlert(String threatType, String sourceIp, String severity, String description) {
        this(threatType, sourceIp, severity, description, "");
    }

    public ThreatAlert(String threatType, String sourceIp, String severity, String description, String payload) {
        this.id = UUID.randomUUID().toString().substring(0, 8);
        this.timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        this.threatType = threatType;
        this.sourceIp = sourceIp;
        this.severity = severity;
        this.description = description;
        this.payload = payload != null ? payload : "";
    }

    public String toJson() {
        return String.format(
            "{\"id\":\"%s\",\"timestamp\":\"%s\",\"type\":\"%s\",\"sourceIp\":\"%s\",\"severity\":\"%s\",\"desc\":\"%s\",\"payload\":\"%s\"}",
            id, timestamp, threatType, sourceIp, severity,
            escapeJson(description),
            escapeJson(payload)
        );
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\b", "\\b")
                .replace("\f", "\\f")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}

// 3. Module: Threat Analyzer
class ThreatAnalyzer {
    public Optional<ThreatAlert> inspect(NetworkPacket packet) {
        String p = packet.payload.toLowerCase();

        // Check for WICAR benign exploit test signatures
        if (p.contains("wicar.org") || p.contains("ms03-011") || p.contains("ms06-014") || p.contains("java-test.html") || p.contains("flash-test.html")) {
            return Optional.of(new ThreatAlert("Browser Exploit Test Signature", packet.sourceIp, "CRITICAL", "Identified WICAR exploit test artifact: " + packet.payload, packet.payload));
        }

        // Check for phishing / malicious links
        if (p.contains("facebook.com-login") || p.contains("free-gift") || p.contains("verify-account") || p.contains("bit.ly/malicious")) {
            return Optional.of(new ThreatAlert("Phishing URL Detected", packet.sourceIp, "HIGH", "Suspicious link targeting credentials: " + packet.payload, packet.payload));
        }

        // SQL Injection
        if (p.contains("' or '1'='1") || p.contains("select * from") || p.contains("union select") || p.contains("drop table")) {
            return Optional.of(new ThreatAlert("SQL Injection Attack", packet.sourceIp, "HIGH", "Malicious SQL syntax found in payload", packet.payload));
        }

        // Cross-Site Scripting (XSS)
        if (p.contains("<script>") || p.contains("alert(") || p.contains("javascript:")) {
            return Optional.of(new ThreatAlert("Cross-Site Scripting (XSS)", packet.sourceIp, "MEDIUM", "Executable client-side script found in input", packet.payload));
        }

        // Command Injection
        if (p.matches(".*(;|&&|\\|\\|).*") || p.matches(".*(cat\\s+/etc/passwd|whoami|powershell).*")) {
            return Optional.of(new ThreatAlert("Command Injection Attack", packet.sourceIp, "HIGH", "Shell command separators or system command execution detected", packet.payload));
        }

        // Directory/Path Traversal
        if (p.matches(".*(\\.\\./|\\.\\.\\\\|%2e%2e).*") || p.contains("../") || p.contains("..\\") || p.contains("%2e%2e")) {
            return Optional.of(new ThreatAlert("Directory Traversal Attack", packet.sourceIp, "HIGH", "Path traversal sequence detected in payload", packet.payload));
        }

        // Brute force / Auth bypass
        if (packet.port == 22 || p.contains("admin:password") || p.contains("failed login attempt")) {
            return Optional.of(new ThreatAlert("Authentication Abuse", packet.sourceIp, "HIGH", "Repeated credential probe pattern", packet.payload));
        }

        // Ransomware / Exploits
        if (packet.port == 445 || p.contains("smb_exploit") || p.contains(".exe download")) {
            return Optional.of(new ThreatAlert("Exploit Probe", packet.sourceIp, "CRITICAL", "Host inspection on vulnerable service", packet.payload));
        }

        // Low severity reconnaissance probe
        if (p.contains("scan=network_recon") || p.contains("recon_probe") || p.contains("ping probe")) {
            return Optional.of(new ThreatAlert("Reconnaissance Probe", packet.sourceIp, "LOW", "Informational network reconnaissance probe detected", packet.payload));
        }

        return Optional.empty();
    }
}

// 4. Module: Network Monitor (Background Traffic Simulator)
class NetworkMonitor implements Runnable {
    private final ThreatAnalyzer analyzer;
    private final List<ThreatAlert> alertLogs;
    private long totalPackets = 0;
    private final Random random = new Random();

    private final String[] sampleIps = {"192.168.1.45", "10.0.0.12", "172.16.0.99", "198.51.100.24", "203.0.113.5"};
    private final String[] normalPayloads = {"GET /index.html HTTP/1.1", "POST /api/login HTTP/1.1", "GET /static/style.css", "PING", "ACK"};
    private final String[] attackPayloads = {
        "GET /users?id=' OR '1'='1' HTTP/1.1",
        "POST /comment?msg=<script>alert(1)</script>",
        "admin:password failed login attempt",
        "GET /download/smb_exploit.exe",
        "GET http://wicar.org/data/ms06-014.html HTTP/1.1",
        "POST /api/exec cmd=ping 127.0.0.1; whoami",
        "GET /files?path=../../etc/passwd HTTP/1.1",
        "GET /probe?scan=network_recon HTTP/1.1"
    };

    public NetworkMonitor(ThreatAnalyzer analyzer, List<ThreatAlert> alertLogs) {
        this.analyzer = analyzer;
        this.alertLogs = alertLogs;
    }

    public long getTotalPackets() {
        return totalPackets;
    }

    public void incrementPacket() {
        totalPackets++;
    }

    @Override
    public void run() {
        while (true) {
            try {
                Thread.sleep(2500); // 1 packet every ~2.5s
                totalPackets++;

                boolean isAttack = random.nextInt(10) > 7; 
                String ip = sampleIps[random.nextInt(sampleIps.length)];
                String payload = isAttack ? attackPayloads[random.nextInt(attackPayloads.length)] : normalPayloads[random.nextInt(normalPayloads.length)];
                int port = isAttack ? 8080 : 443;

                NetworkPacket packet = new NetworkPacket(ip, "192.168.1.1", port, "TCP", payload);
                analyzer.inspect(packet).ifPresent(alert -> {
                    alertLogs.add(0, alert);
                    if (alertLogs.size() > 50) alertLogs.remove(alertLogs.size() - 1);
                    CyberThreatServer.broadcastAlert(alert);
                });
            } catch (InterruptedException e) {
                break;
            }
        }
    }
}

// 5. Main Server
public class CyberThreatServer {
    private static final List<ThreatAlert> alerts = new CopyOnWriteArrayList<>();
    private static final List<BlockingQueue<String>> sseSubscribers = new CopyOnWriteArrayList<>();
    private static final ThreatAnalyzer analyzer = new ThreatAnalyzer();
    private static final NetworkMonitor monitor = new NetworkMonitor(analyzer, alerts);

    public static void broadcastAlert(ThreatAlert alert) {
        String sseData = "data: " + alert.toJson() + "\n\n";
        for (BlockingQueue<String> queue : sseSubscribers) {
            queue.offer(sseData);
        }
    }

    public static void main(String[] args) throws IOException {
        new Thread(monitor).start();

        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.setExecutor(Executors.newCachedThreadPool());

        // GET /api/stream (Server-Sent Events)
        server.createContext("/api/stream", exchange -> {
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, OPTIONS");
            exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type");

            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(204, -1);
                return;
            }

            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            exchange.getResponseHeaders().set("Content-Type", "text/event-stream");
            exchange.getResponseHeaders().set("Cache-Control", "no-cache");
            exchange.getResponseHeaders().set("Connection", "keep-alive");
            exchange.sendResponseHeaders(200, 0); // 0 = chunked transfer encoding

            OutputStream os = exchange.getResponseBody();
            BlockingQueue<String> clientQueue = new LinkedBlockingQueue<>();
            sseSubscribers.add(clientQueue);

            try {
                // Initial connection acknowledgement comment
                os.write(": connected\n\n".getBytes(StandardCharsets.UTF_8));
                os.flush();

                while (true) {
                    String event = clientQueue.poll(15, TimeUnit.SECONDS);
                    if (event != null) {
                        os.write(event.getBytes(StandardCharsets.UTF_8));
                    } else {
                        // Periodic keep-alive heartbeat comment
                        os.write(": ping\n\n".getBytes(StandardCharsets.UTF_8));
                    }
                    os.flush();
                }
            } catch (Exception e) {
                // Client disconnected
            } finally {
                sseSubscribers.remove(clientQueue);
                try { os.close(); } catch (Exception ignored) {}
            }
        });

        // GET /api/stats
        server.createContext("/api/stats", exchange -> {
            long highCount = alerts.stream().filter(a -> a.severity.equalsIgnoreCase("HIGH") || a.severity.equalsIgnoreCase("CRITICAL")).count();
            long mediumCount = alerts.stream().filter(a -> a.severity.equalsIgnoreCase("MEDIUM")).count();
            long lowCount = alerts.stream().filter(a -> a.severity.equalsIgnoreCase("LOW")).count();

            StringBuilder alertJson = new StringBuilder("[");
            for (int i = 0; i < alerts.size(); i++) {
                alertJson.append(alerts.get(i).toJson());
                if (i < alerts.size() - 1) alertJson.append(",");
            }
            alertJson.append("]");

            String response = String.format(
                "{\"totalPackets\":%d,\"totalThreats\":%d,\"high\":%d,\"medium\":%d,\"low\":%d,\"alerts\":%s}",
                monitor.getTotalPackets(), alerts.size(), highCount, mediumCount, lowCount, alertJson
            );

            byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(bytes); }
        });

        // POST /api/analyze (Interactive inspection)
        server.createContext("/api/analyze", exchange -> {
            if ("POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                InputStreamReader reader = new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8);
                BufferedReader br = new BufferedReader(reader);
                StringBuilder body = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) body.append(line);

                String payload = body.toString();
                monitor.incrementPacket();

                NetworkPacket customPacket = new NetworkPacket("127.0.0.1 (Manual Test)", "192.168.1.1", 80, "HTTP", payload);
                Optional<ThreatAlert> detected = analyzer.inspect(customPacket);

                String jsonResponse;
                if (detected.isPresent()) {
                    ThreatAlert alert = detected.get();
                    alerts.add(0, alert);
                    if (alerts.size() > 50) alerts.remove(alerts.size() - 1);
                    broadcastAlert(alert);
                    jsonResponse = String.format("{\"threatDetected\":true,\"message\":\"Threat caught!\",\"alert\":%s}", alert.toJson());
                } else {
                    jsonResponse = "{\"threatDetected\":false,\"message\":\"Traffic analyzed: No known threats detected (Clean Packet).\"}";
                }

                byte[] bytes = jsonResponse.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, bytes.length);
                try (OutputStream os = exchange.getResponseBody()) { os.write(bytes); }
            }
        });

        // Static Files Handler
        server.createContext("/", exchange -> {
            String path = exchange.getRequestURI().getPath();
            if (path.equals("/")) path = "/index.html";

            File file = new File("web" + path);
            if (!file.exists()) {
                String notFound = "404 Not Found";
                exchange.sendResponseHeaders(404, notFound.length());
                try (OutputStream os = exchange.getResponseBody()) { os.write(notFound.getBytes()); }
                return;
            }

            String contentType = "text/plain";
            if (path.endsWith(".html")) contentType = "text/html";
            else if (path.endsWith(".css")) contentType = "text/css";
            else if (path.endsWith(".js")) contentType = "application/javascript";

            exchange.getResponseHeaders().set("Content-Type", contentType);
            exchange.sendResponseHeaders(200, file.length());
            try (FileInputStream fis = new FileInputStream(file); OutputStream os = exchange.getResponseBody()) {
                byte[] buffer = new byte[1024];
                int count;
                while ((count = fis.read(buffer)) >= 0) {
                    os.write(buffer, 0, count);
                }
            }
        });

        server.start();
        System.out.println("Threat Dashboard backend running at http://localhost:8080");
    }
}