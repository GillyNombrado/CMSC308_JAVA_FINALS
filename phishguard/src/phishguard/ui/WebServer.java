package phishguard.ui;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import phishguard.risk.PhishGuardEngine;
import phishguard.risk.RiskResult;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;

public class WebServer {

    private static final int PORT = 8080;
    private static final Path WEB_DIR = findWebDir();

    /** Uses a "web" folder if you have one, otherwise the ui folder inside src. */
    private static Path findWebDir() {
        Path web = Paths.get("web");
        Path ui = Paths.get("src", "phishguard", "ui");
        return (Files.isDirectory(web) ? web : ui).toAbsolutePath().normalize();
    }
    private static final int MAX_BODY = 20_000;

    public static void main(String[] args) throws Exception {
        System.out.println("Training the URL model (a few seconds)...");
        PhishGuardEngine engine = PhishGuardEngine.createDefault();

        // Bound to localhost only, so other computers on the network cannot reach it
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", PORT), 0);
        server.createContext("/api/analyze", ex -> handleAnalyze(ex, engine));
        server.createContext("/", WebServer::handleStatic);
        server.setExecutor(Executors.newFixedThreadPool(4));
        server.start();

        System.out.println("PhishGuard is running at http://localhost:" + PORT);
        System.out.println("Serving UI files from: " + WEB_DIR);
        System.out.println("Press Ctrl+C to stop.");
    }

    // ---------- API ----------

    private static void handleAnalyze(HttpExchange ex, PhishGuardEngine engine) throws java.io.IOException {
        try {
            addCors(ex);
            if ("OPTIONS".equals(ex.getRequestMethod())) { send(ex, 204, "text/plain", new byte[0]); return; }
            if (!"POST".equals(ex.getRequestMethod())) { sendJson(ex, 405, "{\"error\":\"Use POST\"}"); return; }

            String body = readBody(ex.getRequestBody());
            if (body == null) { sendJson(ex, 413, "{\"error\":\"Request too large\"}"); return; }

            Map<String, String> in = parseFlatJson(body);
            String url = in.get("url");
            String message = in.get("message");
            boolean noUrl = url == null || url.trim().isEmpty();
            boolean noMsg = message == null || message.trim().isEmpty();
            if (noUrl && noMsg) {
                sendJson(ex, 400, "{\"error\":\"Enter a link, a message, or both.\"}");
                return;
            }

            RiskResult r = noUrl ? engine.analyzeMessageOnly(message) : engine.analyze(url, message);
            sendJson(ex, 200, toJson(r));
        } catch (IllegalArgumentException e) {
            sendJson(ex, 400, "{\"error\":" + q(e.getMessage()) + "}");
        } catch (Exception e) {
            e.printStackTrace();
            sendJson(ex, 500, "{\"error\":\"Server error\"}");
        }
    }

    private static String toJson(RiskResult r) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"score\":").append(Math.round(r.score)).append(",");
        sb.append("\"level\":").append(q(r.level())).append(",");
        sb.append("\"urlScore\":").append(r.urlScore < 0 ? "null" : String.valueOf(Math.round(r.urlScore))).append(",");
        sb.append("\"textScore\":").append(r.hasMessage ? String.valueOf(Math.round(r.textScore)) : "null").append(",");
        sb.append("\"hasMessage\":").append(r.hasMessage).append(",");
        sb.append("\"brandStatus\":").append(q(r.brand.status.name())).append(",");
        sb.append("\"brandReason\":").append(q(r.brand.reason)).append(",");
        sb.append("\"advice\":").append(q(r.advice())).append(",");
        sb.append("\"reasons\":[");
        for (int i = 0; i < r.reasons.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append(q(r.reasons.get(i)));
        }
        sb.append("]}");
        return sb.toString();
    }

    // ---------- Static files (your HTML/CSS/JS in the web folder) ----------

    private static void handleStatic(HttpExchange ex) throws java.io.IOException {
        try {
            addCors(ex);
            String p = ex.getRequestURI().getPath();
            if (p.equals("/")) p = "/index.html";
            Path file = WEB_DIR.resolve(p.substring(1)).normalize();
            // Block path traversal such as /../secret
            if (!file.startsWith(WEB_DIR) || !Files.isRegularFile(file) || contentType(file.toString()) == null) {
                send(ex, 404, "text/plain; charset=utf-8", "Not found".getBytes(StandardCharsets.UTF_8));
                return;
            }
            send(ex, 200, contentType(file.toString()), Files.readAllBytes(file));
        } catch (Exception e) {
            e.printStackTrace();
            send(ex, 500, "text/plain", "Server error".getBytes(StandardCharsets.UTF_8));
        }
    }

    private static String contentType(String name) {
        String n = name.toLowerCase();
        if (n.endsWith(".html")) return "text/html; charset=utf-8";
        if (n.endsWith(".css"))  return "text/css; charset=utf-8";
        if (n.endsWith(".js"))   return "application/javascript; charset=utf-8";
        if (n.endsWith(".json")) return "application/json; charset=utf-8";
        if (n.endsWith(".svg"))  return "image/svg+xml";
        if (n.endsWith(".png"))  return "image/png";
        if (n.endsWith(".jpg") || n.endsWith(".jpeg")) return "image/jpeg";
        if (n.endsWith(".ico"))  return "image/x-icon";
        return null;   // unknown types (such as .java source files) are never served
    }

    // ---------- Helpers ----------

    private static void addCors(HttpExchange ex) {
        // Lets the UI work even if the HTML file is opened directly from disk
        ex.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
        ex.getResponseHeaders().add("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
        ex.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type");
    }

    private static void sendJson(HttpExchange ex, int code, String json) throws java.io.IOException {
        send(ex, code, "application/json; charset=utf-8", json.getBytes(StandardCharsets.UTF_8));
    }

    private static void send(HttpExchange ex, int code, String type, byte[] data) throws java.io.IOException {
        ex.getResponseHeaders().set("Content-Type", type);
        if (code == 204) { ex.sendResponseHeaders(204, -1); ex.close(); return; }
        ex.sendResponseHeaders(code, data.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(data); }
    }

    private static String readBody(InputStream in) throws java.io.IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] chunk = new byte[2048];
        int n, total = 0;
        while ((n = in.read(chunk)) > 0) {
            total += n;
            if (total > MAX_BODY) return null;
            buf.write(chunk, 0, n);
        }
        return new String(buf.toByteArray(), StandardCharsets.UTF_8);
    }

    /** JSON string literal with proper escaping. */
    private static String q(String s) {
        if (s == null) return "\"\"";
        StringBuilder sb = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        return sb.append("\"").toString();
    }

    /** Minimal parser for a flat JSON object like {"url":"...","message":"..."}. Non-string values are ignored. */
    static Map<String, String> parseFlatJson(String s) {
        Map<String, String> out = new HashMap<>();
        int[] i = {0};
        skipWs(s, i);
        if (i[0] >= s.length() || s.charAt(i[0]) != '{') return out;
        i[0]++;
        while (true) {
            skipWs(s, i);
            if (i[0] >= s.length() || s.charAt(i[0]) == '}') break;
            if (s.charAt(i[0]) == ',') { i[0]++; continue; }
            if (s.charAt(i[0]) != '"') break;
            String key = readString(s, i);
            skipWs(s, i);
            if (i[0] >= s.length() || s.charAt(i[0]) != ':') break;
            i[0]++;
            skipWs(s, i);
            if (i[0] < s.length() && s.charAt(i[0]) == '"') {
                out.put(key, readString(s, i));
            } else {
                while (i[0] < s.length() && ",}".indexOf(s.charAt(i[0])) < 0) i[0]++;   // skip numbers, null, true, false
            }
        }
        return out;
    }

    private static void skipWs(String s, int[] i) {
        while (i[0] < s.length() && Character.isWhitespace(s.charAt(i[0]))) i[0]++;
    }

    private static String readString(String s, int[] i) {
        StringBuilder sb = new StringBuilder();
        i[0]++;                                           // opening quote
        while (i[0] < s.length()) {
            char c = s.charAt(i[0]++);
            if (c == '"') break;
            if (c == '\\' && i[0] < s.length()) {
                char e = s.charAt(i[0]++);
                switch (e) {
                    case 'n': sb.append('\n'); break;
                    case 'r': sb.append('\r'); break;
                    case 't': sb.append('\t'); break;
                    case 'u':
                        if (i[0] + 4 <= s.length()) {
                            try { sb.append((char) Integer.parseInt(s.substring(i[0], i[0] + 4), 16)); } catch (Exception ignored) { }
                            i[0] += 4;
                        }
                        break;
                    default: sb.append(e);               // covers \" \\ \/
                }
            } else sb.append(c);
        }
        return sb.toString();
    }
}