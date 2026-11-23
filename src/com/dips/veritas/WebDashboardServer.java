package com.dips.veritas;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class WebDashboardServer {
    private static final String ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Pattern JSON_URL = Pattern.compile("\"url\"\\s*:\\s*\"([^\"]+)\"");

    private static final String LOGO_SVG =
            "<svg width='30' height='30' viewBox='0 0 32 32' fill='none' xmlns='http://www.w3.org/2000/svg'>"
            + "<rect width='32' height='32' rx='9' fill='#0f172a' stroke='#38bdf8' stroke-opacity='.45'/>"
            + "<path d='M9 9.5L16 23.5L23 9.5' stroke='#38bdf8' stroke-width='2.8' stroke-linecap='round' stroke-linejoin='round'/>"
            + "<path d='M13.2 9.5L16 15.2L18.8 9.5' stroke='#f8fafc' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round' stroke-opacity='.75'/>"
            + "</svg>";

    private static final String FAVICON_URI =
            "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'>"
            + "<rect width='32' height='32' rx='8' fill='%230b0e14'/>"
            + "<path d='M9 9.5L16 23.5L23 9.5' fill='none' stroke='%2338bdf8' stroke-width='3' stroke-linecap='round' stroke-linejoin='round'/></svg>";

    private final HttpServer server;
    private final int port;
    private final String token;
    private final String staffPin;
    private final boolean blockLocalhost;
    private final String lanUrl;
    private final String localUrl;
    private final String dashboardHtml;
    private final String txtContent;

    public WebDashboardServer(
            int port,
            boolean blockLocalhost,
            ReportWriter.FullReport report,
            List<ForensicAuditor.ServiceStatus> services,
            List<RecycleBinForensics.DeletedItem> trashItems,
            List<UsbForensics.UsbDevice> usbDevices,
            List<BrowserForensics.BrowserHit> browserHits,
            EnvironmentAuditor.EnvAudit envAudit,
            NetworkAuditor.NetAudit netAudit,
            String txtContent
    ) throws IOException {
        this.server = HttpServer.create(new InetSocketAddress(port), 0);
        this.port = this.server.getAddress().getPort();
        this.token = randomToken(16);
        this.staffPin = String.format(Locale.ROOT, "%06d", RANDOM.nextInt(1_000_000));
        this.blockLocalhost = blockLocalhost;
        this.lanUrl = "http://" + detectLanIp() + ":" + this.port + "/r/" + this.token;
        this.localUrl = "http://127.0.0.1:" + this.port + "/r/" + this.token;
        this.txtContent = txtContent;
        this.dashboardHtml = buildFullDashboardHtml(
                report, services, trashItems, usbDevices, browserHits, envAudit, netAudit, "/dl/" + this.token + "/log.txt"
        );
        this.server.setExecutor(Executors.newFixedThreadPool(4));
        registerRoutes();
    }

    public void start() {
        server.start();
    }

    public void stop() {
        server.stop(0);
    }

    public String lanUrl() {
        return lanUrl;
    }

    public String localUrl() {
        return localUrl;
    }

    public String staffPin() {
        return staffPin;
    }

    public String dashboardHtml() {
        return dashboardHtml;
    }

    public static String uploadPublicReport(String html, String reportId) {
        try {
            String boundary = "----VeritasReport" + UUID.randomUUID().toString().replace("-", "");
            ByteArrayOutputStream body = new ByteArrayOutputStream(html.length() + 512);
            String filename = "veritas-" + reportId.toLowerCase(Locale.ROOT) + ".html";
            String header = "--" + boundary + "\r\n"
                    + "Content-Disposition: form-data; name=\"file\"; filename=\"" + filename + "\"\r\n"
                    + "Content-Type: text/html\r\n\r\n";
            body.write(header.getBytes(StandardCharsets.UTF_8));
            body.write(html.getBytes(StandardCharsets.UTF_8));
            body.write(("\r\n--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8));

            HttpClient client = HttpClient.newBuilder()
                    .version(HttpClient.Version.HTTP_1_1)
                    .connectTimeout(Duration.ofSeconds(12))
                    .build();
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create("https://tmpfiles.org/api/v1/upload"))
                    .timeout(Duration.ofSeconds(30))
                    .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                    .header("Accept", "application/json")
                    .header("User-Agent", "Veritas/1.0")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(body.toByteArray()))
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (resp.statusCode() >= 200 && resp.statusCode() < 300) {
                Matcher m = JSON_URL.matcher(resp.body());
                if (m.find()) {
                    return m.group(1).replace("\\/", "/").replace("https://tmpfiles.org/", "https://tmpfiles.org/dl/");
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private void registerRoutes() {
        server.createContext("/r/" + token, this::handleDashboard);
        server.createContext("/dl/" + token + "/log.txt", this::handleTxtDownload);
        server.createContext("/", ex -> sendHtml(ex, 404, blockedPage("Invalid Link", "This Veritas staff session link is invalid or expired.")));
    }

    private void handleDashboard(HttpExchange ex) throws IOException {
        if (blockLocalhost && isLocalClient(ex)) {
            sendHtml(ex, 403, blockedPage(
                    "403 — Staff Only",
                    "Local access from the scanned machine is restricted. Open the Staff Link from the SS Staff PC."
            ));
            return;
        }
        if (blockLocalhost) {
            String q = ex.getRequestURI().getRawQuery();
            boolean ok = q != null && q.contains("pin=" + staffPin);
            if (!ok) {
                sendHtml(ex, 200, pinGatePage(q != null && q.contains("pin=")));
                return;
            }
        }
        sendHtml(ex, 200, dashboardHtml);
    }

    private void handleTxtDownload(HttpExchange ex) throws IOException {
        if (blockLocalhost && isLocalClient(ex)) {
            sendHtml(ex, 403, blockedPage("403 — Staff Only", "Local download is blocked in Staff-Only mode."));
            return;
        }
        byte[] bytes = txtContent.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        ex.getResponseHeaders().set("Content-Disposition", "attachment; filename=\"veritas-forensic-log.txt\"");
        ex.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    private boolean isLocalClient(HttpExchange ex) {
        InetAddress addr = ex.getRemoteAddress().getAddress();
        if (addr == null || addr.isLoopbackAddress()) {
            return true;
        }
        try {
            if (NetworkInterface.getByInetAddress(addr) != null) {
                return true;
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    private static String pinGatePage(boolean wrong) {
        String err = wrong ? "<p style='color:#f87171;font-size:13px;margin:8px 0 0'>Incorrect Staff PIN</p>" : "";
        return "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
                + "<link rel='icon' href=\"" + FAVICON_URI + "\"><title>Veritas — Staff Verification</title>"
                + "<style>body{margin:0;min-height:100vh;background:#080a0f;color:#f1f5f9;font-family:system-ui,-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;padding:20px;}"
                + "form{background:#0f1219;border:1px solid #1e2433;border-radius:18px;padding:34px;max-width:360px;width:100%;text-align:center;box-shadow:0 24px 64px rgba(0,0,0,.6);}"
                + ".em{display:inline-flex;margin-bottom:14px}h2{margin:0 0 6px;font-size:19px;letter-spacing:.08em}p{color:#94a3b8;font-size:13px;margin:0}"
                + "input{width:100%;padding:12px;border-radius:10px;border:1px solid #262e42;background:#080a0f;color:#fff;font-size:20px;letter-spacing:6px;text-align:center;margin:18px 0;font-family:monospace;outline:none;}"
                + "input:focus{border-color:#38bdf8}button{width:100%;padding:12px;border:none;border-radius:10px;background:#38bdf8;color:#080a0f;font-weight:700;cursor:pointer;font-size:14px;}</style></head>"
                + "<body><form method='GET'><div class='em'>" + LOGO_SVG + "</div><h2>VERITAS</h2><p>Enter the 6-digit Staff PIN to unlock this forensic report.</p>" + err
                + "<input type='password' name='pin' placeholder='000000' autofocus required>"
                + "<button type='submit'>Unlock Report</button></form></body></html>";
    }

    private static String blockedPage(String title, String message) {
        return "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
                + "<link rel='icon' href=\"" + FAVICON_URI + "\"><title>" + title + "</title>"
                + "<style>body{margin:0;min-height:100vh;background:#080a0f;color:#f1f5f9;font-family:system-ui,-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;padding:20px;}"
                + ".box{background:#0f1219;border:1px solid rgba(239,68,68,.45);border-radius:18px;padding:34px;max-width:430px;text-align:center;box-shadow:0 24px 64px rgba(0,0,0,.55);}"
                + ".em{display:inline-flex;margin-bottom:14px}h1{margin:0 0 10px;font-size:19px;color:#f87171}p{color:#94a3b8;font-size:14px;line-height:1.55;margin:0}</style></head>"
                + "<body><div class='box'><div class='em'>" + LOGO_SVG + "</div><h1>" + title + "</h1><p>" + message + "</p></div></body></html>";
    }

    private static void sendHtml(HttpExchange ex, int code, String html) throws IOException {
        byte[] bytes = html.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        ex.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static String randomToken(int len) {
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            sb.append(ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length())));
        }
        return sb.toString();
    }

    public static String detectLanIp() {
        try {
            Enumeration<NetworkInterface> ifaces = NetworkInterface.getNetworkInterfaces();
            while (ifaces.hasMoreElements()) {
                NetworkInterface ni = ifaces.nextElement();
                if (!ni.isUp() || ni.isLoopback() || ni.isVirtual()) {
                    continue;
                }
                String name = ni.getDisplayName().toLowerCase(Locale.ROOT);
                if (name.contains("virtual") || name.contains("vmware") || name.contains("vbox") || name.contains("hyper-v")) {
                    continue;
                }
                Enumeration<InetAddress> addrs = ni.getInetAddresses();
                while (addrs.hasMoreElements()) {
                    InetAddress addr = addrs.nextElement();
                    if (addr instanceof Inet4Address && !addr.isLoopbackAddress() && addr.isSiteLocalAddress()) {
                        return addr.getHostAddress();
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return "127.0.0.1";
    }

    public static String buildFullDashboardHtml(
            ReportWriter.FullReport r,
            List<ForensicAuditor.ServiceStatus> services,
            List<RecycleBinForensics.DeletedItem> trashItems,
            List<UsbForensics.UsbDevice> usbDevices,
            List<BrowserForensics.BrowserHit> browserHits,
            EnvironmentAuditor.EnvAudit envAudit,
            NetworkAuditor.NetAudit netAudit,
            String txtDownloadPath
    ) {
        StringBuilder findingRows = new StringBuilder();
        StringBuilder replaceRows = new StringBuilder();
        int replaceCount = 0;
        StringBuilder staffSummary = new StringBuilder();
        staffSummary.append("VERITAS | ID: ").append(r.verificationHash())
                .append(" | Verdict: ").append(r.verdict()).append(" (").append(r.score()).append("/100)")
                .append(" | Boot: ").append(r.systemBootTime()).append("\\n");

        if (r.findings().isEmpty()) {
            findingRows.append("<tr><td colspan='4' class='empty-cell'>CLEAN — No suspicious artifacts or cheats detected.</td></tr>");
        } else {
            for (Finding f : r.findings()) {
                staffSummary.append("[").append(f.severity()).append("] [").append(f.category()).append("] ")
                        .append(f.title()).append(" -> ").append(f.location()).append("\\n");
                String rowHtml = buildFindingRow(f);
                findingRows.append(rowHtml);
                if ("REPLACE_METHOD".equals(f.category()) || "TIMELINE_TAMPER".equals(f.category()) || "CHEAT_CONFIG".equals(f.category())) {
                    replaceRows.append(rowHtml);
                    replaceCount++;
                }
            }
        }
        if (replaceCount == 0) {
            replaceRows.append("<tr><td colspan='4' class='empty-cell'>CLEAN — No Replace Method, spoofed mods, or hidden cheat folders detected.</td></tr>");
        }

        StringBuilder instHtml = new StringBuilder();
        if (r.processes().isEmpty()) {
            instHtml.append("<div class='box'><span class='st-pill warn'>OFFLINE</span><p class='muted' style='margin:10px 0 0'>No active Minecraft Java process was running during this scan.</p></div>");
        } else {
            for (ProcessInspector.McProcess p : r.processes()) {
                instHtml.append("<div class='box'><div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:12px'>"
                        + "<strong>").append(esc(p.launcher())).append(" (").append(esc(p.mcVersion())).append(")</strong>"
                        + "<span class='st-pill ok'>IN-INSTANCE ACTIVE</span></div>"
                        + "<div class='ev-grid'>"
                        + "<span class='ev-chip'><b>PID</b> ").append(p.pid()).append("</span>"
                        + "<span class='ev-chip'><b>Process</b> ").append(esc(p.name())).append("</span>"
                        + "<span class='ev-chip'><b>Started</b> ").append(esc(p.startTime())).append("</span>"
                        + "<span class='ev-chip'><b>Modules</b> ").append(p.loadedModules().size()).append("</span>"
                        + "</div><div class='sub-loc' style='margin-top:12px'>").append(esc(p.commandLine())).append("</div></div>");
            }
        }

        StringBuilder svcRows = new StringBuilder();
        long stoppedSvc = 0;
        for (ForensicAuditor.ServiceStatus s : services) {
            boolean ok = s.status().toLowerCase(Locale.ROOT).startsWith("running");
            if (!ok) stoppedSvc++;
            svcRows.append("<tr><td><strong>").append(esc(s.name())).append("</strong></td>")
                    .append("<td><span class='st-pill ").append(ok ? "ok" : "bad").append("'>").append(esc(s.status())).append("</span></td>")
                    .append("<td>").append(s.critical() ? "<span class='cat-tag'>Critical SS</span>" : "<span class='muted'>Telemetry / Index</span>").append("</td></tr>");
        }

        StringBuilder trashRows = new StringBuilder();
        int lim = Math.min(trashItems.size(), 80);
        for (int i = 0; i < lim; i++) {
            RecycleBinForensics.DeletedItem it = trashItems.get(i);
            trashRows.append("<tr><td class='mono'>#").append(esc(it.id())).append("</td>")
                    .append("<td><strong>").append(esc(it.fileName())).append("</strong></td>")
                    .append("<td class='mono'>").append(esc(it.deletedAt().toString())).append("</td>")
                    .append("<td>").append(ConsoleUi.formatBytes(it.sizeBytes())).append("</td>")
                    .append("<td><span class='st-pill ").append(it.recoverable() ? "ok" : "warn").append("'>")
                    .append(it.recoverable() ? "RECOVERABLE" : "META-ONLY").append("</span></td>")
                    .append("<td class='mono muted'>").append(esc(it.originalPath())).append("</td></tr>");
        }

        StringBuilder usbRows = new StringBuilder();
        for (UsbForensics.UsbDevice d : usbDevices) {
            usbRows.append("<tr><td><span class='st-pill ").append(d.connected() ? "ok" : "warn").append("'>")
                    .append(d.connected() ? "CONNECTED" : "DISCONNECTED").append("</span></td>")
                    .append("<td><strong>").append(esc(d.name())).append("</strong></td>")
                    .append("<td class='mono'>").append(esc(d.driveLetter())).append("</td>")
                    .append("<td class='mono muted'>").append(esc(d.serial())).append("</td></tr>");
        }

        StringBuilder brRows = new StringBuilder();
        if (browserHits.isEmpty()) {
            brRows.append("<tr><td colspan='3' class='empty-cell'>CLEAN — No cheat domains found in Browser History or DNS Cache.</td></tr>");
        } else {
            for (BrowserForensics.BrowserHit h : browserHits) {
                brRows.append("<tr><td><span class='cat-tag'>").append(esc(h.source())).append("</span></td>")
                        .append("<td class='mono'><strong>").append(esc(h.domainOrUrl())).append("</strong></td>")
                        .append("<td class='muted'>").append(esc(h.note())).append("</td></tr>");
            }
        }

        StringBuilder altChips = new StringBuilder();
        if (r.mcAccounts().isEmpty()) {
            altChips.append("<span class='muted'>No launcher accounts detected.</span>");
        } else {
            for (String a : r.mcAccounts()) {
                altChips.append("<span class='chip'>").append(esc(a)).append("</span>");
            }
        }

        String hwModel = envAudit != null ? envAudit.hardwareModel() : "Physical PC";
        boolean isVm = envAudit != null && envAudit.isVm();
        String vpnText = (envAudit == null || envAudit.vpnAdapters().isEmpty()) ? "None detected" : String.join(", ", envAudit.vpnAdapters());
        int tcpCount = netAudit != null ? netAudit.listeningCount() : 0;

        String verdictColor = switch (r.verdict()) {
            case "CRITICAL" -> "#ef4444";
            case "HIGH" -> "#f97316";
            case "SUSPICIOUS" -> "#eab308";
            default -> "#22c55e";
        };
        int dashOffset = (int) Math.round(251.2 * (1.0 - (r.score() / 100.0)));

        String dlBtn = txtDownloadPath != null
                ? "<a class='act-btn primary' href='" + esc(txtDownloadPath) + "'>Download .TXT</a>"
                : "";

        return "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
                + "<link rel='icon' href=\"" + FAVICON_URI + "\"><title>Veritas — Forensic Dashboard</title>"
                + "<style>"
                + "*{box-sizing:border-box}body{margin:0;background:#080a0f;color:#e2e8f0;font-family:system-ui,-apple-system,Segoe UI,sans-serif;display:flex;min-height:100vh;}"
                + ".side{width:254px;background:#0c0f16;border-right:1px solid #1b2030;padding:22px 14px;display:flex;flex-direction:column;gap:4px;position:sticky;top:0;height:100vh;flex-shrink:0;overflow-y:auto;}"
                + ".brand{display:flex;align-items:center;gap:11px;padding:2px 10px 18px;border-bottom:1px solid #1b2030;margin-bottom:10px;}"
                + ".brand strong{font-size:15px;letter-spacing:.12em;color:#f8fafc}.brand small{display:block;font-size:11px;color:#64748b;font-family:monospace;margin-top:1px}"
                + ".nav-btn{position:relative;width:100%;display:flex;align-items:center;justify-content:space-between;background:transparent;border:none;outline:none;color:#94a3b8;padding:9px 12px;border-radius:9px;font-size:13px;font-weight:500;cursor:pointer;text-align:left;transition:background .15s,color .15s;}"
                + ".nav-btn:hover{background:#131824;color:#f1f5f9}"
                + ".nav-btn.active{background:#151c2c;color:#f8fafc;font-weight:600;}"
                + ".nav-btn.active::before{content:'';position:absolute;left:0;top:7px;bottom:7px;width:3px;border-radius:3px;background:#38bdf8;}"
                + ".cnt{font-family:monospace;font-size:11px;padding:2px 7px;border-radius:6px;background:#171d2b;color:#94a3b8;}"
                + ".nav-btn.active .cnt{background:rgba(56,189,248,.16);color:#38bdf8;}"
                + ".side-foot{margin-top:auto;padding-top:14px;border-top:1px solid #1b2030;font-family:monospace;font-size:11px;color:#64748b;line-height:1.65;padding-left:8px;}"
                + ".main{flex:1;padding:28px 34px;max-width:1320px;width:100%;overflow-x:hidden;}"
                + ".topbar{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:14px;margin-bottom:22px;}"
                + ".topbar h1{margin:0;font-size:21px;font-weight:700;color:#f8fafc;letter-spacing:-.02em}.topbar p{margin:4px 0 0;font-size:12px;color:#64748b;font-family:monospace;}"
                + ".actions{display:flex;gap:8px;flex-wrap:wrap;}"
                + ".act-btn{padding:8px 14px;border-radius:9px;border:1px solid #242c40;background:#10141f;color:#e2e8f0;font-size:12.5px;font-weight:600;cursor:pointer;text-decoration:none;outline:none;}"
                + ".act-btn:hover{border-color:#38bdf8;color:#fff}.act-btn.primary{background:#38bdf8;color:#080a0f;border-color:#38bdf8;}"
                + ".hero-grid{display:grid;grid-template-columns:220px 1fr;gap:14px;margin-bottom:22px;}"
                + ".gauge-card{background:#0f1219;border:1px solid #1b2030;border-radius:14px;padding:18px;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;}"
                + ".kpi-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;}"
                + ".kpi{background:#0f1219;border:1px solid #1b2030;border-radius:13px;padding:15px 17px;display:flex;flex-direction:column;justify-content:center;}"
                + ".kpi span{font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;color:#64748b;font-family:monospace;}"
                + ".kpi strong{font-size:19px;color:#f8fafc;margin-top:6px;}"
                + ".toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:14px;}"
                + ".f-pill{background:#0f1219;border:1px solid #1b2030;color:#94a3b8;padding:6px 12px;border-radius:8px;font-size:12px;font-weight:600;cursor:pointer;outline:none;}"
                + ".f-pill.active{background:#f8fafc;color:#080a0f;border-color:#f8fafc;}"
                + ".search{flex:1;min-width:200px;background:#0f1219;border:1px solid #1b2030;color:#f8fafc;padding:8px 13px;border-radius:9px;font-size:13px;outline:none;}"
                + ".search:focus{border-color:#38bdf8}"
                + ".table-wrap{background:#0f1219;border:1px solid #1b2030;border-radius:14px;overflow-x:auto;}"
                + "table{width:100%;border-collapse:collapse;font-size:13px;}th{text-align:left;padding:12px 16px;font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;color:#64748b;background:#0c0f16;border-bottom:1px solid #1b2030;}"
                + "td{padding:14px 16px;border-bottom:1px solid #161b28;vertical-align:top;}tr:last-child td{border-bottom:none;}tr:hover td{background:#121724;}"
                + ".sev-pill{display:inline-block;padding:3px 9px;border-radius:6px;font-size:10.5px;font-weight:700;font-family:monospace;letter-spacing:.04em;}"
                + ".sev-pill.critical{background:rgba(239,68,68,.16);color:#f87171;border:1px solid rgba(239,68,68,.32);}"
                + ".sev-pill.high{background:rgba(249,115,22,.16);color:#fb923c;border:1px solid rgba(249,115,22,.32);}"
                + ".sev-pill.suspicious{background:rgba(234,179,8,.14);color:#facc15;border:1px solid rgba(234,179,8,.32);}"
                + ".sev-pill.info{background:rgba(56,189,248,.14);color:#38bdf8;border:1px solid rgba(56,189,248,.32);}"
                + ".st-pill{display:inline-block;padding:3px 9px;border-radius:6px;font-size:11px;font-weight:700;font-family:monospace;}"
                + ".st-pill.ok{background:rgba(34,197,94,.14);color:#4ade80;}.st-pill.bad{background:rgba(239,68,68,.16);color:#f87171;}.st-pill.warn{background:rgba(234,179,8,.14);color:#facc15;}"
                + ".cat-tag{font-family:monospace;font-size:11px;color:#38bdf8;background:rgba(56,189,248,.09);border:1px solid rgba(56,189,248,.2);padding:3px 8px;border-radius:6px;}"
                + ".sub-loc{font-family:monospace;font-size:11px;color:#64748b;margin-top:5px;word-break:break-all;}"
                + ".ev-grid{display:flex;flex-wrap:wrap;gap:6px;}"
                + ".ev-chip{display:inline-flex;align-items:center;gap:5px;background:#141926;border:1px solid #222a3d;border-radius:7px;padding:4px 9px;font-size:11.5px;color:#cbd5e1;font-family:monospace;}"
                + ".ev-chip b{color:#38bdf8;font-weight:600;}"
                + ".mono{font-family:monospace;font-size:12px;word-break:break-all;}.muted{color:#64748b;}"
                + ".empty-cell{text-align:center;padding:28px;color:#4ade80;font-weight:600;}"
                + ".panel{display:none;}.panel.active{display:block;}"
                + ".box{background:#0f1219;border:1px solid #1b2030;border-radius:14px;padding:20px;margin-bottom:14px;}"
                + ".chips{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px;}.chip{font-family:monospace;font-size:12px;background:#141926;border:1px solid #222a3d;padding:5px 11px;border-radius:8px;color:#e2e8f0;}"
                + "@media(max-width:920px){body{flex-direction:column}.side{width:100%;height:auto;position:static}.hero-grid{grid-template-columns:1fr}.kpi-grid{grid-template-columns:repeat(2,1fr)}.main{padding:18px}}"
                + "</style></head><body>"
                + "<aside class='side'>"
                + "<div class='brand'>" + LOGO_SVG + "<div><strong>VERITAS</strong><small>SS Forensics</small></div></div>"
                + "<button class='nav-btn active' data-t='p-find'><span>All Findings</span><span class='cnt'>" + r.findings().size() + "</span></button>"
                + "<button class='nav-btn' data-t='p-inst'><span>MC Instance</span><span class='cnt'>" + r.processes().size() + "</span></button>"
                + "<button class='nav-btn' data-t='p-rep'><span>Replace &amp; Configs</span><span class='cnt'>" + replaceCount + "</span></button>"
                + "<button class='nav-btn' data-t='p-svc'><span>Windows Services</span><span class='cnt'>" + services.size() + "</span></button>"
                + "<button class='nav-btn' data-t='p-trash'><span>Recycle Bin</span><span class='cnt'>" + trashItems.size() + "</span></button>"
                + "<button class='nav-btn' data-t='p-usb'><span>USB History</span><span class='cnt'>" + usbDevices.size() + "</span></button>"
                + "<button class='nav-btn' data-t='p-br'><span>Browser &amp; DNS</span><span class='cnt'>" + browserHits.size() + "</span></button>"
                + "<button class='nav-btn' data-t='p-env'><span>VM, VPN &amp; Net</span><span class='cnt'>" + tcpCount + "</span></button>"
                + "<button class='nav-btn' data-t='p-alts'><span>Alts &amp; Macros</span><span class='cnt'>" + r.mcAccounts().size() + "</span></button>"
                + "<div class='side-foot'>ID: " + esc(r.verificationHash()) + "<br>OS: " + esc(r.osName()) + "<br>Boot: " + esc(r.systemBootTime()) + "</div>"
                + "</aside>"
                + "<main class='main'>"
                + "<div class='topbar'><div><h1>Forensic Inspection Report</h1><p>ID " + esc(r.verificationHash()) + " · " + esc(r.timestamp()) + "</p></div>"
                + "<div class='actions'><button class='act-btn' id='cpBtn'>Copy Staff Summary</button>" + dlBtn + "</div></div>"
                + "<div class='hero-grid'>"
                + "<div class='gauge-card'><svg width='96' height='96' viewBox='0 0 100 100'>"
                + "<circle cx='50' cy='50' r='40' fill='none' stroke='#1b2030' stroke-width='8.5'/>"
                + "<circle cx='50' cy='50' r='40' fill='none' stroke='" + verdictColor + "' stroke-width='8.5' stroke-dasharray='251.2' stroke-dashoffset='" + dashOffset + "' stroke-linecap='round' transform='rotate(-90 50 50)'/>"
                + "<text x='50' y='55' text-anchor='middle' fill='#f8fafc' font-size='21' font-weight='700' font-family='monospace'>" + r.score() + "</text></svg>"
                + "<strong style='margin-top:8px;color:" + verdictColor + ";letter-spacing:.06em;font-size:14px'>" + esc(r.verdict()) + "</strong>"
                + "<span class='muted' style='font-size:11px;margin-top:2px'>Risk Score / 100</span></div>"
                + "<div class='kpi-grid'>"
                + "<div class='kpi'><span>Minecraft Instance</span><strong style='color:" + (r.processes().isEmpty() ? "#facc15" : "#4ade80") + "'>" + (r.processes().isEmpty() ? "OFFLINE" : "ACTIVE") + "</strong></div>"
                + "<div class='kpi'><span>Findings</span><strong>" + r.findings().size() + "</strong></div>"
                + "<div class='kpi'><span>Services Checked</span><strong>" + services.size() + " (" + stoppedSvc + " stopped)</strong></div>"
                + "<div class='kpi'><span>JARs / Binaries</span><strong>" + r.jarsScanned() + " / " + r.binariesScanned() + "</strong></div>"
                + "<div class='kpi'><span>Recycle Bin</span><strong>" + trashItems.size() + " items</strong></div>"
                + "<div class='kpi'><span>USB Devices</span><strong>" + r.usbConnected() + " active / " + r.usbHistory() + " hist</strong></div>"
                + "</div></div>"
                + "<section id='p-find' class='panel active'>"
                + "<div class='toolbar'>"
                + "<button class='f-pill active' data-f='all'>All</button>"
                + "<button class='f-pill' data-f='critical'>Critical</button>"
                + "<button class='f-pill' data-f='high'>High</button>"
                + "<button class='f-pill' data-f='suspicious'>Suspicious</button>"
                + "<button class='f-pill' data-f='info'>Info</button>"
                + "<input class='search' id='qIn' placeholder='Search findings, paths, hashes...'></div>"
                + "<div class='table-wrap'><table><thead><tr><th>Severity</th><th>Category</th><th>Finding &amp; Path</th><th>Evidence</th></tr></thead><tbody>" + findingRows + "</tbody></table></div></section>"
                + "<section id='p-inst' class='panel'>" + instHtml + "</section>"
                + "<section id='p-rep' class='panel'><div class='table-wrap'><table><thead><tr><th>Severity</th><th>Category</th><th>Finding &amp; Path</th><th>Evidence</th></tr></thead><tbody>" + replaceRows + "</tbody></table></div></section>"
                + "<section id='p-svc' class='panel'><div class='table-wrap'><table><thead><tr><th>Service</th><th>Status</th><th>Classification</th></tr></thead><tbody>" + svcRows + "</tbody></table></div></section>"
                + "<section id='p-trash' class='panel'><div class='table-wrap'><table><thead><tr><th>ID</th><th>File Name</th><th>Deleted At</th><th>Size</th><th>State</th><th>Original Path</th></tr></thead><tbody>" + trashRows + "</tbody></table></div></section>"
                + "<section id='p-usb' class='panel'><div class='table-wrap'><table><thead><tr><th>State</th><th>Device</th><th>Drive</th><th>Serial Number</th></tr></thead><tbody>" + usbRows + "</tbody></table></div></section>"
                + "<section id='p-br' class='panel'><div class='table-wrap'><table><thead><tr><th>Source</th><th>Domain / URL</th><th>Evidence</th></tr></thead><tbody>" + brRows + "</tbody></table></div></section>"
                + "<section id='p-env' class='panel'><div class='box'><strong>System &amp; Network Environment</strong>"
                + "<div class='ev-grid' style='margin-top:12px'>"
                + "<span class='ev-chip'><b>Hardware</b> " + esc(hwModel) + "</span>"
                + "<span class='ev-chip'><b>VM</b> " + (isVm ? "DETECTED" : "Physical") + "</span>"
                + "<span class='ev-chip'><b>VPN</b> " + esc(vpnText) + "</span>"
                + "<span class='ev-chip'><b>TCP Listeners</b> " + tcpCount + "</span>"
                + "</div></div></section>"
                + "<section id='p-alts' class='panel'><div class='box'><strong>Minecraft Accounts / Alts (" + r.mcAccounts().size() + ")</strong><div class='chips'>" + altChips + "</div></div>"
                + "<div class='box'><strong>Gaming Mouse &amp; Macro Software</strong><p class='mono' style='margin:10px 0 0'>" + (r.mouseSoftware().isEmpty() ? "None detected" : esc(String.join(", ", r.mouseSoftware()))) + "</p></div></section>"
                + "</main><script>"
                + "document.querySelectorAll('.nav-btn').forEach(b=>b.onclick=()=>{document.querySelectorAll('.nav-btn').forEach(x=>x.classList.remove('active'));document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));b.classList.add('active');document.getElementById(b.dataset.t).classList.add('active');});"
                + "let cur='all';const rows=[...document.querySelectorAll('#p-find .f-row')];"
                + "const apply=()=>{const q=document.getElementById('qIn').value.toLowerCase();rows.forEach(r=>{const okS=cur==='all'||r.dataset.sev===cur;const okQ=!q||r.textContent.toLowerCase().includes(q);r.style.display=okS&&okQ?'':'none';});};"
                + "document.querySelectorAll('.f-pill').forEach(b=>b.onclick=()=>{document.querySelectorAll('.f-pill').forEach(x=>x.classList.remove('active'));b.classList.add('active');cur=b.dataset.f;apply();});"
                + "document.getElementById('qIn').oninput=apply;"
                + "document.getElementById('cpBtn').onclick=async()=>{await navigator.clipboard.writeText(\"" + escJson(staffSummary.toString()) + "\");document.getElementById('cpBtn').textContent='Copied!';setTimeout(()=>document.getElementById('cpBtn').textContent='Copy Staff Summary',1800);};"
                + "</script></body></html>";
    }

    private static String buildFindingRow(Finding f) {
        String sevLow = f.severity().toLowerCase(Locale.ROOT);
        StringBuilder chips = new StringBuilder("<div class='ev-grid'>");
        for (String d : f.details()) {
            int colon = d.indexOf(':');
            if (colon > 0 && colon < 34) {
                String k = d.substring(0, colon).trim();
                String v = d.substring(colon + 1).trim();
                chips.append("<span class='ev-chip'><b>").append(esc(k)).append("</b> ").append(esc(v)).append("</span>");
            } else {
                chips.append("<span class='ev-chip'>").append(esc(d)).append("</span>");
            }
        }
        chips.append("</div>");
        return "<tr class='f-row' data-sev='" + sevLow + "'>"
                + "<td><span class='sev-pill " + sevLow + "'>" + esc(f.severity()) + "</span></td>"
                + "<td><span class='cat-tag'>" + esc(f.category()) + "</span></td>"
                + "<td><strong>" + esc(f.title()) + "</strong><div class='sub-loc'>" + esc(f.location()) + "</div></td>"
                + "<td>" + chips + "</td></tr>";
    }

    private static String esc(String s) {
        return s == null ? "" : s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    private static String escJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "");
    }
}
