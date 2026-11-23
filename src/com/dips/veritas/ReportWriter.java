package com.dips.veritas;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.List;
import java.util.Locale;

public final class ReportWriter {
    public record FullReport(
            String version,
            String osName,
            String systemBootTime,
            String timestamp,
            double elapsedSeconds,
            int score,
            String verdict,
            String verificationHash,
            List<ProcessInspector.McProcess> processes,
            int jarsScanned,
            int binariesScanned,
            int recycleItems,
            int usbConnected,
            int usbHistory,
            int browsersChecked,
            List<String> mcAccounts,
            List<String> mouseSoftware,
            List<Finding> findings
    ) {
    }

    private ReportWriter() {
    }

    public static String computeVerificationHash(String timestamp, int score, List<Finding> findings) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update((timestamp + "|" + score + "|" + findings.size()).getBytes(StandardCharsets.UTF_8));
            for (Finding f : findings) {
                md.update((f.category() + "|" + f.severity() + "|" + f.location()).getBytes(StandardCharsets.UTF_8));
            }
            byte[] h = md.digest();
            StringBuilder sb = new StringBuilder(16);
            for (int i = 0; i < 8; i++) {
                sb.append(String.format(Locale.ROOT, "%02X", h[i]));
            }
            return sb.toString();
        } catch (Exception e) {
            return "0000000000000000";
        }
    }

    public static void printConsole(FullReport r) {
        System.out.println();
        System.out.println(ConsoleUi.bold(ConsoleUi.blue("---------------------- VERITAS SUMMARY ----------------------")));
        System.out.println("  " + ConsoleUi.blue("Platform   :") + " " + ConsoleUi.white(r.osName()));
        System.out.println("  " + ConsoleUi.blue("Last Boot  :") + " " + ConsoleUi.cyan(r.systemBootTime()));
        if (r.processes().isEmpty()) {
            System.out.println("  " + ConsoleUi.blue("Instance   :") + " " + ConsoleUi.yellow("OFFLINE (No active Minecraft process detected)"));
        } else {
            System.out.println("  " + ConsoleUi.blue("Instance   :") + " " + ConsoleUi.bold(ConsoleUi.green("IN-INSTANCE ACTIVE (" + r.processes().size() + " process)")));
            for (ProcessInspector.McProcess p : r.processes()) {
                System.out.println("    " + ConsoleUi.cyan("->") + " " + ConsoleUi.bold(p.launcher())
                        + " | Ver: " + ConsoleUi.cyan(p.mcVersion())
                        + " | PID: " + p.pid()
                        + " | Started: " + ConsoleUi.yellow(p.startTime())
                        + " | Modules: " + p.loadedModules().size());
            }
        }
        System.out.println("  " + ConsoleUi.blue("JARs       :") + " " + r.jarsScanned() + " inspected");
        System.out.println("  " + ConsoleUi.blue("Binaries   :") + " " + r.binariesScanned() + " inspected");
        System.out.println("  " + ConsoleUi.blue("RecycleBin :") + " " + ConsoleUi.magenta(r.recycleItems() + " deleted item(s) indexed"));
        System.out.println("  " + ConsoleUi.blue("USB Drives :") + " " + ConsoleUi.cyan(r.usbConnected() + " connected") + " / " + ConsoleUi.yellow(r.usbHistory() + " historical"));
        System.out.println("  " + ConsoleUi.blue("Browsers   :") + " " + r.browsersChecked() + " profile(s) + DNS/Quarantine");
        System.out.println("  " + ConsoleUi.blue("MC Alts    :") + " " + (r.mcAccounts().isEmpty() ? "None found" : ConsoleUi.cyan(String.join(", ", r.mcAccounts()))));
        System.out.println("  " + ConsoleUi.blue("Mouse SW   :") + " " + (r.mouseSoftware().isEmpty() ? "None detected" : ConsoleUi.yellow(String.join(", ", r.mouseSoftware()))));
        System.out.printf(Locale.ROOT, "  %s %.2f s%n", ConsoleUi.blue("Duration   :"), r.elapsedSeconds());
        System.out.println("  " + ConsoleUi.blue("Report ID  :") + " " + ConsoleUi.cyan(r.verificationHash()));
        System.out.println("  " + ConsoleUi.blue("Verdict    :") + " [" + ConsoleUi.severityBadge(r.verdict()) + "]  Score " + r.score() + "/100");
        System.out.println(ConsoleUi.bold(ConsoleUi.blue("-------------------------------------------------------------")));

        if (r.findings().isEmpty()) {
            System.out.println("\n  " + ConsoleUi.bold(ConsoleUi.green("CLEAN: No cheats, injections, or bypass traces detected.")));
            return;
        }

        for (Finding f : r.findings()) {
            System.out.println();
            String catColor = switch (f.severity()) {
                case "CRITICAL", "HIGH" -> ConsoleUi.red(f.category());
                case "SUSPICIOUS" -> ConsoleUi.yellow(f.category());
                default -> ConsoleUi.cyan(f.category());
            };
            System.out.println("  [" + ConsoleUi.severityBadge(f.severity()) + "] [" + catColor + "] " + ConsoleUi.bold(f.title()));
            System.out.println("    " + ConsoleUi.dim("Location :") + " " + ConsoleUi.white(f.location()));
            for (String d : f.details()) {
                System.out.println("    " + ConsoleUi.cyan("-") + " " + d);
            }
        }
    }

    public static void writeJson(Path path, FullReport r) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"tool\": \"veritas\",\n");
        sb.append("  \"version\": \"").append(r.version()).append("\",\n");
        sb.append("  \"reportId\": \"").append(r.verificationHash()).append("\",\n");
        sb.append("  \"os\": \"").append(escJson(r.osName())).append("\",\n");
        sb.append("  \"systemBootTime\": \"").append(escJson(r.systemBootTime())).append("\",\n");
        sb.append("  \"inInstance\": ").append(!r.processes().isEmpty()).append(",\n");
        sb.append("  \"timestamp\": \"").append(r.timestamp()).append("\",\n");
        sb.append("  \"score\": ").append(r.score()).append(",\n");
        sb.append("  \"verdict\": \"").append(r.verdict()).append("\",\n");
        sb.append("  \"findings\": [\n");
        for (int i = 0; i < r.findings().size(); i++) {
            Finding f = r.findings().get(i);
            sb.append("    {\n");
            sb.append("      \"category\": \"").append(escJson(f.category())).append("\",\n");
            sb.append("      \"severity\": \"").append(escJson(f.severity())).append("\",\n");
            sb.append("      \"weight\": ").append(f.weight()).append(",\n");
            sb.append("      \"title\": \"").append(escJson(f.title())).append("\",\n");
            sb.append("      \"location\": \"").append(escJson(f.location())).append("\",\n");
            sb.append("      \"details\": [");
            for (int d = 0; d < f.details().size(); d++) {
                if (d > 0) sb.append(", ");
                sb.append("\"").append(escJson(f.details().get(d))).append("\"");
            }
            sb.append("]\n    }").append(i + 1 < r.findings().size() ? "," : "").append("\n");
        }
        sb.append("  ]\n}\n");
        ensureParent(path);
        Files.writeString(path, sb.toString(), StandardCharsets.UTF_8);
    }

    public static void writeFullGuiJson(
            Path path,
            FullReport r,
            List<ForensicAuditor.ServiceStatus> services,
            List<RecycleBinForensics.DeletedItem> trashItems,
            List<UsbForensics.UsbDevice> usbDevices,
            List<BrowserForensics.BrowserHit> browserHits,
            EnvironmentAuditor.EnvAudit envAudit,
            NetworkAuditor.NetAudit netAudit
    ) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"reportId\": \"").append(escJson(r.verificationHash())).append("\",\n");
        sb.append("  \"os\": \"").append(escJson(r.osName())).append("\",\n");
        sb.append("  \"bootTime\": \"").append(escJson(r.systemBootTime())).append("\",\n");
        sb.append("  \"timestamp\": \"").append(escJson(r.timestamp())).append("\",\n");
        sb.append("  \"elapsed\": ").append(String.format(Locale.ROOT, "%.2f", r.elapsedSeconds())).append(",\n");
        sb.append("  \"score\": ").append(r.score()).append(",\n");
        sb.append("  \"verdict\": \"").append(escJson(r.verdict())).append("\",\n");
        sb.append("  \"jarsScanned\": ").append(r.jarsScanned()).append(",\n");
        sb.append("  \"binariesScanned\": ").append(r.binariesScanned()).append(",\n");
        sb.append("  \"browsersChecked\": ").append(r.browsersChecked()).append(",\n");
        sb.append("  \"hardware\": \"").append(escJson(envAudit != null ? envAudit.hardwareModel() : "Physical PC")).append("\",\n");
        sb.append("  \"isVm\": ").append(envAudit != null && envAudit.isVm()).append(",\n");
        sb.append("  \"tcpListeners\": ").append(netAudit != null ? netAudit.listeningCount() : 0).append(",\n");

        sb.append("  \"vpns\": [");
        if (envAudit != null) {
            for (int i = 0; i < envAudit.vpnAdapters().size(); i++) {
                if (i > 0) sb.append(", ");
                sb.append("\"").append(escJson(envAudit.vpnAdapters().get(i))).append("\"");
            }
        }
        sb.append("],\n");

        sb.append("  \"mcAccounts\": [");
        for (int i = 0; i < r.mcAccounts().size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append("\"").append(escJson(r.mcAccounts().get(i))).append("\"");
        }
        sb.append("],\n");

        sb.append("  \"mouseSoftware\": [");
        for (int i = 0; i < r.mouseSoftware().size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append("\"").append(escJson(r.mouseSoftware().get(i))).append("\"");
        }
        sb.append("],\n");

        sb.append("  \"processes\": [\n");
        for (int i = 0; i < r.processes().size(); i++) {
            ProcessInspector.McProcess p = r.processes().get(i);
            sb.append("    {\"pid\": ").append(p.pid())
                    .append(", \"name\": \"").append(escJson(p.name()))
                    .append("\", \"launcher\": \"").append(escJson(p.launcher()))
                    .append("\", \"version\": \"").append(escJson(p.mcVersion()))
                    .append("\", \"startTime\": \"").append(escJson(p.startTime()))
                    .append("\", \"modules\": ").append(p.loadedModules().size())
                    .append(", \"cmd\": \"").append(escJson(p.commandLine())).append("\"}")
                    .append(i + 1 < r.processes().size() ? "," : "").append("\n");
        }
        sb.append("  ],\n");

        sb.append("  \"findings\": [\n");
        for (int i = 0; i < r.findings().size(); i++) {
            Finding f = r.findings().get(i);
            sb.append("    {\"category\": \"").append(escJson(f.category()))
                    .append("\", \"severity\": \"").append(escJson(f.severity()))
                    .append("\", \"weight\": ").append(f.weight())
                    .append(", \"title\": \"").append(escJson(f.title()))
                    .append("\", \"location\": \"").append(escJson(f.location()))
                    .append("\", \"details\": [");
            for (int d = 0; d < f.details().size(); d++) {
                if (d > 0) sb.append(", ");
                sb.append("\"").append(escJson(f.details().get(d))).append("\"");
            }
            sb.append("]}").append(i + 1 < r.findings().size() ? "," : "").append("\n");
        }
        sb.append("  ],\n");

        sb.append("  \"services\": [\n");
        for (int i = 0; i < services.size(); i++) {
            ForensicAuditor.ServiceStatus s = services.get(i);
            sb.append("    {\"name\": \"").append(escJson(s.name()))
                    .append("\", \"status\": \"").append(escJson(s.status()))
                    .append("\", \"critical\": ").append(s.critical()).append("}")
                    .append(i + 1 < services.size() ? "," : "").append("\n");
        }
        sb.append("  ],\n");

        sb.append("  \"trash\": [\n");
        int lim = Math.min(trashItems.size(), 100);
        for (int i = 0; i < lim; i++) {
            RecycleBinForensics.DeletedItem it = trashItems.get(i);
            sb.append("    {\"id\": \"").append(escJson(it.id()))
                    .append("\", \"fileName\": \"").append(escJson(it.fileName()))
                    .append("\", \"originalPath\": \"").append(escJson(it.originalPath()))
                    .append("\", \"size\": \"").append(escJson(ConsoleUi.formatBytes(it.sizeBytes())))
                    .append("\", \"deletedAt\": \"").append(escJson(it.deletedAt().toString()))
                    .append("\", \"recoverable\": ").append(it.recoverable())
                    .append(", \"suspicious\": ").append(it.suspicious()).append("}")
                    .append(i + 1 < lim ? "," : "").append("\n");
        }
        sb.append("  ],\n");

        sb.append("  \"usb\": [\n");
        for (int i = 0; i < usbDevices.size(); i++) {
            UsbForensics.UsbDevice d = usbDevices.get(i);
            sb.append("    {\"name\": \"").append(escJson(d.name()))
                    .append("\", \"serial\": \"").append(escJson(d.serial()))
                    .append("\", \"drive\": \"").append(escJson(d.driveLetter()))
                    .append("\", \"size\": \"").append(escJson(d.sizeInfo()))
                    .append("\", \"connected\": ").append(d.connected()).append("}")
                    .append(i + 1 < usbDevices.size() ? "," : "").append("\n");
        }
        sb.append("  ],\n");

        sb.append("  \"browser\": [\n");
        for (int i = 0; i < browserHits.size(); i++) {
            BrowserForensics.BrowserHit h = browserHits.get(i);
            sb.append("    {\"source\": \"").append(escJson(h.source()))
                    .append("\", \"target\": \"").append(escJson(h.domainOrUrl()))
                    .append("\", \"note\": \"").append(escJson(h.note())).append("\"}")
                    .append(i + 1 < browserHits.size() ? "," : "").append("\n");
        }
        sb.append("  ]\n");
        sb.append("}\n");

        ensureParent(path);
        Files.writeString(path, sb.toString(), StandardCharsets.UTF_8);
    }

    public static void writeTxt(
            Path path,
            FullReport r,
            List<RecycleBinForensics.DeletedItem> trashItems,
            List<UsbForensics.UsbDevice> usbDevices,
            List<BrowserForensics.BrowserHit> browserHits
    ) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("==================================================================\n");
        sb.append("  VERITAS v").append(r.version()).append(" - EXACT FORENSIC LOG\n");
        sb.append("==================================================================\n");
        sb.append("Report ID      : ").append(r.verificationHash()).append("\n");
        sb.append("Timestamp      : ").append(r.timestamp()).append("\n");
        sb.append("Platform       : ").append(r.osName()).append("\n");
        sb.append("Last Boot      : ").append(r.systemBootTime()).append("\n");
        sb.append("Verdict        : ").append(r.verdict()).append(" (Score ").append(r.score()).append("/100)\n");
        sb.append(String.format(Locale.ROOT, "Scan Duration  : %.2f s%n", r.elapsedSeconds()));
        sb.append("JARs Scanned   : ").append(r.jarsScanned()).append("\n");
        sb.append("Binaries       : ").append(r.binariesScanned()).append("\n");
        sb.append("Findings Total : ").append(r.findings().size()).append("\n\n");

        sb.append("[1] ACTIVE MINECRAFT INSTANCE\n");
        if (r.processes().isEmpty()) {
            sb.append("  Status: OFFLINE (No active Minecraft process detected)\n\n");
        } else {
            for (ProcessInspector.McProcess p : r.processes()) {
                sb.append("  Status   : IN-INSTANCE ACTIVE\n");
                sb.append("  Launcher : ").append(p.launcher()).append(" (Version ").append(p.mcVersion()).append(")\n");
                sb.append("  PID      : ").append(p.pid()).append(" (").append(p.name()).append(")\n");
                sb.append("  Started  : ").append(p.startTime()).append("\n");
                sb.append("  Modules  : ").append(p.loadedModules().size()).append("\n");
                sb.append("  Command  : ").append(p.commandLine()).append("\n\n");
            }
        }

        sb.append("[2] FORENSIC FINDINGS (").append(r.findings().size()).append(")\n");
        if (r.findings().isEmpty()) {
            sb.append("  CLEAN - No suspicious artifacts detected.\n");
        } else {
            int idx = 1;
            for (Finding f : r.findings()) {
                sb.append("  #").append(idx++).append(" [").append(f.severity()).append("] [")
                        .append(f.category()).append("] ").append(f.title()).append("\n");
                sb.append("     Location : ").append(f.location()).append("\n");
                for (String d : f.details()) {
                    sb.append("     - ").append(d).append("\n");
                }
            }
        }
        sb.append("\n");

        sb.append("[3] RECYCLE BIN / TRASH INDEX (").append(trashItems.size()).append(" items)\n");
        int tLim = Math.min(trashItems.size(), 50);
        for (int i = 0; i < tLim; i++) {
            RecycleBinForensics.DeletedItem it = trashItems.get(i);
            sb.append("  #").append(it.id()).append(" | ").append(it.deletedAt())
                    .append(" | ").append(ConsoleUi.formatBytes(it.sizeBytes()))
                    .append(" | ").append(it.recoverable() ? "RECOVERABLE" : "META-ONLY")
                    .append(" | ").append(it.originalPath()).append("\n");
        }
        sb.append("\n");

        sb.append("[4] USB STORAGE DEVICES (").append(usbDevices.size()).append(")\n");
        for (UsbForensics.UsbDevice d : usbDevices) {
            sb.append("  [").append(d.connected() ? "CONNECTED" : "DISCONNECTED").append("] ")
                    .append(d.name()).append(" | Drive: ").append(d.driveLetter())
                    .append(" | Serial: ").append(d.serial()).append(" | ").append(d.sizeInfo()).append("\n");
        }
        sb.append("\n");

        sb.append("[5] BROWSER / DNS / QUARANTINE HITS (").append(browserHits.size()).append(")\n");
        if (browserHits.isEmpty()) {
            sb.append("  None.\n");
        } else {
            for (BrowserForensics.BrowserHit h : browserHits) {
                sb.append("  [").append(h.source()).append("] ").append(h.domainOrUrl())
                        .append(" (").append(h.note()).append(")\n");
            }
        }
        sb.append("\n[6] MINECRAFT ACCOUNTS / ALTS (").append(r.mcAccounts().size()).append(")\n");
        sb.append("  ").append(r.mcAccounts().isEmpty() ? "None." : String.join(", ", r.mcAccounts())).append("\n");
        sb.append("\n[7] GAMING MOUSE / MACRO SOFTWARE\n");
        sb.append("  ").append(r.mouseSoftware().isEmpty() ? "None detected." : String.join(", ", r.mouseSoftware())).append("\n");

        ensureParent(path);
        Files.writeString(path, sb.toString(), StandardCharsets.UTF_8);
    }
    public static void writeHtml(Path path, FullReport r) throws IOException {
        StringBuilder rows = new StringBuilder();
        StringBuilder staffSummary = new StringBuilder();
        staffSummary.append("Veritas v").append(r.version())
                .append(" | ID: ").append(r.verificationHash())
                .append(" | Verdict: ").append(r.verdict()).append(" (").append(r.score()).append("/100)")
                .append(" | In-Instance: ").append(!r.processes().isEmpty())
                .append(" | USB: ").append(r.usbConnected()).append(" active / ").append(r.usbHistory()).append(" history\\n");

        if (r.findings().isEmpty()) {
            rows.append("<div class='empty'>CLEAN â€” No suspicious artifacts or cheats detected.</div>");
        } else {
            for (Finding f : r.findings()) {
                staffSummary.append("[").append(f.severity()).append("] [").append(f.category()).append("] ")
                        .append(f.title()).append(" -> ").append(f.location()).append("\\n");
                String sevLow = f.severity().toLowerCase(Locale.ROOT);
                rows.append("<div class='card sev-").append(sevLow).append("' data-sev='").append(sevLow).append("'>");
                rows.append("<div class='head'><span class='badge'>").append(escHtml(f.severity())).append("</span>");
                rows.append("<span class='cat'>").append(escHtml(f.category())).append("</span>");
                rows.append("<strong>").append(escHtml(f.title())).append("</strong></div>");
                rows.append("<div class='loc'>").append(escHtml(f.location())).append("</div><ul>");
                for (String d : f.details()) {
                    rows.append("<li>").append(escHtml(d)).append("</li>");
                }
                rows.append("</ul></div>");
            }
        }

        String html = "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>"
                + "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                + "<title>Veritas Forensic Report â€” " + escHtml(r.verificationHash()) + "</title>"
                + "<style>"
                + "*{box-sizing:border-box}body{margin:0;background:#09090b;color:#f4f4f5;font-family:system-ui,-apple-system,sans-serif;padding:32px 20px;}"
                + ".wrap{max-width:1000px;margin:0 auto;}.top{display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:12px;margin-bottom:20px;}"
                + "h1{margin:0 0 6px;font-size:26px}.sub{color:#a1a1aa;font-size:13px;}"
                + ".copybtn{background:#fafafa;color:#09090b;border:none;border-radius:10px;padding:10px 16px;font-weight:700;cursor:pointer;}"
                + ".stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:10px;margin-bottom:20px;}"
                + ".stat{background:#18181b;border:1px solid #27272a;border-radius:12px;padding:14px;}"
                + ".stat span{display:block;color:#a1a1aa;font-size:11px;text-transform:uppercase;}"
                + ".stat strong{font-size:18px;margin-top:4px;display:block;}"
                + ".bar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;align-items:center;}"
                + ".pill{background:#18181b;border:1px solid #27272a;color:#a1a1aa;padding:6px 12px;border-radius:99px;font-size:12px;cursor:pointer;}"
                + ".pill.active{background:#fafafa;color:#09090b;border-color:#fafafa;font-weight:600;}"
                + ".search{flex:1;min-width:200px;padding:8px 12px;border-radius:10px;border:1px solid #27272a;background:#18181b;color:#fafafa;font-size:13px;}"
                + ".card{background:#18181b;border:1px solid #27272a;border-left:4px solid #71717a;border-radius:10px;padding:16px;margin-bottom:12px;}"
                + ".sev-critical{border-left-color:#ef4444;}.sev-high{border-left-color:#f97316;}.sev-suspicious{border-left-color:#eab308;}.sev-info{border-left-color:#38bdf8;}"
                + ".head{display:flex;align-items:center;gap:10px;flex-wrap:wrap;}"
                + ".badge{font-size:11px;font-weight:700;padding:2px 8px;border-radius:99px;background:#27272a;}"
                + ".cat{font-size:11px;color:#38bdf8;font-family:monospace;}"
                + ".loc{font-family:monospace;font-size:12px;color:#a1a1aa;margin:8px 0;word-break:break-all;}"
                + "ul{margin:6px 0 0 18px;color:#d4d4d8;font-size:13px;}.empty{padding:24px;background:#18181b;border-radius:10px;color:#4ade80;text-align:center;font-weight:600;}"
                + "</style></head><body><div class='wrap'><div class='top'><div>"
                + "<h1>Veritas v" + escHtml(r.version()) + " â€” Forensic Report</h1>"
                + "<div class='sub'>" + escHtml(r.osName()) + " | Boot: " + escHtml(r.systemBootTime()) + " | ID: " + escHtml(r.verificationHash()) + "</div></div>"
                + "<button class='copybtn' id='cpBtn'>Copy Staff Summary</button></div>"
                + "<div class='stats'>"
                + "<div class='stat'><span>Verdict</span><strong>" + escHtml(r.verdict()) + " (" + r.score() + "/100)</strong></div>"
                + "<div class='stat'><span>Instance</span><strong>" + (r.processes().isEmpty() ? "OFFLINE" : "ACTIVE") + "</strong></div>"
                + "<div class='stat'><span>Recycle Bin</span><strong>" + r.recycleItems() + " items</strong></div>"
                + "<div class='stat'><span>USB Devices</span><strong>" + r.usbConnected() + " / " + r.usbHistory() + "</strong></div>"
                + "<div class='stat'><span>Findings</span><strong>" + r.findings().size() + "</strong></div></div>"
                + "<div class='bar'>"
                + "<button class='pill active' data-f='all'>All</button>"
                + "<button class='pill' data-f='critical'>Critical</button>"
                + "<button class='pill' data-f='high'>High</button>"
                + "<button class='pill' data-f='suspicious'>Suspicious</button>"
                + "<button class='pill' data-f='info'>Info</button>"
                + "<input class='search' id='qIn' placeholder='Filter findings...'></div>"
                + "<div id='list'>" + rows + "</div></div>"
                + "<script>"
                + "let cur='all';const cards=[...document.querySelectorAll('.card')];"
                + "const apply=()=>{const q=document.getElementById('qIn').value.toLowerCase();"
                + "cards.forEach(c=>{const okS=cur==='all'||c.dataset.sev===cur;const okQ=!q||c.textContent.toLowerCase().includes(q);c.style.display=okS&&okQ?'block':'none';});};"
                + "document.querySelectorAll('.pill').forEach(b=>b.onclick=()=>{document.querySelectorAll('.pill').forEach(x=>x.classList.remove('active'));b.classList.add('active');cur=b.dataset.f;apply();});"
                + "document.getElementById('qIn').oninput=apply;"
                + "document.getElementById('cpBtn').onclick=async()=>{await navigator.clipboard.writeText(\"" + escJson(staffSummary.toString()) + "\");document.getElementById('cpBtn').textContent='Copied!';setTimeout(()=>document.getElementById('cpBtn').textContent='Copy Staff Summary',1800);};"
                + "</script></body></html>";

        ensureParent(path);
        Files.writeString(path, html, StandardCharsets.UTF_8);
    }

    private static void ensureParent(Path path) throws IOException {
        Path p = path.toAbsolutePath().getParent();
        if (p != null) {
            Files.createDirectories(p);
        }
    }

    private static String escJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "");
    }

    private static String escHtml(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    public static String nowIso() {
        return Instant.now().toString();
    }
}
