package com.dips.veritas;

import java.awt.Desktop;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Scanner;

public final class Main {
    public static final String VERSION = "1.0.0";

    private Main() {
    }

    public static void main(String[] args) {
        if (args.length == 0) {
            runInteractiveMenu();
            return;
        }

        boolean deep = false;
        Path htmlOut = null;
        Path jsonOut = null;
        Path txtOut = null;
        Path guiJsonOut = null;
        String recoverId = null;
        List<Path> extraPaths = new ArrayList<>();
        String cmd = args[0].toLowerCase(Locale.ROOT);

        for (int i = 0; i < args.length; i++) {
            switch (args[i].toLowerCase(Locale.ROOT)) {
                case "scan", "--quick", "usb", "trash", "browser", "instance", "recover" -> {
                    if ("recover".equals(args[i].toLowerCase(Locale.ROOT)) && i + 1 < args.length) {
                        recoverId = args[++i];
                    }
                }
                case "--deep" -> deep = true;
                case "--no-color" -> ConsoleUi.setColorEnabled(false);
                case "--html" -> {
                    if (i + 1 >= args.length) {
                        System.err.println("Missing path after --html");
                        System.exit(1);
                    }
                    htmlOut = Path.of(args[++i]);
                }
                case "--json" -> {
                    if (i + 1 >= args.length) {
                        System.err.println("Missing path after --json");
                        System.exit(1);
                    }
                    jsonOut = Path.of(args[++i]);
                }
                case "--gui-json" -> {
                    if (i + 1 >= args.length) {
                        System.err.println("Missing path after --gui-json");
                        System.exit(1);
                    }
                    guiJsonOut = Path.of(args[++i]);
                }
                case "--txt" -> {
                    if (i + 1 >= args.length) {
                        System.err.println("Missing path after --txt");
                        System.exit(1);
                    }
                    txtOut = Path.of(args[++i]);
                }
                case "-v", "--version", "version" -> {
                    System.out.println("veritas " + VERSION);
                    return;
                }
                case "-h", "--help", "help" -> {
                    printUsage();
                    return;
                }
                default -> extraPaths.add(Path.of(args[i]));
            }
        }

        try {
            switch (cmd) {
                case "usb" -> showUsbForensics();
                case "trash" -> showRecycleBin(null);
                case "browser" -> showBrowserForensics();
                case "instance" -> showInstanceCheck();
                case "recover" -> recoverById(recoverId);
                default -> runFullScan(deep, extraPaths, htmlOut, jsonOut, txtOut, guiJsonOut, false, false, false);
            }
        } catch (Exception e) {
            System.err.println(ConsoleUi.red("Error: " + e.getMessage()));
            System.exit(1);
        }
    }

    private static void runInteractiveMenu() {
        ConsoleUi.printBanner(VERSION);
        System.out.println("  " + ConsoleUi.blue("OS :") + " " + ConsoleUi.white(OsInfo.displayName()));
        Scanner sc = new Scanner(System.in);

        while (true) {
            System.out.println();
            System.out.println("  " + ConsoleUi.bold(ConsoleUi.yellow("Tip:")) + " "
                    + ConsoleUi.dim("For the most thorough SS check, use ") + ConsoleUi.cyan("[2] Staff-Only Web Dashboard")
                    + ConsoleUi.dim(" (blocks local PC) or ") + ConsoleUi.blue("[3] Local Web Dashboard") + ConsoleUi.dim("."));
            System.out.println();
            System.out.println(ConsoleUi.bold(ConsoleUi.cyan("Select Veritas Forensic Module:")));
            System.out.println("  " + ConsoleUi.green("[1]") + " Full Screenshare Scan (12-Stage + Auto .TXT Log)");
            System.out.println("  " + ConsoleUi.cyan("[2]") + " Staff-Only Web Dashboard (Blocks Local PC + Generates Staff Link & PIN)");
            System.out.println("  " + ConsoleUi.blue("[3]") + " Local Web Dashboard (Opens Full Interactive Report on This PC)");
            System.out.println("  " + ConsoleUi.blue("[4]") + " Check Active Minecraft Instance & Loaded DLLs/Modules");
            System.out.println("  " + ConsoleUi.magenta("[5]") + " Recycle Bin Forensics & Recover Deleted Files");
            System.out.println("  " + ConsoleUi.yellow("[6]") + " USB Forensics (Connected & Disconnected USB History)");
            System.out.println("  " + ConsoleUi.red("[7]") + " Browser History & Cleared DNS / Quarantine Recovery");
            System.out.println("  " + ConsoleUi.magenta("[8]") + " Macro Software, Scripts & Minecraft Alt-Accounts");
            System.out.println("  " + ConsoleUi.cyan("[9]") + " Environment, VM/VPN, Hidden Cheat Configs & Network Audit");
            System.out.println("  " + ConsoleUi.dim("[0]") + " Exit");
            System.out.print(ConsoleUi.bold(ConsoleUi.cyan("\nveritas> ")));

            if (!sc.hasNextLine()) {
                break;
            }
            String choice = sc.nextLine().trim();
            try {
                switch (choice) {
                    case "1" -> runFullScan(false, List.of(), null, null, defaultTxtLogPath(), null, false, false, false);
                    case "2" -> runFullScan(true, List.of(), null, null, defaultTxtLogPath(), null, false, true, true);
                    case "3" -> runFullScan(true, List.of(), null, null, defaultTxtLogPath(), null, true, true, false);
                    case "4" -> showInstanceCheck();
                    case "5" -> showRecycleBin(sc);
                    case "6" -> showUsbForensics();
                    case "7" -> showBrowserForensics();
                    case "8" -> showMacrosAndAlts();
                    case "9" -> showEnvironmentAndArtifacts();
                    case "0", "exit", "quit" -> {
                        return;
                    }
                    default -> System.out.println(ConsoleUi.yellow("Invalid option."));
                }
            } catch (Exception e) {
                System.err.println(ConsoleUi.red("Error: " + e.getMessage()));
            }
        }
    }

    private static void showInstanceCheck() {
        ConsoleUi.printBanner(VERSION);
        ProcessInspector.ProcessAudit pa = ProcessInspector.inspect();
        System.out.println("  " + ConsoleUi.blue("Last System Boot :") + " " + ConsoleUi.cyan(pa.systemBootTime()));
        if (!pa.isInInstance()) {
            System.out.println("  " + ConsoleUi.blue("Minecraft Status :") + " " + ConsoleUi.yellow("OFFLINE (Not in instance)"));
            return;
        }
        System.out.println("  " + ConsoleUi.blue("Minecraft Status :") + " " + ConsoleUi.bold(ConsoleUi.green("IN-INSTANCE ACTIVE")));
        for (ProcessInspector.McProcess p : pa.processes()) {
            System.out.println();
            System.out.println("  " + ConsoleUi.cyan("Launcher :") + " " + ConsoleUi.bold(p.launcher()));
            System.out.println("  " + ConsoleUi.cyan("Version  :") + " " + p.mcVersion());
            System.out.println("  " + ConsoleUi.cyan("PID      :") + " " + p.pid() + " (" + p.name() + ")");
            System.out.println("  " + ConsoleUi.cyan("Started  :") + " " + ConsoleUi.yellow(p.startTime()));
            System.out.println("  " + ConsoleUi.cyan("Modules  :") + " " + p.loadedModules().size() + " native libraries loaded");
        }
        for (Finding f : pa.findings()) {
            System.out.println("  [" + ConsoleUi.severityBadge(f.severity()) + "] " + f.title() + " -> " + f.location());
        }
    }

    private static void showRecycleBin(Scanner sc) throws Exception {
        ConsoleUi.printBanner(VERSION);
        System.out.println(ConsoleUi.bold(ConsoleUi.magenta("Recycle Bin Forensics & Recovery")));
        List<RecycleBinForensics.DeletedItem> items = RecycleBinForensics.listDeleted();
        if (items.isEmpty()) {
            System.out.println("  " + ConsoleUi.green("Recycle Bin is empty or contains no $I metadata."));
            return;
        }
        int limit = Math.min(items.size(), 30);
        System.out.println("  Showing " + limit + " most recent of " + items.size() + " deleted item(s):\n");
        for (int i = 0; i < limit; i++) {
            RecycleBinForensics.DeletedItem it = items.get(i);
            String tag = it.suspicious() ? ConsoleUi.red("[SUSPICIOUS]") : ConsoleUi.dim("[NORMAL]");
            String rec = it.recoverable() ? ConsoleUi.green("RECOVERABLE") : ConsoleUi.yellow("METADATA-ONLY");
            System.out.println("  " + ConsoleUi.cyan("#" + it.id()) + " " + tag + " " + ConsoleUi.bold(it.fileName())
                    + " (" + ConsoleUi.formatBytes(it.sizeBytes()) + ") | " + rec);
            System.out.println("     " + ConsoleUi.dim("Deleted:") + " " + ConsoleUi.yellow(it.deletedAt().toString())
                    + " | " + ConsoleUi.dim("From:") + " " + it.originalPath());
        }

        if (sc != null) {
            System.out.print(ConsoleUi.cyan("\nEnter ID to recover to ./veritas-recovered (or ENTER to skip): "));
            String pick = sc.nextLine().trim();
            if (!pick.isEmpty()) {
                for (RecycleBinForensics.DeletedItem it : items) {
                    if (it.id().equals(pick)) {
                        Path out = RecycleBinForensics.recover(it, Path.of("veritas-recovered"));
                        System.out.println("  " + ConsoleUi.bold(ConsoleUi.green("Recovered successfully -> ")) + out.toAbsolutePath());
                        return;
                    }
                }
                System.out.println("  " + ConsoleUi.yellow("ID not found: " + pick));
            }
        }
    }

    private static void showUsbForensics() {
        ConsoleUi.printBanner(VERSION);
        System.out.println(ConsoleUi.bold(ConsoleUi.yellow("USB Storage Forensics (Connected & Disconnected History)")));
        UsbForensics.UsbAudit audit = UsbForensics.inspect();
        if (audit.devices().isEmpty()) {
            System.out.println("  " + ConsoleUi.green("No USB storage devices found."));
            return;
        }
        for (UsbForensics.UsbDevice d : audit.devices()) {
            String st = d.connected() ? ConsoleUi.bold(ConsoleUi.cyan("[CONNECTED]   ")) : ConsoleUi.yellow("[DISCONNECTED]");
            System.out.println("  " + st + " " + ConsoleUi.bold(d.name())
                    + " | Drive: " + ConsoleUi.white(d.driveLetter())
                    + " | Serial: " + ConsoleUi.dim(d.serial())
                    + " | " + d.sizeInfo());
        }
    }

    private static void showBrowserForensics() {
        ConsoleUi.printBanner(VERSION);
        System.out.println(ConsoleUi.bold(ConsoleUi.red("Browser History & Cleared DNS Cache Forensics")));
        BrowserForensics.BrowserAudit ba = BrowserForensics.inspect();
        System.out.println("  " + ConsoleUi.blue("Browser Profiles Checked :") + " " + ba.browsersChecked() + " + Windows DNS Cache");
        if (ba.hits().isEmpty() && ba.findings().isEmpty()) {
            System.out.println("  " + ConsoleUi.bold(ConsoleUi.green("CLEAN: No cheat domains found in Browser History or DNS Cache.")));
            return;
        }
        for (BrowserForensics.BrowserHit h : ba.hits()) {
            System.out.println("  " + ConsoleUi.red("[MATCH]") + " " + ConsoleUi.cyan(h.source()) + " -> " + ConsoleUi.bold(h.domainOrUrl()));
        }
        for (Finding f : ba.findings()) {
            System.out.println("  [" + ConsoleUi.severityBadge(f.severity()) + "] " + f.title());
        }
    }

    private static void showMacrosAndAlts() {
        ConsoleUi.printBanner(VERSION);
        System.out.println(ConsoleUi.bold(ConsoleUi.magenta("Macro Software, Scripts & Minecraft Alt-Accounts")));
        MacroDetector.MacroAudit ma = MacroDetector.inspect();
        List<String> alts = AccountAuditor.discoverAccounts(MinecraftScanner.discoverMinecraftDirs());
        System.out.println("  " + ConsoleUi.blue("Minecraft Accounts :") + " " + (alts.isEmpty() ? "None found" : ConsoleUi.cyan(String.join(", ", alts))));
        System.out.println("  " + ConsoleUi.blue("Gaming Mouse SW    :") + " " + (ma.mouseSoftware().isEmpty() ? "None detected" : ConsoleUi.yellow(String.join(", ", ma.mouseSoftware()))));
        System.out.println("  " + ConsoleUi.blue("Macro Scripts      :") + " " + ma.scriptsFound());
        for (Finding f : ma.findings()) {
            System.out.println("  [" + ConsoleUi.severityBadge(f.severity()) + "] " + f.title() + " -> " + f.location());
        }
    }

    private static void showEnvironmentAndArtifacts() {
        ConsoleUi.printBanner(VERSION);
        System.out.println(ConsoleUi.bold(ConsoleUi.cyan("Environment, VM/VPN, Hidden Cheat Configs & Network Audit")));
        EnvironmentAuditor.EnvAudit env = EnvironmentAuditor.inspect();
        ArtifactHunter.ArtifactAudit art = ArtifactHunter.scan(MinecraftScanner.discoverMinecraftDirs());
        NetworkAuditor.NetAudit net = NetworkAuditor.inspect();

        System.out.println("  " + ConsoleUi.blue("Hardware Model :") + " " + ConsoleUi.white(env.hardwareModel())
                + (env.isVm() ? " " + ConsoleUi.red("[VM DETECTED]") : " " + ConsoleUi.green("[PHYSICAL]")));
        System.out.println("  " + ConsoleUi.blue("VPN Adapters   :") + " " + (env.vpnAdapters().isEmpty() ? ConsoleUi.green("None") : ConsoleUi.yellow(String.join(", ", env.vpnAdapters()))));
        System.out.println("  " + ConsoleUi.blue("TCP Listeners  :") + " " + net.listeningCount());
        System.out.println("  " + ConsoleUi.blue("Config Dirs    :") + " " + art.dirsChecked() + " inspected");

        List<Finding> list = new ArrayList<>();
        list.addAll(env.findings());
        list.addAll(art.findings());
        list.addAll(net.findings());
        if (list.isEmpty()) {
            System.out.println("  " + ConsoleUi.bold(ConsoleUi.green("CLEAN: No VM, hidden cheat folders, or suspicious listeners found.")));
            return;
        }
        for (Finding f : list) {
            System.out.println("  [" + ConsoleUi.severityBadge(f.severity()) + "] " + f.title() + " -> " + f.location());
        }
    }

    private static void recoverById(String id) throws Exception {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("Missing Recycle Bin item ID.");
        }
        for (RecycleBinForensics.DeletedItem it : RecycleBinForensics.listDeleted()) {
            if (it.id().equals(id)) {
                Path out = RecycleBinForensics.recover(it, Path.of(System.getProperty("user.home"), "Desktop", "veritas-recovered"));
                System.out.println("RECOVERED:" + out.toAbsolutePath());
                return;
            }
        }
        throw new IllegalArgumentException("Recycle Bin item not found: " + id);
    }

    private static Path defaultTxtLogPath() {
        String stamp = java.time.LocalDateTime.now()
                .format(java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
        return Path.of("veritas-log-" + stamp + ".txt");
    }

    private static void runFullScan(
            boolean deep,
            List<Path> extraPaths,
            Path htmlOut,
            Path jsonOut,
            Path txtOut,
            Path guiJsonOut,
            boolean autoOpen,
            boolean launchWebServer,
            boolean blockLocalPc
    ) throws Exception {
        ConsoleUi.printBanner(VERSION);
        long startNanos = System.nanoTime();

        System.out.println(ConsoleUi.cyan("  [ 1/12]") + " Inspecting active Minecraft instance, JVM flags & loaded modules...");
        ProcessInspector.ProcessAudit procAudit = ProcessInspector.inspect();

        System.out.println(ConsoleUi.cyan("  [ 2/12]") + " Scanning Minecraft launchers, JAR bytecode, mods & logs...");
        MinecraftScanner.MinecraftAudit mcAudit = MinecraftScanner.scan(extraPaths, deep);

        System.out.println(ConsoleUi.cyan("  [ 3/12]") + " Detecting Replace Method (spoofed mods, timestamps & Zone.Identifier)...");
        ReplaceDetector.ReplaceAudit replaceAudit = ReplaceDetector.scan(mcAudit.discoveredDirs());

        System.out.println(ConsoleUi.cyan("  [ 4/12]") + " Analyzing PE/ELF/Mach-O binaries, disguised files & Authenticode...");
        List<Path> binRoots = new ArrayList<>(BinaryScanner.defaultScanRoots());
        binRoots.addAll(extraPaths);
        BinaryScanner.BinaryAudit binAudit = BinaryScanner.scan(binRoots, deep);

        System.out.println(ConsoleUi.cyan("  [ 5/12]") + " Auditing Recycle Bin / Trash metadata...");
        List<RecycleBinForensics.DeletedItem> trashItems = RecycleBinForensics.listDeleted();
        List<Finding> trashFindings = RecycleBinForensics.audit(trashItems);

        System.out.println(ConsoleUi.cyan("  [ 6/12]") + " Checking connected & disconnected USB storage history...");
        UsbForensics.UsbAudit usbAudit = UsbForensics.inspect();

        System.out.println(ConsoleUi.cyan("  [ 7/12]") + " Auditing Browser History, DNS Cache & macOS Quarantine...");
        BrowserForensics.BrowserAudit browserAudit = BrowserForensics.inspect();

        System.out.println(ConsoleUi.cyan("  [ 8/12]") + " Detecting Macro software, scripts & Minecraft alt-accounts...");
        MacroDetector.MacroAudit macroAudit = MacroDetector.inspect();
        List<String> mcAccounts = AccountAuditor.discoverAccounts(mcAudit.discoveredDirs());

        System.out.println(ConsoleUi.cyan("  [ 9/12]") + " Checking VM / Cloud PC environment & active VPN adapters...");
        EnvironmentAuditor.EnvAudit envAudit = EnvironmentAuditor.inspect();

        System.out.println(ConsoleUi.cyan("  [10/12]") + " Hunting hidden cheat config folders & options.txt anomalies...");
        ArtifactHunter.ArtifactAudit artAudit = ArtifactHunter.scan(mcAudit.discoveredDirs());

        System.out.println(ConsoleUi.cyan("  [11/12]") + " Inspecting active TCP listeners & cheat-auth ports...");
        NetworkAuditor.NetAudit netAudit = NetworkAuditor.inspect();

        System.out.println(ConsoleUi.cyan("  [12/12]") + " Checking EventLog tampering, clock spoofing, BAM, Prefetch, Services & Hosts...");
        TamperAuditor.TamperAudit tamperAudit = TamperAuditor.inspect();
        ForensicAuditor.ForensicAudit osAudit = ForensicAuditor.run();

        List<Finding> all = new ArrayList<>();
        all.addAll(procAudit.findings());
        all.addAll(mcAudit.findings());
        all.addAll(replaceAudit.findings());
        all.addAll(binAudit.findings());
        all.addAll(trashFindings);
        all.addAll(usbAudit.findings());
        all.addAll(browserAudit.findings());
        all.addAll(macroAudit.findings());
        all.addAll(envAudit.findings());
        all.addAll(artAudit.findings());
        all.addAll(netAudit.findings());
        all.addAll(tamperAudit.findings());
        all.addAll(osAudit.findings());
        all.sort(Comparator.comparingInt(Finding::weight).reversed());

        int score = 0;
        for (Finding f : all) {
            score = Math.min(100, score + f.weight());
        }
        String verdict = ConsoleUi.verdictFromScore(score);
        double elapsed = (System.nanoTime() - startNanos) / 1_000_000_000.0;
        String now = ReportWriter.nowIso();
        String hash = ReportWriter.computeVerificationHash(now, score, all);

        int usbConn = (int) usbAudit.devices().stream().filter(UsbForensics.UsbDevice::connected).count();
        int usbHist = (int) usbAudit.devices().stream().filter(d -> !d.connected()).count();

        ReportWriter.FullReport report = new ReportWriter.FullReport(
                VERSION,
                OsInfo.displayName(),
                procAudit.systemBootTime(),
                now,
                elapsed,
                score,
                verdict,
                hash,
                procAudit.processes(),
                mcAudit.jarsScanned(),
                binAudit.binariesScanned(),
                trashItems.size(),
                usbConn,
                usbHist,
                browserAudit.browsersChecked(),
                mcAccounts,
                macroAudit.mouseSoftware(),
                all
        );

        ReportWriter.printConsole(report);

        if (txtOut != null) {
            ReportWriter.writeTxt(txtOut, report, trashItems, usbAudit.devices(), browserAudit.hits());
            System.out.println("\n  " + ConsoleUi.green("TXT Log    :") + " " + txtOut.toAbsolutePath());
        }
        if (htmlOut != null) {
            String fullHtml = WebDashboardServer.buildFullDashboardHtml(
                    report, osAudit.services(), trashItems, usbAudit.devices(), browserAudit.hits(), envAudit, netAudit, null
            );
            java.nio.file.Files.writeString(htmlOut, fullHtml, java.nio.charset.StandardCharsets.UTF_8);
            System.out.println("  " + ConsoleUi.green("HTML Report:") + " " + htmlOut.toAbsolutePath());
        }
        if (jsonOut != null) {
            ReportWriter.writeJson(jsonOut, report);
            System.out.println("  " + ConsoleUi.green("JSON Report:") + " " + jsonOut.toAbsolutePath());
        }
        if (guiJsonOut != null) {
            ReportWriter.writeFullGuiJson(guiJsonOut, report, osAudit.services(), trashItems, usbAudit.devices(), browserAudit.hits(), envAudit, netAudit);
        }

        if (launchWebServer) {
            String txtRaw = txtOut != null && java.nio.file.Files.isRegularFile(txtOut)
                    ? java.nio.file.Files.readString(txtOut, java.nio.charset.StandardCharsets.UTF_8)
                    : "";
            WebDashboardServer web = new WebDashboardServer(
                    8765,
                    blockLocalPc,
                    report,
                    osAudit.services(),
                    trashItems,
                    usbAudit.devices(),
                    browserAudit.hits(),
                    envAudit,
                    netAudit,
                    txtRaw
            );
            web.start();

            System.out.println();
            System.out.println(ConsoleUi.bold(ConsoleUi.blue("------------------ VERITAS WEB DASHBOARD ------------------")));
            if (blockLocalPc) {
                System.out.println(ConsoleUi.dim("  Generating Remote Staff Link (works from any PC worldwide)..."));
                String remoteHtml = WebDashboardServer.buildFullDashboardHtml(
                        report, osAudit.services(), trashItems, usbAudit.devices(), browserAudit.hits(), envAudit, netAudit, null
                );
                String cloudUrl = WebDashboardServer.uploadPublicReport(remoteHtml, hash);
                System.out.println("  " + ConsoleUi.red("Local PC    :") + " BLOCKED (403 Staff Only)");
                if (cloudUrl != null) {
                    System.out.println("  " + ConsoleUi.bold(ConsoleUi.green("Remote Link :")) + " " + ConsoleUi.cyan(cloudUrl));
                    System.out.println("  " + ConsoleUi.dim("              Works on ANY Staff PC worldwide (even on different networks)."));
                }
                System.out.println("  " + ConsoleUi.cyan("LAN Link    :") + " " + web.lanUrl());
                System.out.println("  " + ConsoleUi.yellow("Staff PIN   :") + " " + ConsoleUi.bold(web.staffPin()));
            } else {
                System.out.println("  " + ConsoleUi.green("Local URL   :") + " " + ConsoleUi.bold(web.localUrl()));
                System.out.println("  " + ConsoleUi.cyan("LAN URL     :") + " " + web.lanUrl());
                if (autoOpen && Desktop.isDesktopSupported()) {
                    try {
                        Desktop.getDesktop().browse(java.net.URI.create(web.localUrl()));
                    } catch (Exception ignored) {
                    }
                }
            }
            System.out.println(ConsoleUi.dim("  Press ENTER to stop the Web Dashboard server..."));
            new Scanner(System.in).nextLine();
            web.stop();
            System.out.println("  " + ConsoleUi.yellow("Web Dashboard stopped."));
        }
    }

    private static void printUsage() {
        ConsoleUi.printBanner(VERSION);
        System.out.println("Usage (run with no arguments for color interactive menu):");
        System.out.println("  java -jar veritas-1.0.0.jar scan [--deep] [--html report.html] [--json report.json]");
        System.out.println("  java -jar veritas-1.0.0.jar instance");
        System.out.println("  java -jar veritas-1.0.0.jar trash");
        System.out.println("  java -jar veritas-1.0.0.jar usb");
        System.out.println("  java -jar veritas-1.0.0.jar browser");
    }
}
