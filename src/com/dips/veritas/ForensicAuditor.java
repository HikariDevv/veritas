package com.dips.veritas;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;

public final class ForensicAuditor {
    private static final List<String> CHEAT_ARTIFACT_NAMES = List.of(
            "vape", "slinky", "sluded", "sludedloader", "drip", "entropy", "whiteout", "koid",
            "itami", "lithiumlite", "karma", "doomsday", "prestige", "glock", "opautoclicker",
            "gsautoclicker", "autoclicker", "extremeinjector", "xenos",
            "cheatengine", "wurst", "meteor", "breeze", "catlean", "yukio",
            "sapphire", "exelon", "icetea", "akira", "antic", "vapev4", "vapelite", "cheatloader",
            "eulen", "redengine", "skript.gg", "hxcheats", "susano", "2take1", "cherax",
            "kiddions", "modest-menu", "yimmenu", "tzproject", "desudo",
            "synapsex", "krnl", "fluxus", "solara", "jjsploit", "dx9ware", "aimmy"
    );

    private static final List<String> BENIGN_DELETED_EXE = List.of(
            "setup", "install", "unins", "update", "onedrive", "winget", "vcredist", "vc_redist", "python",
            "nvidia", "asus", "armoury", "bluestacks", "teamspeak", "discord", "chrome", "brave",
            "firefox", "edge", "vscode", "code.exe", "lunar", "badlion", "feather", "labymod",
            "minecraft", "curseforge", "modrinth", "prism", "steam", "epic", "riot", "spotify",
            "obs", "medal", "7z", "winrar", "git", "node", "jdk", "jre", "java", "aetheris",
            "veritas", "qrdrop", "pvz"
    );

    public record ServiceStatus(String name, String status, boolean critical) {
    }

    public record ForensicAudit(int checksRun, List<ServiceStatus> services, List<Finding> findings) {
    }

    private ForensicAuditor() {
    }

    public static ForensicAudit run() {
        List<Finding> findings = new ArrayList<>();
        List<ServiceStatus> services = new ArrayList<>();
        int checks = 0;

        checks++;
        auditHostsFile(findings);

        if (OsInfo.isWindows()) {
            java.time.Instant bootInstant = resolveWindowsBootInstant();
            checks++;
            auditWindowsServices(services, findings);
            checks++;
            auditWindowsPrefetch(findings, bootInstant);
            checks++;
            auditWindowsBamRegistry(findings);
            checks++;
            auditWindowsRecent(findings, bootInstant);
            checks++;
            auditWindowsPcaAndSelfDestruct(findings);
        } else {
            checks++;
            auditUnixTempAndShm(findings);
            checks++;
            auditUnixPersistence(findings);
        }

        return new ForensicAudit(checks, services, findings);
    }

    private static void auditUnixTempAndShm(List<Finding> findings) {
        List<Path> dirs = OsInfo.isLinux()
                ? List.of(Path.of("/tmp"), Path.of("/dev/shm"))
                : List.of(Path.of("/tmp"), Path.of("/private/tmp"));
        for (Path dir : dirs) {
            if (!Files.isDirectory(dir)) {
                continue;
            }
            try (Stream<Path> s = Files.list(dir)) {
                for (Path p : s.toList()) {
                    String lower = p.getFileName().toString().toLowerCase(Locale.ROOT);
                    for (String kw : CHEAT_ARTIFACT_NAMES) {
                        if (lower.contains(kw)) {
                            findings.add(new Finding(
                                    "UNIX_TEMP", "HIGH", 45,
                                    "Suspicious artifact in " + dir + ": " + p.getFileName(),
                                    p.toString(),
                                    List.of("Matched keyword: " + kw)
                            ));
                            break;
                        }
                    }
                    if (dir.toString().equals("/dev/shm") && (lower.endsWith(".so") || lower.endsWith(".jar"))) {
                        findings.add(new Finding(
                                "LINUX_SHM_INJECT", "CRITICAL", 55,
                                "Shared library/JAR hidden in RAM-backed /dev/shm: " + p.getFileName(),
                                p.toString(),
                                List.of("Memory-backed /dev/shm is commonly used to hide Linux injectors")
                        ));
                    }
                }
            } catch (IOException ignored) {
            }
        }
    }

    private static void auditUnixPersistence(List<Finding> findings) {
        String home = System.getProperty("user.home", "");
        Path dir = OsInfo.isMac()
                ? Path.of(home, "Library", "LaunchAgents")
                : Path.of(home, ".config", "autostart");
        if (!Files.isDirectory(dir)) {
            return;
        }
        try (Stream<Path> s = Files.list(dir)) {
            for (Path p : s.toList()) {
                String lower = p.getFileName().toString().toLowerCase(Locale.ROOT);
                for (String kw : CHEAT_ARTIFACT_NAMES) {
                    if (lower.contains(kw)) {
                        findings.add(new Finding(
                                "UNIX_PERSISTENCE", "HIGH", 45,
                                "Suspicious startup entry in " + dir + ": " + p.getFileName(),
                                p.toString(),
                                List.of("Matched keyword: " + kw)
                        ));
                        break;
                    }
                }
            }
        } catch (IOException ignored) {
        }
    }

    private static void auditHostsFile(List<Finding> findings) {
        Path hosts = OsInfo.isWindows()
                ? Path.of("C:\\Windows\\System32\\drivers\\etc\\hosts")
                : Path.of("/etc/hosts");
        if (!Files.isReadable(hosts)) {
            return;
        }
        try {
            for (String raw : Files.readAllLines(hosts, StandardCharsets.UTF_8)) {
                String line = raw.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                String lower = line.toLowerCase(Locale.ROOT);
                if (lower.endsWith("localhost") || lower.contains("broadcasthost") || lower.contains("ip6-")) {
                    continue;
                }
                boolean cheatDomain = false;
                for (String kw : CHEAT_ARTIFACT_NAMES) {
                    if (lower.contains(kw)) {
                        cheatDomain = true;
                        break;
                    }
                }
                if (cheatDomain) {
                    findings.add(new Finding(
                            "HOSTS_BYPASS", "CRITICAL", 55,
                            "Cheat client auth/crack redirect detected in hosts file",
                            hosts.toString(),
                            List.of("Entry: " + line)
                    ));
                } else {
                    findings.add(new Finding(
                            "HOSTS_ENTRY", "INFO", 5,
                            "Custom entry in system hosts file",
                            hosts.toString(),
                            List.of("Entry: " + line)
                    ));
                }
            }
        } catch (IOException ignored) {
        }
    }

    private static void auditWindowsServices(List<ServiceStatus> services, List<Finding> findings) {
        List<String> criticalServices = List.of("SysMain", "EventLog", "DPS", "PcaSvc", "Dnscache");
        List<String> monitored = List.of("SysMain", "EventLog", "DPS", "PcaSvc", "DiagTrack", "DusmSvc", "Dnscache", "WSearch", "WinDefend");

        for (String name : monitored) {
            List<String> lines = ProcessInspector.execLines("sc", "query", name);
            String state = null;
            for (String line : lines) {
                String upper = line.toUpperCase(Locale.ROOT);
                if (upper.contains("RUNNING")) {
                    state = "Running";
                    break;
                } else if (upper.contains("STOPPED")) {
                    state = "Stopped";
                    break;
                } else if (upper.contains("PAUSED")) {
                    state = "Paused";
                    break;
                }
            }
            if (state == null) {
                continue;
            }
            boolean isCrit = criticalServices.contains(name);
            services.add(new ServiceStatus(name, state, isCrit));
            if (!"Running".equalsIgnoreCase(state)) {
                String sev = isCrit ? "HIGH" : "SUSPICIOUS";
                int w = isCrit ? 35 : 15;
                findings.add(new Finding(
                        "SERVICE_STOPPED", sev, w,
                        "Windows forensic service is not running: " + name,
                        "Service -> " + name,
                        List.of("Status: " + state, "Stopped forensic services can hide execution, DNS, or search traces")
                ));
            }
        }
    }

    private static java.time.Instant resolveWindowsBootInstant() {
        List<String> lines = ProcessInspector.execLines(
                "powershell", "-NoProfile", "-Command",
                "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')"
        );
        for (String l : lines) {
            try {
                return java.time.Instant.parse(l.trim());
            } catch (Exception ignored) {
            }
        }
        return java.time.Instant.EPOCH;
    }

    private static void auditWindowsPrefetch(List<Finding> findings, java.time.Instant bootInstant) {
        Path pfDir = Path.of("C:\\Windows\\Prefetch");
        if (!Files.isDirectory(pfDir)) {
            return;
        }
        try (Stream<Path> s = Files.list(pfDir)) {
            List<Path> pfFiles = s.filter(p -> p.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".pf")).toList();
            if (pfFiles.isEmpty()) {
                findings.add(new Finding(
                        "ANTI_BYPASS", "HIGH", 35,
                        "Windows Prefetch folder is empty",
                        pfDir.toString(),
                        List.of("Prefetch may have been wiped or disabled before screenshare")
                ));
                return;
            }
            for (Path pf : pfFiles) {
                java.time.Instant mtime = Files.getLastModifiedTime(pf).toInstant();
                if (mtime.isBefore(bootInstant)) {
                    continue;
                }
                String lower = pf.getFileName().toString().toLowerCase(Locale.ROOT);
                for (String kw : CHEAT_ARTIFACT_NAMES) {
                    if (lower.contains(kw)) {
                        findings.add(new Finding(
                                "PREFETCH", "CRITICAL", 55,
                                "In-session Prefetch execution trace: " + pf.getFileName(),
                                pf.toString(),
                                List.of("Session: IN-SESSION (After PC Boot)", "Matched keyword: " + kw, "Last modified: " + mtime)
                        ));
                        break;
                    }
                }
            }
        } catch (IOException ignored) {
        }
    }

    private static void auditWindowsBamRegistry(List<Finding> findings) {
        List<String> lines = ProcessInspector.execLines(
                "reg", "query",
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings", "/s"
        );
        for (String line : lines) {
            String lower = line.toLowerCase(Locale.ROOT);
            if (!lower.contains(".exe")) {
                continue;
            }
            for (String kw : CHEAT_ARTIFACT_NAMES) {
                if (lower.contains(kw)) {
                    findings.add(new Finding(
                            "REGISTRY_BAM", "CRITICAL", 55,
                            "BAM execution history matched cheat binary: " + kw,
                            "HKLM\\...\\bam\\State\\UserSettings",
                            List.of(line.trim())
                    ));
                    break;
                }
            }
        }
    }

    private static void auditWindowsRecent(List<Finding> findings, java.time.Instant bootInstant) {
        String appData = System.getenv("APPDATA");
        if (appData == null) {
            return;
        }
        Path recent = Path.of(appData, "Microsoft", "Windows", "Recent");
        if (!Files.isDirectory(recent)) {
            return;
        }
        try (Stream<Path> s = Files.list(recent)) {
            for (Path p : s.toList()) {
                java.time.Instant mtime = Files.getLastModifiedTime(p).toInstant();
                if (mtime.isBefore(bootInstant)) {
                    continue;
                }
                String lower = p.getFileName().toString().toLowerCase(Locale.ROOT);
                for (String kw : CHEAT_ARTIFACT_NAMES) {
                    if (lower.contains(kw)) {
                        findings.add(new Finding(
                                "RECENT_FILES", "HIGH", 40,
                                "In-session shortcut in Windows Recent: " + p.getFileName(),
                                p.toString(),
                                List.of("Session: IN-SESSION (After PC Boot)", "Matched keyword: " + kw)
                        ));
                        break;
                    }
                }
            }
        } catch (IOException ignored) {
        }
    }

    private static void auditWindowsMuiCache(List<Finding> findings) {
        List<String> lines = ProcessInspector.execLines(
                "reg", "query",
                "HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache"
        );
        for (String line : lines) {
            String lower = line.toLowerCase(Locale.ROOT);
            for (String kw : CHEAT_ARTIFACT_NAMES) {
                if (lower.contains(kw)) {
                    findings.add(new Finding(
                            "REGISTRY_MUICACHE", "HIGH", 40,
                            "MuiCache execution trace matched: " + kw,
                            "HKCU\\...\\MuiCache",
                            List.of(line.trim())
                    ));
                    break;
                }
            }
        }
    }

    private static void auditWindowsPcaAndSelfDestruct(List<Finding> findings) {
        String ps = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
                + "$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime; "
                + "function R13([string]$s){ $a=$s.ToCharArray(); for($i=0;$i -lt $a.Length;$i++){ $c=[int]$a[$i]; "
                + "if($c -ge 65 -and $c -le 90){$a[$i]=[char]((($c-65+13)%26)+65)} "
                + "elseif($c -ge 97 -and $c -le 122){$a[$i]=[char]((($c-97+13)%26)+97)} }; -join $a }; "
                + "$k='HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Count'; "
                + "$p=Get-ItemProperty $k -ErrorAction SilentlyContinue; "
                + "if($p){ foreach($x in $p.PSObject.Properties){ if($x.Value -is [byte[]] -and $x.Value.Length -ge 68){ "
                + "$n=R13 $x.Name; $cnt=[BitConverter]::ToInt32($x.Value,4); $ft=[BitConverter]::ToInt64($x.Value,60); "
                + "if($ft -gt 0 -and $n -match '^[A-Za-z]:\\\\.+\\.exe$'){ $dt=[DateTime]::FromFileTime($ft); "
                + "$inS=($dt -ge $boot); $ex=(Test-Path -LiteralPath $n); "
                + "Write-Output ('UA|' + $inS + '|' + $ex + '|' + $cnt + '|' + $dt.ToString('yyyy-MM-dd HH:mm:ss') + '|' + $n) } } } }";

        List<String> lines = ProcessInspector.execLines("powershell", "-NoProfile", "-Command", ps);
        java.util.Set<String> seen = new java.util.LinkedHashSet<>();

        for (String line : lines) {
            if (!line.startsWith("UA|")) {
                continue;
            }
            String[] parts = line.split("\\|", 6);
            if (parts.length < 6) {
                continue;
            }
            boolean inSession = Boolean.parseBoolean(parts[1]);
            boolean exists = Boolean.parseBoolean(parts[2]);
            String runCount = parts[3];
            String lastRun = parts[4];
            String exePath = parts[5].trim();
            String lower = exePath.toLowerCase(Locale.ROOT);
            if (!seen.add(lower)) {
                continue;
            }

            String matchedKw = null;
            for (String kw : CHEAT_ARTIFACT_NAMES) {
                if (lower.contains(kw)) {
                    matchedKw = kw;
                    break;
                }
            }

            String fileName = Path.of(exePath).getFileName().toString();
            if (!inSession) {
                continue;
            }
            if (matchedKw != null) {
                findings.add(new Finding(
                        "IN_SESSION_CHEAT", "CRITICAL", 70,
                        (exists ? "Cheat/injector executed IN THIS SESSION: " : "Self-destructed cheat executed IN THIS SESSION: ") + fileName,
                        exePath,
                        List.of(
                                "Session: IN-SESSION (After PC Boot)",
                                "Last Run: " + lastRun,
                                "Run Count: " + runCount,
                                "Matched Signature: " + matchedKw,
                                "File Status: " + (exists ? "Present on disk" : "DELETED AFTER RUN (Self-Destruct)")
                        )
                ));
                continue;
            }

            boolean inUserHotDir = lower.contains("\\downloads\\") || lower.contains("\\desktop\\")
                    || lower.contains("\\documents\\") || lower.contains("\\appdata\\local\\temp\\");
            if (!exists && inUserHotDir && !isBenignDeletedExe(lower)) {
                findings.add(new Finding(
                        "SELF_DESTRUCT_TRACE", "HIGH", 45,
                        "Binary executed IN THIS SESSION and deleted: " + fileName,
                        exePath,
                        List.of(
                                "Session: IN-SESSION (After PC Boot)",
                                "Last Run: " + lastRun,
                                "Run Count: " + runCount,
                                "File Status: DELETED AFTER EXECUTION (possible C++ self-destruct)"
                        )
                ));
            }
        }
    }

    private static boolean isBenignDeletedExe(String lowerPath) {
        for (String ok : BENIGN_DELETED_EXE) {
            if (lowerPath.contains(ok)) {
                return true;
            }
        }
        return false;
    }
}
