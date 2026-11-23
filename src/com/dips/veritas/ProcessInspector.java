package com.dips.veritas;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class ProcessInspector {
    public record McProcess(
            long pid,
            String name,
            String launcher,
            String mcVersion,
            String startTime,
            String commandLine,
            List<String> loadedModules
    ) {
    }

    public record ProcessAudit(String systemBootTime, List<McProcess> processes, List<Finding> findings) {
        public boolean isInInstance() {
            return !processes.isEmpty();
        }
    }

    private static final Pattern VERSION_FLAG = Pattern.compile("--version\\s+\"?([^\\s\"]+)\"?");

    private static final List<String> CHEAT_MODULE_KEYWORDS = List.of(
            "vape", "slinky", "drip", "entropy", "whiteout", "koid", "itami", "lithiumlite",
            "karma", "doomsday", "prestige", "glock", "autoclick", "cheatengine", "extremeinjector"
    );

    private ProcessInspector() {
    }

    public static ProcessAudit inspect() {
        List<McProcess> mcProcs = new ArrayList<>();
        List<Finding> findings = new ArrayList<>();
        String bootTime = detectBootTime();

        if (OsInfo.isWindows()) {
            inspectWindows(mcProcs, findings);
        } else {
            inspectUnix(mcProcs, findings);
        }

        for (McProcess p : mcProcs) {
            String lowerCmd = p.commandLine().toLowerCase(Locale.ROOT);
            boolean officialClient = lowerCmd.contains("lunar") || lowerCmd.contains("badlion")
                    || lowerCmd.contains("feather") || lowerCmd.contains("labymod")
                    || lowerCmd.contains("ichor") || lowerCmd.contains("genesis")
                    || lowerCmd.contains("modrinth") || lowerCmd.contains("prism")
                    || lowerCmd.contains("curseforge") || lowerCmd.contains("multimc");

            if (lowerCmd.contains("-javaagent:") || lowerCmd.contains("-agentlib:") || lowerCmd.contains("-agentpath:")) {
                if (!officialClient && !lowerCmd.contains("intellij") && !lowerCmd.contains("idea_rt")
                        && !lowerCmd.contains("optifine") && !lowerCmd.contains("fabric")
                        && !lowerCmd.contains("forge") && !lowerCmd.contains("quilt")
                        && !lowerCmd.contains("sentry")) {
                    findings.add(new Finding(
                            "JVM_AGENT", "CRITICAL", 55,
                            "Custom JVM agent attached to Minecraft (PID " + p.pid() + ")",
                            p.launcher() + " (" + p.mcVersion() + ")",
                            List.of("Detected -javaagent/-agentlib/-agentpath flag", trimCmd(p.commandLine()))
                    ));
                }
            }
            if (lowerCmd.contains("-xbootclasspath") && !officialClient) {
                findings.add(new Finding(
                        "JVM_AGENT", "HIGH", 35,
                        "Modified JVM boot classpath detected (PID " + p.pid() + ")",
                        p.launcher(),
                        List.of(trimCmd(p.commandLine()))
                ));
            }

            for (String mod : p.loadedModules()) {
                String lowerMod = mod.toLowerCase(Locale.ROOT);
                for (String kw : CHEAT_MODULE_KEYWORDS) {
                    if (lowerMod.contains(kw)) {
                        findings.add(new Finding(
                                "INJECTED_MODULE", "CRITICAL", 60,
                                "Suspicious native module loaded in Minecraft (PID " + p.pid() + ")",
                                mod,
                                List.of("Matched signature keyword: " + kw)
                        ));
                        break;
                    }
                }
                if ((lowerMod.contains("\\appdata\\local\\temp\\") || lowerMod.contains("\\downloads\\")
                        || lowerMod.contains("/tmp/") || lowerMod.contains("/downloads/"))
                        && (lowerMod.endsWith(".dll") || lowerMod.endsWith(".so") || lowerMod.endsWith(".dylib"))
                        && !isTrustedMinecraftNative(lowerMod)) {
                    findings.add(new Finding(
                            "INJECTED_MODULE", "SUSPICIOUS", 25,
                            "Native library loaded from Temp/Downloads in Minecraft (PID " + p.pid() + ")",
                            mod,
                            List.of("Unexpected native library path inside active JVM process")
                    ));
                }
            }
        }

        return new ProcessAudit(bootTime, mcProcs, findings);
    }

    private static boolean isTrustedMinecraftNative(String lowerMod) {
        String[] trusted = {
                "lwjgl", "jna", "jnidispatch", "glfw", "openal", "jansi", "netty",
                "stb", "jemalloc", "tinyfd", "shaderc", "opus", "jinput", "sapi",
                "narrator", "discord", "lunar", "badlion", "feather", "labymod",
                "ichor", "genesis", "sentry", "sqlite", "zstd", "lz4", "brotli",
                "snappy", "skia", "freetype", "harfbuzz", "libcef", "jcef",
                "libegl", "libgles", "vulkan", "angle", "oshi", "mojang", "jline"
        };
        for (String t : trusted) {
            if (lowerMod.contains(t)) {
                return true;
            }
        }
        return false;
    }

    private static String detectLauncher(String name, String lowerCmd) {
        if (lowerCmd.contains("lunar") || name.toLowerCase(Locale.ROOT).contains("lunar")) return "Lunar Client";
        if (lowerCmd.contains("badlion") || name.toLowerCase(Locale.ROOT).contains("badlion")) return "Badlion Client";
        if (lowerCmd.contains("feather")) return "Feather Client";
        if (lowerCmd.contains("fabric")) return "Fabric";
        if (lowerCmd.contains("neoforge")) return "NeoForge";
        if (lowerCmd.contains("forge")) return "Forge";
        if (lowerCmd.contains("quilt")) return "Quilt";
        if (lowerCmd.contains("prism")) return "PrismLauncher";
        return "Minecraft Java";
    }

    private static String detectMcVersion(String cmd) {
        Matcher m = VERSION_FLAG.matcher(cmd);
        if (m.find()) {
            return m.group(1);
        }
        return "Unknown";
    }

    private static String detectBootTime() {
        if (OsInfo.isWindows()) {
            List<String> lines = execLines("powershell", "-NoProfile", "-Command",
                    "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss')");
            if (!lines.isEmpty() && !lines.get(0).isBlank()) {
                return lines.get(0).trim();
            }
        } else {
            List<String> lines = execLines("uptime", "-s");
            if (!lines.isEmpty() && !lines.get(0).isBlank()) {
                return lines.get(0).trim();
            }
        }
        return "Unknown";
    }

    private static void inspectWindows(List<McProcess> out, List<Finding> findings) {
        List<String> lines = execLines(
                "powershell", "-NoProfile", "-Command",
                "Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'java|lunar|badlion|feather|minecraft' } | "
                        + "ForEach-Object { \"$($_.ProcessId)|$($_.Name)|$($_.CreationDate)|$($_.CommandLine)\" }"
        );

        long selfPid = ProcessHandle.current().pid();
        for (String line : lines) {
            String[] parts = line.split("\\|", 4);
            if (parts.length < 4) {
                continue;
            }
            long pid = parseLongSafe(parts[0].trim());
            if (pid <= 0 || pid == selfPid) {
                continue;
            }
            String name = parts[1].trim();
            String start = parts[2].trim();
            String cmd = parts[3].trim();
            String lower = cmd.toLowerCase(Locale.ROOT);
            if (!isMinecraftCommand(name, lower)) {
                continue;
            }
            List<String> mods = execLines(
                    "powershell", "-NoProfile", "-Command",
                    "(Get-Process -Id " + pid + " -ErrorAction SilentlyContinue).Modules | ForEach-Object { $_.FileName }"
            );
            out.add(new McProcess(pid, name, detectLauncher(name, lower), detectMcVersion(cmd), start, cmd, mods));
        }

        List<String> allProcs = execLines(
                "powershell", "-NoProfile", "-Command",
                "Get-CimInstance Win32_Process | ForEach-Object { \"$($_.ProcessId)|$($_.Name)|$($_.ExecutablePath)\" }"
        );
        for (String line : allProcs) {
            String[] parts = line.split("\\|", 3);
            if (parts.length < 3) {
                continue;
            }
            String name = parts[1].trim().toLowerCase(Locale.ROOT);
            String path = parts[2].trim();
            if (name.contains("processhacker") || name.contains("cheatengine") || name.contains("extremeinjector")
                    || name.contains("xenos") || name.contains("opautoclicker") || name.contains("gsautoclicker")
                    || name.contains("vape") || name.contains("slinky") || name.contains("drip")) {
                findings.add(new Finding(
                        "ACTIVE_PROCESS", "CRITICAL", 60,
                        "Active cheat/injector/autoclicker process: " + parts[1].trim(),
                        path.isEmpty() ? "PID " + parts[0].trim() : path,
                        List.of("Running PID: " + parts[0].trim())
                ));
            }
        }
    }

    private static void inspectUnix(List<McProcess> out, List<Finding> findings) {
        List<String> lines = execLines("ps", "-eo", "pid=,lstart=,args=");
        long selfPid = ProcessHandle.current().pid();

        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            String[] tokens = trimmed.split("\\s+", 7);
            if (tokens.length < 7) {
                continue;
            }
            long pid = parseLongSafe(tokens[0]);
            if (pid <= 0 || pid == selfPid) {
                continue;
            }
            String start = tokens[1] + " " + tokens[2] + " " + tokens[3] + " " + tokens[4] + " " + tokens[5];
            String cmd = tokens[6];
            String lower = cmd.toLowerCase(Locale.ROOT);
            if (!isMinecraftCommand("java", lower)) {
                continue;
            }
            List<String> mods = OsInfo.isLinux() ? readLinuxMaps(pid) : readMacModules(pid);
            out.add(new McProcess(pid, "java", detectLauncher("java", lower), detectMcVersion(cmd), start, cmd, mods));
        }

        String ldPreload = System.getenv("LD_PRELOAD");
        if (ldPreload != null && !ldPreload.isBlank()) {
            findings.add(new Finding(
                    "ENV_INJECTION", "HIGH", 35,
                    "LD_PRELOAD environment variable is active",
                    ldPreload,
                    List.of("Shared library preloading can inject code into JVM processes")
            ));
        }
        String dyld = System.getenv("DYLD_INSERT_LIBRARIES");
        if (dyld != null && !dyld.isBlank()) {
            findings.add(new Finding(
                    "ENV_INJECTION", "HIGH", 35,
                    "DYLD_INSERT_LIBRARIES environment variable is active",
                    dyld,
                    List.of("macOS dylib injection variable detected")
            ));
        }
    }

    private static List<String> readLinuxMaps(long pid) {
        Set<String> libs = new LinkedHashSet<>();
        Path maps = Path.of("/proc/" + pid + "/maps");
        if (!Files.isReadable(maps)) {
            return List.of();
        }
        try {
            for (String line : Files.readAllLines(maps, StandardCharsets.UTF_8)) {
                int idx = line.indexOf('/');
                if (idx >= 0) {
                    String path = line.substring(idx).trim();
                    if (path.endsWith(".so") || path.contains(".so.")) {
                        libs.add(path);
                    }
                }
            }
        } catch (IOException ignored) {
        }
        return new ArrayList<>(libs);
    }

    private static List<String> readMacModules(long pid) {
        Set<String> libs = new LinkedHashSet<>();
        for (String line : execLines("lsof", "-p", String.valueOf(pid))) {
            int idx = line.indexOf('/');
            if (idx >= 0) {
                String path = line.substring(idx).trim();
                if (path.endsWith(".dylib") || path.endsWith(".so")) {
                    libs.add(path);
                }
            }
        }
        return new ArrayList<>(libs);
    }

    private static boolean isMinecraftCommand(String name, String lowerCmd) {
        if (lowerCmd.contains("veritas")) {
            return false;
        }
        return lowerCmd.contains("net.minecraft") || lowerCmd.contains("minecraft")
                || lowerCmd.contains("mojang") || lowerCmd.contains("fabricmc")
                || lowerCmd.contains("minecraftforge") || lowerCmd.contains("neoforged")
                || lowerCmd.contains("lunarclient") || lowerCmd.contains("badlion")
                || lowerCmd.contains("feather") || lowerCmd.contains("optifine")
                || name.toLowerCase(Locale.ROOT).contains("lunar")
                || name.toLowerCase(Locale.ROOT).contains("badlion");
    }

    private static String trimCmd(String cmd) {
        return cmd.length() > 220 ? cmd.substring(0, 220) + "..." : cmd;
    }

    private static long parseLongSafe(String s) {
        try {
            return Long.parseLong(s);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    public static List<String> execLines(String... cmd) {
        List<String> out = new ArrayList<>();
        try {
            Process proc = new ProcessBuilder(cmd).redirectErrorStream(true).start();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) {
                    out.add(line);
                }
            }
            proc.waitFor(8, TimeUnit.SECONDS);
        } catch (Exception ignored) {
        }
        return out;
    }
}
