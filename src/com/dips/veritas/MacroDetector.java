package com.dips.veritas;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;

public final class MacroDetector {
    public record MacroAudit(int scriptsFound, List<String> mouseSoftware, List<Finding> findings) {
    }

    private static final List<String> MACRO_EXTS = List.of(".ahk", ".rec", ".amc", ".mgn", ".gmacro", ".mcr");

    private static final List<String> MACRO_PROCS = List.of(
            "autohotkey", "tinytask", "xmousebuttoncontrol", "macrorecorder",
            "opautoclicker", "gsautoclicker", "speedautoclicker", "fastclicker"
    );

    private MacroDetector() {
    }

    public static MacroAudit inspect() {
        List<Finding> findings = new ArrayList<>();
        List<String> mouseSoftware = new ArrayList<>();
        int[] scriptsFound = {0};

        if (OsInfo.isWindows()) {
            checkWindowsMacroProcesses(findings);
            checkWindowsMouseSoftware(mouseSoftware, findings);
        } else {
            checkUnixMacroProcesses(findings);
        }

        String home = System.getProperty("user.home", "");
        List<Path> dirs = List.of(
                Path.of(home, "Desktop"),
                Path.of(home, "Downloads"),
                Path.of(home, "Documents")
        );

        for (Path dir : dirs) {
            if (!Files.isDirectory(dir)) {
                continue;
            }
            try {
                Files.walkFileTree(dir, java.util.Set.of(), 2, new java.nio.file.SimpleFileVisitor<>() {
                    @Override
                    public java.nio.file.FileVisitResult visitFile(Path p, java.nio.file.attribute.BasicFileAttributes attrs) {
                        if (!attrs.isRegularFile()) {
                            return java.nio.file.FileVisitResult.CONTINUE;
                        }
                        String lower = p.getFileName().toString().toLowerCase(Locale.ROOT);
                        for (String ext : MACRO_EXTS) {
                            if (lower.endsWith(ext)) {
                                scriptsFound[0]++;
                                findings.add(new Finding(
                                        "MACRO_SCRIPT", "HIGH", 40,
                                        "Macro/automation script detected: " + p.getFileName(),
                                        p.toAbsolutePath().toString(),
                                        List.of("Extension: " + ext, "Last modified: " + attrs.lastModifiedTime())
                                ));
                                break;
                            }
                        }
                        return java.nio.file.FileVisitResult.CONTINUE;
                    }

                    @Override
                    public java.nio.file.FileVisitResult visitFileFailed(Path file, IOException exc) {
                        return java.nio.file.FileVisitResult.CONTINUE;
                    }
                });
            } catch (Exception ignored) {
            }
        }

        return new MacroAudit(scriptsFound[0], mouseSoftware, findings);
    }

    private static void checkWindowsMacroProcesses(List<Finding> findings) {
        List<String> lines = ProcessInspector.execLines(
                "powershell", "-NoProfile", "-Command",
                "Get-Process | ForEach-Object { \"$($_.Id)|$($_.ProcessName)\" }"
        );
        for (String line : lines) {
            String[] parts = line.split("\\|", 2);
            if (parts.length < 2) {
                continue;
            }
            String lower = parts[1].trim().toLowerCase(Locale.ROOT);
            for (String mp : MACRO_PROCS) {
                if (lower.contains(mp)) {
                    findings.add(new Finding(
                            "MACRO_ACTIVE", "CRITICAL", 55,
                            "Active macro/autoclicker process running: " + parts[1].trim(),
                            "PID " + parts[0].trim(),
                            List.of("Matched macro tool: " + mp)
                    ));
                    break;
                }
            }
        }
    }

    private static void checkUnixMacroProcesses(List<Finding> findings) {
        for (String line : ProcessInspector.execLines("ps", "-eo", "pid=,comm=")) {
            String lower = line.toLowerCase(Locale.ROOT);
            if (lower.contains("xdotool") || lower.contains("ydotool") || lower.contains("autoclick")) {
                findings.add(new Finding(
                        "MACRO_ACTIVE", "HIGH", 40,
                        "Active input automation tool detected",
                        line.trim(),
                        List.of("Input injection/autoclicker utility running")
                ));
            }
        }
    }

    private static void checkWindowsMouseSoftware(List<String> software, List<Finding> findings) {
        String local = System.getenv("LOCALAPPDATA");
        String appData = System.getenv("APPDATA");
        String progData = System.getenv("ProgramData");

        checkSoftwarePath(software, findings, "Logitech G HUB", local != null ? Path.of(local, "LGHUB", "settings.db") : null);
        checkSoftwarePath(software, findings, "Razer Synapse", progData != null ? Path.of(progData, "Razer", "Synapse3") : null);
        checkSoftwarePath(software, findings, "Glorious Core", appData != null ? Path.of(appData, "Glorious Core") : null);
        checkSoftwarePath(software, findings, "Bloody7", Path.of("C:\\Program Files (x86)\\Bloody7"));
        checkSoftwarePath(software, findings, "Corsair iCUE", appData != null ? Path.of(appData, "Corsair", "CUE") : null);
        checkSoftwarePath(software, findings, "SteelSeries GG", progData != null ? Path.of(progData, "SteelSeries", "GG") : null);
    }

    private static void checkSoftwarePath(List<String> software, List<Finding> findings, String name, Path path) {
        if (path == null || !Files.exists(path)) {
            return;
        }
        software.add(name);
        try {
            Instant mtime = Files.getLastModifiedTime(path).toInstant();
            long minsAgo = Duration.between(mtime, Instant.now()).toMinutes();
            if (minsAgo >= 0 && minsAgo <= 30) {
                findings.add(new Finding(
                        "MOUSE_MACRO_CFG", "SUSPICIOUS", 20,
                        name + " configuration modified " + minsAgo + " min ago",
                        path.toString(),
                        List.of("Last modified: " + mtime, "Inspect mouse profiles/macros in " + name)
                ));
            }
        } catch (IOException ignored) {
        }
    }
}
