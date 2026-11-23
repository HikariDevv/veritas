package com.dips.veritas;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public final class TamperAuditor {
    public record TamperAudit(int checksRun, List<Finding> findings) {
    }

    private TamperAuditor() {
    }

    public static TamperAudit inspect() {
        List<Finding> findings = new ArrayList<>();
        int checks = 0;

        if (OsInfo.isWindows()) {
            checks++;
            checkEventLogCleared(findings);
            checks++;
            checkSystemClockTamper(findings);
            checks++;
            checkRecentDriverInstall(findings);
        } else {
            checks++;
            checkUnixHistoryWipe(findings);
        }

        return new TamperAudit(checks, findings);
    }

    private static void checkEventLogCleared(List<Finding> findings) {
        List<String> sysClear = ProcessInspector.execLines(
                "wevtutil", "qe", "System", "/q:*[System[(EventID=104)]]", "/c:1", "/rd:true", "/f:text"
        );
        for (String line : sysClear) {
            if (line.trim().startsWith("Date:")) {
                findings.add(new Finding(
                        "LOG_TAMPER", "HIGH", 40,
                        "Windows System Event Log was cleared (Event ID 104)",
                        "EventLog -> System",
                        List.of(line.trim(), "Clearing Windows Event Logs is a common anti-SS tactic")
                ));
                break;
            }
        }

        List<String> secClear = ProcessInspector.execLines(
                "wevtutil", "qe", "Security", "/q:*[System[(EventID=1102)]]", "/c:1", "/rd:true", "/f:text"
        );
        for (String line : secClear) {
            if (line.trim().startsWith("Date:")) {
                findings.add(new Finding(
                        "LOG_TAMPER", "CRITICAL", 50,
                        "Windows Security Audit Log was cleared (Event ID 1102)",
                        "EventLog -> Security",
                        List.of(line.trim(), "Security log wipe detected")
                ));
                break;
            }
        }
    }

    private static void checkSystemClockTamper(List<Finding> findings) {
        List<String> lines = ProcessInspector.execLines(
                "wevtutil", "qe", "Security", "/q:*[System[(EventID=4616)]]", "/c:1", "/rd:true", "/f:text"
        );
        for (String line : lines) {
            if (line.trim().startsWith("Date:")) {
                findings.add(new Finding(
                        "CLOCK_TAMPER", "SUSPICIOUS", 20,
                        "System clock change recorded (Event ID 4616)",
                        "EventLog -> Security",
                        List.of(line.trim(), "Changing system time can spoof Prefetch/file timestamps")
                ));
                break;
            }
        }
    }

    private static void checkRecentDriverInstall(List<Finding> findings) {
        List<String> lines = ProcessInspector.execLines(
                "powershell", "-NoProfile", "-Command",
                "Get-WinEvent -FilterHashtable @{LogName='System';Id=7045;StartTime=(Get-Date).AddHours(-12)} -ErrorAction SilentlyContinue | "
                        + "Select-Object -First 5 | ForEach-Object { \"$($_.TimeCreated)|$($_.Message -replace '\\r|\\n',' ')\" }"
        );
        for (String line : lines) {
            String lower = line.toLowerCase();
            if (lower.contains(".sys") && (lower.contains("\\temp\\") || lower.contains("\\downloads\\") || lower.contains("cheat") || lower.contains("inject"))) {
                findings.add(new Finding(
                        "KERNEL_DRIVER", "CRITICAL", 55,
                        "Suspicious kernel service/driver installed in last 12h (Event 7045)",
                        "EventLog -> System",
                        List.of(line.length() > 220 ? line.substring(0, 220) + "..." : line)
                ));
            }
        }
    }

    private static void checkUnixHistoryWipe(List<Finding> findings) {
        String home = System.getProperty("user.home", "");
        for (Path p : List.of(Path.of(home, ".bash_history"), Path.of(home, ".zsh_history"))) {
            if (!Files.isRegularFile(p)) {
                continue;
            }
            try {
                long sz = Files.size(p);
                long mins = Duration.between(Files.getLastModifiedTime(p).toInstant(), Instant.now()).toMinutes();
                if (sz == 0 && mins >= 0 && mins <= 30) {
                    findings.add(new Finding(
                            "LOG_TAMPER", "HIGH", 35,
                            "Shell history file was wiped to 0 bytes " + mins + " min ago",
                            p.toString(),
                            List.of("Possible attempt to hide terminal commands before SS")
                    ));
                }
            } catch (IOException ignored) {
            }
        }
    }
}
