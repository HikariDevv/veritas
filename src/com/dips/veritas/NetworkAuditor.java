package com.dips.veritas;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public final class NetworkAuditor {
    public record NetAudit(int listeningCount, List<Finding> findings) {
    }

    private static final List<Integer> SUSPICIOUS_LOCAL_PORTS = List.of(
            1337, 4444, 6666, 7777, 8443, 9999, 13337, 31337
    );

    private NetworkAuditor() {
    }

    public static NetAudit inspect() {
        List<Finding> findings = new ArrayList<>();
        int listening = 0;

        if (OsInfo.isWindows()) {
            List<String> lines = ProcessInspector.execLines("netstat", "-ano", "-p", "TCP");
            for (String line : lines) {
                String t = line.trim();
                if (!t.startsWith("TCP")) {
                    continue;
                }
                String[] parts = t.split("\\s+");
                if (parts.length < 5) {
                    continue;
                }
                String localAddr = parts[1];
                String state = parts[3];
                String pid = parts[4];
                if ("LISTENING".equalsIgnoreCase(state)) {
                    listening++;
                    int port = parsePort(localAddr);
                    if (SUSPICIOUS_LOCAL_PORTS.contains(port)) {
                        findings.add(new Finding(
                                "NET_LISTENER", "SUSPICIOUS", 20,
                                "Suspicious local TCP listener on port " + port + " (PID " + pid + ")",
                                localAddr,
                                List.of("Local proxy/crack/loader port listening on " + localAddr)
                        ));
                    }
                }
            }
        } else {
            List<String> lines = OsInfo.isMac()
                    ? ProcessInspector.execLines("lsof", "-iTCP", "-sTCP:LISTEN", "-n", "-P")
                    : ProcessInspector.execLines("ss", "-tln");
            for (String line : lines) {
                String lower = line.toLowerCase(Locale.ROOT);
                if (lower.contains("listen")) {
                    listening++;
                }
            }
        }

        return new NetAudit(listening, findings);
    }

    private static int parsePort(String addr) {
        int colon = addr.lastIndexOf(':');
        if (colon < 0) {
            return -1;
        }
        try {
            return Integer.parseInt(addr.substring(colon + 1));
        } catch (NumberFormatException e) {
            return -1;
        }
    }
}
