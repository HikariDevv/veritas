package com.dips.veritas;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class BrowserForensics {
    public record BrowserHit(String source, String domainOrUrl, String note) {
    }

    public record BrowserAudit(int browsersChecked, List<BrowserHit> hits, List<Finding> findings) {
    }

    private static final List<String> CHEAT_DOMAINS = List.of(
            "vape.gg", "slinky.gg", "drip.gg", "entropy.club", "whiteout.lol",
            "doomsdayclient.com", "prestigeclient.vip", "meteorclient.com", "wurstclient.net",
            "liquidbounce.net", "rusherhack.org", "futureclient.net", "aristois.net",
            "opautoclicker.com", "cheatengine.org", "processhacker.sourceforge.io",
            "unknowncheats.me", "anticheat.ac", "karmaclient"
    );

    private static final Pattern URL_EXTRACT = Pattern.compile("https?://[a-z0-9._\\-/:?&=%#+~]{6,180}");

    private BrowserForensics() {
    }

    public static BrowserAudit inspect() {
        List<BrowserHit> hits = new ArrayList<>();
        List<Finding> findings = new ArrayList<>();
        int checked = 0;

        List<Path> historyFiles = discoverBrowserHistoryFiles();
        for (Path hist : historyFiles) {
            checked++;
            inspectHistoryFile(hist, hits, findings);
        }

        if (OsInfo.isWindows()) {
            inspectWindowsDnsCache(hits, findings);
        } else if (OsInfo.isMac()) {
            inspectMacQuarantineEvents(hits, findings);
        } else {
            inspectUnixShellHistory(hits, findings);
        }

        return new BrowserAudit(checked, hits, findings);
    }

    private static List<Path> discoverBrowserHistoryFiles() {
        List<Path> files = new ArrayList<>();
        String home = System.getProperty("user.home", "");

        if (OsInfo.isWindows()) {
            String local = System.getenv("LOCALAPPDATA");
            String roaming = System.getenv("APPDATA");
            if (local != null) {
                addIfFile(files, Path.of(local, "Google", "Chrome", "User Data", "Default", "History"));
                addIfFile(files, Path.of(local, "Microsoft", "Edge", "User Data", "Default", "History"));
                addIfFile(files, Path.of(local, "BraveSoftware", "Brave-Browser", "User Data", "Default", "History"));
                addIfFile(files, Path.of(local, "Vivaldi", "User Data", "Default", "History"));
            }
            if (roaming != null) {
                addIfFile(files, Path.of(roaming, "Opera Software", "Opera Stable", "History"));
                addIfFile(files, Path.of(roaming, "Opera Software", "Opera GX Stable", "History"));
                addFirefoxProfiles(files, Path.of(roaming, "Mozilla", "Firefox", "Profiles"));
            }
        } else if (OsInfo.isMac()) {
            Path appSup = Path.of(home, "Library", "Application Support");
            addIfFile(files, Path.of(home, "Library", "Safari", "History.db"));
            addIfFile(files, appSup.resolve(Path.of("Google", "Chrome", "Default", "History")));
            addIfFile(files, appSup.resolve(Path.of("BraveSoftware", "Brave-Browser", "Default", "History")));
            addIfFile(files, appSup.resolve(Path.of("Microsoft Edge", "Default", "History")));
            addIfFile(files, appSup.resolve(Path.of("Arc", "User Data", "Default", "History")));
            addIfFile(files, appSup.resolve(Path.of("com.operasoftware.Opera", "History")));
            addFirefoxProfiles(files, appSup.resolve(Path.of("Firefox", "Profiles")));
        } else {
            Path cfg = Path.of(home, ".config");
            addIfFile(files, cfg.resolve(Path.of("google-chrome", "Default", "History")));
            addIfFile(files, cfg.resolve(Path.of("chromium", "Default", "History")));
            addIfFile(files, cfg.resolve(Path.of("BraveSoftware", "Brave-Browser", "Default", "History")));
            addIfFile(files, cfg.resolve(Path.of("microsoft-edge", "Default", "History")));
            addIfFile(files, cfg.resolve(Path.of("opera", "History")));
            addIfFile(files, cfg.resolve(Path.of("vivaldi", "Default", "History")));
            addFirefoxProfiles(files, Path.of(home, ".mozilla", "firefox"));
        }

        return files;
    }

    private static void addFirefoxProfiles(List<Path> files, Path profilesRoot) {
        if (!Files.isDirectory(profilesRoot)) {
            return;
        }
        try (var s = Files.list(profilesRoot)) {
            for (Path p : s.toList()) {
                addIfFile(files, p.resolve("places.sqlite"));
            }
        } catch (IOException ignored) {
        }
    }

    private static void inspectMacQuarantineEvents(List<BrowserHit> hits, List<Finding> findings) {
        Path qdb = Path.of(System.getProperty("user.home", ""),
                "Library", "Preferences", "com.apple.LaunchServices.QuarantineEventsV2");
        if (!Files.isReadable(qdb)) {
            return;
        }
        try {
            byte[] raw = Files.readAllBytes(qdb);
            String ascii = extractPrintableLower(raw, Math.min(raw.length, 4 * 1024 * 1024));
            Set<String> matched = new LinkedHashSet<>();
            for (String dom : CHEAT_DOMAINS) {
                if (ascii.contains(dom)) {
                    matched.add(dom);
                }
            }
            if (!matched.isEmpty()) {
                List<String> details = new ArrayList<>();
                for (String d : matched) {
                    String url = findSampleUrl(ascii, d);
                    hits.add(new BrowserHit("macOS QuarantineEventsV2 (Survives History Clear)", url, "Download origin"));
                    details.add(url);
                }
                findings.add(new Finding(
                        "MACOS_QUARANTINE_DB", "CRITICAL", 55,
                        "Cheat download origin recovered from macOS QuarantineEventsV2",
                        qdb.toString(),
                        details
                ));
            }
        } catch (IOException ignored) {
        }
    }

    private static void inspectUnixShellHistory(List<BrowserHit> hits, List<Finding> findings) {
        String home = System.getProperty("user.home", "");
        List<Path> histFiles = List.of(
                Path.of(home, ".bash_history"),
                Path.of(home, ".zsh_history"),
                Path.of(home, ".local", "share", "fish", "fish_history")
        );
        for (Path hf : histFiles) {
            if (!Files.isReadable(hf)) {
                continue;
            }
            try {
                String content = Files.readString(hf, StandardCharsets.UTF_8).toLowerCase(Locale.ROOT);
                List<String> matched = new ArrayList<>();
                for (String dom : CHEAT_DOMAINS) {
                    if (content.contains(dom)) {
                        matched.add(dom);
                        hits.add(new BrowserHit(hf.getFileName().toString(), dom, "Shell download/command trace"));
                    }
                }
                if (content.contains("ld_preload") || content.contains("dyld_insert_libraries")) {
                    matched.add("LD_PRELOAD / DYLD injection command");
                }
                if (!matched.isEmpty()) {
                    findings.add(new Finding(
                            "SHELL_HISTORY", "HIGH", 40,
                            "Suspicious cheat/injection command in " + hf.getFileName(),
                            hf.toString(),
                            matched
                    ));
                }
            } catch (IOException ignored) {
            }
        }
    }

    private static void inspectHistoryFile(Path hist, List<BrowserHit> hits, List<Finding> findings) {
        String browser = guessBrowserName(hist);
        Path tmpCopy = null;
        try {
            long size = Files.size(hist);
            Instant mtime = Files.getLastModifiedTime(hist).toInstant();
            long minsAgo = Duration.between(mtime, Instant.now()).toMinutes();

            if (size <= 45_000 && minsAgo >= 0 && minsAgo <= 30) {
                findings.add(new Finding(
                        "BROWSER_WIPED", "HIGH", 35,
                        browser + " history database appears freshly cleared (" + ConsoleUi.formatBytes(size) + ")",
                        hist.toString(),
                        List.of("Modified " + minsAgo + " min ago with minimal SQLite size (possible history clear before SS)")
                ));
            }

            tmpCopy = Files.createTempFile("veritas_hist_", ".db");
            Files.copy(hist, tmpCopy, StandardCopyOption.REPLACE_EXISTING);
            byte[] raw = Files.readAllBytes(tmpCopy);
            int limit = Math.min(raw.length, 6 * 1024 * 1024);
            String ascii = extractPrintableLower(raw, limit);

            Set<String> matchedDomains = new LinkedHashSet<>();
            for (String dom : CHEAT_DOMAINS) {
                if (ascii.contains(dom)) {
                    matchedDomains.add(dom);
                }
            }

            if (!matchedDomains.isEmpty()) {
                List<String> details = new ArrayList<>();
                for (String dom : matchedDomains) {
                    String sampleUrl = findSampleUrl(ascii, dom);
                    hits.add(new BrowserHit(browser + " History", sampleUrl, "Matched cheat domain: " + dom));
                    details.add(sampleUrl);
                }
                findings.add(new Finding(
                        "BROWSER_HISTORY", "HIGH", 40,
                        browser + " history contains cheat website traces (" + matchedDomains.size() + " domain(s))",
                        hist.toString(),
                        details
                ));
            }
        } catch (IOException ignored) {
        } finally {
            if (tmpCopy != null) {
                try {
                    Files.deleteIfExists(tmpCopy);
                } catch (IOException ignored) {
                }
            }
        }
    }

    private static void inspectWindowsDnsCache(List<BrowserHit> hits, List<Finding> findings) {
        List<String> lines = ProcessInspector.execLines("ipconfig", "/displaydns");
        Set<String> dnsMatches = new LinkedHashSet<>();

        for (String line : lines) {
            String lower = line.toLowerCase(Locale.ROOT);
            for (String dom : CHEAT_DOMAINS) {
                if (lower.contains(dom)) {
                    dnsMatches.add(dom);
                }
            }
        }

        if (!dnsMatches.isEmpty()) {
            List<String> details = new ArrayList<>();
            for (String d : dnsMatches) {
                hits.add(new BrowserHit("Windows DNS Cache (Survives History Clear / Incognito)", d, "Active DNS resolver record"));
                details.add("DNS Record: " + d);
            }
            findings.add(new Finding(
                    "DNS_CACHE_RECOVERY", "CRITICAL", 50,
                    "Cheat domain recovered from Windows DNS Cache (" + dnsMatches.size() + " domain(s))",
                    "ipconfig /displaydns",
                    details
            ));
        }
    }

    private static String findSampleUrl(String ascii, String domain) {
        int idx = ascii.indexOf(domain);
        if (idx < 0) {
            return domain;
        }
        int start = Math.max(0, idx - 32);
        int end = Math.min(ascii.length(), idx + 120);
        Matcher m = URL_EXTRACT.matcher(ascii.substring(start, end));
        while (m.find()) {
            if (m.group().contains(domain)) {
                return m.group();
            }
        }
        return domain;
    }

    private static String extractPrintableLower(byte[] data, int limit) {
        StringBuilder sb = new StringBuilder(limit / 2);
        for (int i = 0; i < limit; i++) {
            int b = data[i] & 0xFF;
            sb.append(b >= 32 && b <= 126 ? (char) Character.toLowerCase(b) : ' ');
        }
        return sb.toString();
    }

    private static String guessBrowserName(Path p) {
        String s = p.toString().toLowerCase(Locale.ROOT);
        if (s.contains("safari")) return "Safari";
        if (s.contains("firefox") || s.contains("mozilla")) return "Firefox";
        if (s.contains("arc")) return "Arc";
        if (s.contains("brave")) return "Brave";
        if (s.contains("edge")) return "Microsoft Edge";
        if (s.contains("opera gx")) return "Opera GX";
        if (s.contains("opera")) return "Opera";
        if (s.contains("vivaldi")) return "Vivaldi";
        if (s.contains("chromium")) return "Chromium";
        return "Google Chrome";
    }

    private static void addIfFile(List<Path> list, Path p) {
        if (Files.isRegularFile(p)) {
            list.add(p);
        }
    }
}
