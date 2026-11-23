package com.dips.veritas;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public final class ReplaceDetector {
    private static final Map<String, List<String>> LEGIT_MOD_EXPECTED_PACKAGES = new LinkedHashMap<>();

    static {
        LEGIT_MOD_EXPECTED_PACKAGES.put("optifine", List.of("net/optifine/", "optifine/"));
        LEGIT_MOD_EXPECTED_PACKAGES.put("sodium", List.of("me/jellysquid/mods/sodium/", "net/caffeinemc/mods/sodium/"));
        LEGIT_MOD_EXPECTED_PACKAGES.put("lithium", List.of("me/jellysquid/mods/lithium/", "net/caffeinemc/mods/lithium/"));
        LEGIT_MOD_EXPECTED_PACKAGES.put("iris", List.of("net/coderbot/iris/", "net/irisshaders/"));
        LEGIT_MOD_EXPECTED_PACKAGES.put("phosphor", List.of("me/jellysquid/mods/phosphor/"));
        LEGIT_MOD_EXPECTED_PACKAGES.put("patcher", List.of("club/sk1er/patcher/"));
        LEGIT_MOD_EXPECTED_PACKAGES.put("essential", List.of("gg/essential/"));
        LEGIT_MOD_EXPECTED_PACKAGES.put("labymod", List.of("net/labymod/"));
        LEGIT_MOD_EXPECTED_PACKAGES.put("badlion", List.of("net/badlion/"));
        LEGIT_MOD_EXPECTED_PACKAGES.put("replaymod", List.of("com/replaymod/"));
    }

    public record ReplaceAudit(int filesChecked, List<Finding> findings) {
    }

    private ReplaceDetector() {
    }

    public static ReplaceAudit scan(List<Path> mcDirs) {
        List<Finding> findings = new ArrayList<>();
        int[] checked = {0};

        for (Path root : mcDirs) {
            inspectModDirs(root, checked, findings);
        }

        for (Path binRoot : BinaryScanner.defaultScanRoots()) {
            inspectRecentReplacesInDir(binRoot, checked, findings);
        }

        return new ReplaceAudit(checked[0], findings);
    }

    private static void inspectModDirs(Path root, int[] checked, List<Finding> findings) {
        try (Stream<Path> walk = Files.walk(root, 4)) {
            for (Path p : walk.filter(Files::isRegularFile).toList()) {
                String lowerName = p.getFileName().toString().toLowerCase(Locale.ROOT);
                String fullLower = p.toAbsolutePath().toString().toLowerCase(Locale.ROOT);
                if (!lowerName.endsWith(".jar")) {
                    continue;
                }
                if (!fullLower.contains("\\mods\\") && !fullLower.contains("/mods/")
                        && !fullLower.contains("\\versions\\") && !fullLower.contains("/versions/")) {
                    continue;
                }
                checked[0]++;
                checkJarReplaceSignals(p, lowerName, findings);
            }
        } catch (IOException ignored) {
        }
    }

    private static void checkJarReplaceSignals(Path jar, String lowerName, List<Finding> findings) {
        try {
            BasicFileAttributes attrs = Files.readAttributes(jar, BasicFileAttributes.class);
            Instant created = attrs.creationTime().toInstant();
            Instant modified = attrs.lastModifiedTime().toInstant();
            Instant now = Instant.now();

            long modMinsAgo = Duration.between(modified, now).toMinutes();
            long createMinusModSec = Duration.between(modified, created).getSeconds();

            List<String> reasons = new ArrayList<>();
            int weight = 0;

            for (Map.Entry<String, List<String>> entry : LEGIT_MOD_EXPECTED_PACKAGES.entrySet()) {
                if (lowerName.contains(entry.getKey())) {
                    if (!jarContainsAnyPrefix(jar, entry.getValue())) {
                        weight += 65;
                        reasons.add("MOD REPLACE DETECTED: named '" + jar.getFileName()
                                + "' but missing expected package (" + String.join(" or ", entry.getValue()) + ")");
                    }
                    break;
                }
            }

            if (modMinsAgo >= 0 && modMinsAgo <= 20) {
                weight += 30;
                reasons.add("JAR modified/replaced very recently (" + modMinsAgo + " min ago)");
            }

            if (createMinusModSec > 120 && modMinsAgo >= 0 && modMinsAgo <= 180) {
                weight += 25;
                reasons.add("Copy-replace timestamp anomaly: Created (" + created + ") is newer than Modified (" + modified + ")");
            }

            if (OsInfo.isWindows()) {
                String zoneUrl = readZoneIdentifierUrl(jar);
                if (zoneUrl != null && !zoneUrl.isBlank()) {
                    String zLow = zoneUrl.toLowerCase(Locale.ROOT);
                    if (zLow.contains("vape") || zLow.contains("slinky") || zLow.contains("drip")
                            || zLow.contains("doomsday") || zLow.contains("prestige") || zLow.contains("mediafire")
                            || zLow.contains("mega.nz") || zLow.contains("discord")) {
                        weight += 30;
                        reasons.add("NTFS Zone.Identifier download source: " + zoneUrl);
                    }
                }
            }

            if (weight >= 30) {
                reasons.add("Created: " + created + " | Modified: " + modified + " | Size: " + ConsoleUi.formatBytes(attrs.size()));
                reasons.add("SHA-256: " + sha256File(jar));
                String sev = weight >= 65 ? "CRITICAL" : (weight >= 45 ? "HIGH" : "SUSPICIOUS");
                findings.add(new Finding(
                        "REPLACE_METHOD", sev, Math.min(100, weight),
                        "Possible file replace / spoofed JAR: " + jar.getFileName(),
                        jar.toAbsolutePath().toString(),
                        reasons
                ));
            }
        } catch (IOException ignored) {
        }
    }

    private static void inspectRecentReplacesInDir(Path dir, int[] checked, List<Finding> findings) {
        if (!Files.isDirectory(dir)) {
            return;
        }
        try (Stream<Path> s = Files.list(dir)) {
            for (Path p : s.toList()) {
                if (!Files.isRegularFile(p)) {
                    continue;
                }
                String lower = p.getFileName().toString().toLowerCase(Locale.ROOT);
                if (!lower.endsWith(".exe") && !lower.endsWith(".dll") && !lower.endsWith(".so") && !lower.endsWith(".dylib")) {
                    continue;
                }
                checked[0]++;
                BasicFileAttributes attrs = Files.readAttributes(p, BasicFileAttributes.class);
                Instant created = attrs.creationTime().toInstant();
                Instant modified = attrs.lastModifiedTime().toInstant();
                Instant now = Instant.now();

                long modMinsAgo = Duration.between(modified, now).toMinutes();
                long createdAgeMins = Duration.between(created, now).toMinutes();

                if (modMinsAgo >= 0 && modMinsAgo <= 15 && createdAgeMins > 60) {
                    findings.add(new Finding(
                            "REPLACE_METHOD", "HIGH", 40,
                            "Existing binary overwritten in-place (" + modMinsAgo + " min ago): " + p.getFileName(),
                            p.toAbsolutePath().toString(),
                            List.of(
                                    "Original CreationTime: " + created + " (" + createdAgeMins + " min ago)",
                                    "Overwritten LastModifiedTime: " + modified + " (" + modMinsAgo + " min ago)",
                                    "SHA-256: " + sha256File(p)
                            )
                    ));
                }
            }
        } catch (IOException ignored) {
        }
    }

    private static boolean jarContainsAnyPrefix(Path jar, List<String> prefixes) {
        try (ZipFile zf = new ZipFile(jar.toFile())) {
            Enumeration<? extends ZipEntry> entries = zf.entries();
            int count = 0;
            while (entries.hasMoreElements() && count < 5000) {
                ZipEntry e = entries.nextElement();
                count++;
                String en = e.getName().toLowerCase(Locale.ROOT);
                for (String pref : prefixes) {
                    if (en.startsWith(pref)) {
                        return true;
                    }
                }
            }
        } catch (IOException ignored) {
            return true;
        }
        return false;
    }

    private static String readZoneIdentifierUrl(Path file) {
        java.io.File ads = new java.io.File(file.toAbsolutePath() + ":Zone.Identifier");
        if (!ads.isFile()) {
            return null;
        }
        try (java.io.BufferedReader br = new java.io.BufferedReader(
                new java.io.InputStreamReader(new java.io.FileInputStream(ads), StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.startsWith("HostUrl=")) {
                    return line.substring("HostUrl=".length()).trim();
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    public static String sha256File(Path file) {
        try {
            byte[] data = Files.readAllBytes(file);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] h = md.digest(data);
            StringBuilder sb = new StringBuilder(h.length * 2);
            for (byte b : h) {
                sb.append(String.format(Locale.ROOT, "%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "unavailable";
        }
    }
}
