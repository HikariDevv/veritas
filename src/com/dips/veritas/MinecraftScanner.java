package com.dips.veritas;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public final class MinecraftScanner {
    private static final List<String> KNOWN_CLIENTS = List.of(
            "vape", "slinky", "drip", "entropy", "whiteout", "koid", "itami", "lithiumlite",
            "karma", "doomsday", "prestige", "liquidbounce", "wurst", "meteorclient",
            "aristois", "impactclient", "futureclient", "rusherhack", "ravenb+", "ravenb3",
            "ravenxd", "augustus", "riseclient", "sigma", "novoline", "moonclient",
            "exhibition", "tenacity", "fdpclient", "bleachhack", "phobos", "kami-blue",
            "baritone", "xray-ultimate", "autoclicker"
    );

    private static final List<String> CHEAT_MODULES = List.of(
            "killaura", "autoclicker", "aimassist", "triggerbot", "reachmodule",
            "velocitymodule", "scaffoldwalk", "antibot", "critmodule", "blinkmodule",
            "backtrack", "wtap", "fastplace", "cheststealer", "playeresp",
            "tracers", "flyhack", "speedhack", "noslow", "timerhack", "selfdestruct"
    );

    private static final List<String> BYTECODE_CHEAT_STRINGS = List.of(
            "selfdestruct", "killaura", "aimassist", "triggerbot", "autoclicker",
            "vape.gg", "slinky.gg", "drip.gg", "doomsdayclient", "prestigeclient",
            "discord.com/api/webhooks/"
    );

    public record MinecraftAudit(List<Path> discoveredDirs, int jarsScanned, List<Finding> findings) {
    }

    private MinecraftScanner() {
    }

    public static List<Path> discoverMinecraftDirs() {
        Set<Path> dirs = new LinkedHashSet<>();
        String home = System.getProperty("user.home", "");

        if (OsInfo.isWindows()) {
            String appData = System.getenv("APPDATA");
            if (appData != null) {
                addIfDir(dirs, Path.of(appData, ".minecraft"));
                addIfDir(dirs, Path.of(appData, "PrismLauncher", "instances"));
                addIfDir(dirs, Path.of(appData, "ATLauncher", "instances"));
                addIfDir(dirs, Path.of(appData, ".feather"));
                addIfDir(dirs, Path.of(appData, "ModrinthApp", "profiles"));
            }
            addIfDir(dirs, Path.of(home, ".lunarclient"));
            addIfDir(dirs, Path.of(home, ".badlion"));
        } else if (OsInfo.isMac()) {
            addIfDir(dirs, Path.of(home, "Library", "Application Support", "minecraft"));
            addIfDir(dirs, Path.of(home, "Library", "Application Support", "PrismLauncher", "instances"));
            addIfDir(dirs, Path.of(home, "Library", "Application Support", "ModrinthApp", "profiles"));
            addIfDir(dirs, Path.of(home, ".lunarclient"));
        } else {
            addIfDir(dirs, Path.of(home, ".minecraft"));
            addIfDir(dirs, Path.of(home, ".local", "share", "PrismLauncher", "instances"));
            addIfDir(dirs, Path.of(home, ".local", "share", "MultiMC", "instances"));
            addIfDir(dirs, Path.of(home, ".local", "share", "ModrinthApp", "profiles"));
            addIfDir(dirs, Path.of(home, ".lunarclient"));
        }

        return new ArrayList<>(dirs);
    }

    public static MinecraftAudit scan(List<Path> extraPaths, boolean deepBytecode) {
        Set<Path> roots = new LinkedHashSet<>(discoverMinecraftDirs());
        if (extraPaths != null) {
            for (Path p : extraPaths) {
                if (Files.exists(p)) {
                    roots.add(p.toAbsolutePath().normalize());
                }
            }
        }

        List<Finding> findings = new ArrayList<>();
        int[] jarsScanned = {0};

        for (Path root : roots) {
            checkRecentModsModification(root, findings);
            scanRoot(root, jarsScanned, findings, deepBytecode);
        }

        return new MinecraftAudit(new ArrayList<>(roots), jarsScanned[0], findings);
    }

    private static void checkRecentModsModification(Path root, List<Finding> findings) {
        Path mods = root.resolve("mods");
        if (!Files.isDirectory(mods)) {
            return;
        }
        try {
            Instant modified = Files.getLastModifiedTime(mods).toInstant();
            long minsAgo = Duration.between(modified, Instant.now()).toMinutes();
            if (minsAgo >= 0 && minsAgo <= 20) {
                findings.add(new Finding(
                        "TIMELINE_TAMPER", "SUSPICIOUS", 25,
                        "Minecraft mods folder modified recently (" + minsAgo + " min ago)",
                        mods.toAbsolutePath().toString(),
                        List.of("Last modified: " + modified)
                ));
            }
        } catch (IOException ignored) {
        }
    }

    private static void scanRoot(Path root, int[] jarsScanned, List<Finding> findings, boolean deepBytecode) {
        try (Stream<Path> walk = Files.walk(root, 5)) {
            List<Path> paths = walk.filter(Files::isRegularFile).toList();
            for (Path p : paths) {
                String name = p.getFileName().toString().toLowerCase(Locale.ROOT);
                String fullLower = p.toAbsolutePath().toString().toLowerCase(Locale.ROOT);

                if (name.endsWith(".jar")) {
                    if (fullLower.contains("libraries") && !nameMatchesCheat(name)) {
                        continue;
                    }
                    jarsScanned[0]++;
                    inspectJar(p, name, findings, deepBytecode || fullLower.contains("\\mods\\") || fullLower.contains("/mods/"));
                } else if (name.equals("latest.log") && fullLower.contains("logs")) {
                    inspectLatestLog(p, findings);
                } else if ((name.endsWith(".zip") || name.endsWith(".mcpack")) && fullLower.contains("resourcepacks")) {
                    if (name.contains("xray") || name.contains("x-ray")) {
                        findings.add(new Finding(
                                "RESOURCEPACK", "HIGH", 35,
                                "X-Ray resource pack detected: " + p.getFileName(),
                                p.toAbsolutePath().toString(),
                                List.of("Resource pack name matches X-Ray pattern")
                        ));
                    }
                }
            }
        } catch (IOException ignored) {
        }
    }

    public static void inspectJar(Path jarPath, String lowerName, List<Finding> findings, boolean inspectBytecode) {
        List<String> reasons = new ArrayList<>();
        int weight = 0;

        for (String client : KNOWN_CLIENTS) {
            if (lowerName.contains(client)) {
                weight += 55;
                reasons.add("JAR filename matches cheat client signature: " + client);
                break;
            }
        }

        Set<String> matchedModules = new LinkedHashSet<>();
        Set<String> matchedClients = new LinkedHashSet<>();
        Set<String> bytecodeHits = new LinkedHashSet<>();
        boolean hasAgentManifest = false;

        try (ZipFile zf = new ZipFile(jarPath.toFile())) {
            Enumeration<? extends ZipEntry> entries = zf.entries();
            int entryCount = 0;
            int classBytesInspected = 0;
            while (entries.hasMoreElements() && entryCount < 4500) {
                ZipEntry e = entries.nextElement();
                entryCount++;
                String en = e.getName().toLowerCase(Locale.ROOT);

                if (en.equals("meta-inf/manifest.mf")) {
                    String mf = readBoundedText(zf, e, 8192).toLowerCase(Locale.ROOT);
                    if (mf.contains("premain-class") || mf.contains("agent-class")) {
                        hasAgentManifest = true;
                    }
                }
                for (String client : KNOWN_CLIENTS) {
                    if (en.contains("/" + client + "/") || en.startsWith(client + "/")) {
                        matchedClients.add(client);
                    }
                }
                for (String mod : CHEAT_MODULES) {
                    if (en.contains(mod)) {
                        matchedModules.add(mod);
                    }
                }
                if (inspectBytecode && en.endsWith(".class") && classBytesInspected < 2 * 1024 * 1024 && e.getSize() > 0 && e.getSize() < 128 * 1024) {
                    String clsText = readBoundedText(zf, e, 32768).toLowerCase(Locale.ROOT);
                    classBytesInspected += clsText.length();
                    for (String sig : BYTECODE_CHEAT_STRINGS) {
                        if (clsText.contains(sig)) {
                            bytecodeHits.add(sig);
                        }
                    }
                }
            }
        } catch (IOException ignored) {
            return;
        }

        if (!matchedClients.isEmpty()) {
            weight += 60;
            reasons.add("Internal package matches cheat client: " + String.join(", ", matchedClients));
        }
        if (matchedModules.size() >= 3) {
            weight += 55;
            reasons.add("Multiple cheat module classes (" + matchedModules.size() + "): " + String.join(", ", matchedModules));
        } else if (matchedModules.size() == 2) {
            weight += 30;
            reasons.add("Suspicious module classes: " + String.join(", ", matchedModules));
        }
        if (bytecodeHits.size() >= 2) {
            weight += 50;
            reasons.add("Deep .class bytecode strings matched: " + String.join(", ", bytecodeHits));
        }
        if (hasAgentManifest && (!matchedModules.isEmpty() || !matchedClients.isEmpty() || !bytecodeHits.isEmpty())) {
            weight += 25;
            reasons.add("Java Instrumentation agent manifest (Premain-Class/Agent-Class)");
        }

        if (weight >= 30) {
            String sev = weight >= 65 ? "CRITICAL" : (weight >= 45 ? "HIGH" : "SUSPICIOUS");
            findings.add(new Finding(
                    "MINECRAFT_JAR", sev, Math.min(100, weight),
                    "Suspicious Minecraft JAR: " + jarPath.getFileName(),
                    jarPath.toAbsolutePath().toString(),
                    reasons
            ));
        }
    }

    private static void inspectLatestLog(Path logPath, List<Finding> findings) {
        try {
            long size = Files.size(logPath);
            if (size <= 0 || size > 10L * 1024L * 1024L) {
                return;
            }
            String content = Files.readString(logPath, StandardCharsets.UTF_8).toLowerCase(Locale.ROOT);
            List<String> hits = new ArrayList<>();
            for (String client : KNOWN_CLIENTS) {
                if (content.contains("[" + client + "]") || content.contains("loading mod " + client)
                        || content.contains("loaded " + client)) {
                    hits.add(client);
                }
            }
            if (!hits.isEmpty()) {
                findings.add(new Finding(
                        "MINECRAFT_LOG", "HIGH", 40,
                        "Cheat client reference found in latest.log",
                        logPath.toAbsolutePath().toString(),
                        List.of("Matched client references: " + String.join(", ", hits))
                ));
            }
        } catch (IOException ignored) {
        }
    }

    private static boolean nameMatchesCheat(String lowerName) {
        for (String c : KNOWN_CLIENTS) {
            if (lowerName.contains(c)) {
                return true;
            }
        }
        return false;
    }

    private static String readBoundedText(ZipFile zf, ZipEntry e, int maxBytes) throws IOException {
        try (InputStream in = zf.getInputStream(e)) {
            byte[] buf = in.readNBytes(maxBytes);
            return new String(buf, StandardCharsets.ISO_8859_1);
        }
    }

    private static void addIfDir(Set<Path> dirs, Path p) {
        if (Files.isDirectory(p)) {
            dirs.add(p.toAbsolutePath().normalize());
        }
    }
}
