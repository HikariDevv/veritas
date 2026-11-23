package com.dips.veritas;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

public final class BinaryScanner {
    private static final long MAX_FILE_BYTES = 20L * 1024L * 1024L;

    private static final List<String> CHEAT_FILE_NAMES = List.of(
            "vape", "slinky", "sluded", "sludedloader", "drip", "entropy", "whiteout", "koid",
            "itami", "lithiumlite", "karma", "doomsday", "prestige", "glock", "opautoclicker",
            "gsautoclicker", "autoclicker", "extremeinjector", "xenos", "processhacker",
            "cheatengine", "dreamclient", "phantomclient", "breeze", "catlean", "yukio",
            "sapphire", "exelon", "icetea", "akira", "antic", "vapev4", "vapelite", "cheatloader",
            "eulen", "redengine", "skript.gg", "hxcheats", "susano", "2take1", "cherax",
            "kiddions", "modest-menu", "yimmenu", "tzproject", "desudo",
            "synapsex", "krnl", "fluxus", "solara", "jjsploit", "dx9ware", "aimmy"
    );

    private static final List<String> JNI_SYMBOLS = List.of(
            "jni_getcreatedjavavms", "jni_onload", "jvmtienv", "retransformclasses",
            "getloadedclasses", "defineclass", "findclass", "getfieldid"
    );

    private static final List<String> CLICKER_INJECT_STRINGS = List.of(
            "virtualallocex", "writeprocessmemory", "createremotethread",
            "setwindowshookex", "getasynckeystate", "mouse_event", "sendinput",
            "cgeventpost", "xtestfakebuttonevent"
    );

    private static final List<String> LEGIT_DLL_NAMES = List.of(
            "lwjgl", "glfw", "openal", "jemalloc", "stb", "tinyfd", "shaderc", "opus",
            "jinput", "sapi", "narrator", "jna", "jnidispatch", "jansi", "netty",
            "discord-rpc", "discord_game_sdk", "discord_dispatch", "lunar", "badlion",
            "feather", "labymod", "ichor", "genesis", "sentry", "freetype", "harfbuzz",
            "angle", "libegl", "libgles", "vulkan", "d3dcompiler", "vcruntime", "msvcp",
            "ucrtbase", "concrt140", "api-ms-win-", "awt.dll", "jvm.dll", "java.dll",
            "nio.dll", "net.dll", "zip.dll", "verify.dll", "management.dll", "instrument.dll",
            "jimage.dll", "fontmanager.dll", "lcms.dll", "javajpeg.dll", "mlib_image.dll",
            "prefs.dll", "sunmscapi.dll", "jsound.dll", "sqlite", "leveldb", "zstd",
            "lz4", "brotli", "snappy", "skia", "libcef", "chrome_elf", "ffmpeg",
            "avcodec", "avformat", "avutil", "swscale", "swresample", "oshi"
    );

    private static final List<String> LEGIT_CLIENT_PATHS = List.of(
            ".lunarclient", "lunar client", "badlion", "feather", "labymod",
            "modrinth", "prismlauncher", "multimc", "curseforge", "atlauncher",
            "gdlauncher", "\\.minecraft\\runtime", "\\.minecraft\\bin",
            "/.minecraft/runtime", "/.minecraft/bin", "\\zulu", "\\temurin",
            "\\adoptium", "\\jdk-", "\\jre-"
    );

    private static final List<String> PACKER_SECTIONS = List.of(
            "upx0", "upx1", "themida", ".vmp0", ".vmp1", ".aspack", ".mpress1", ".enigma1"
    );

    public record BinaryAudit(int binariesScanned, List<Finding> findings) {
    }

    private BinaryScanner() {
    }

    public static List<Path> defaultScanRoots() {
        Set<Path> roots = new LinkedHashSet<>();
        String home = System.getProperty("user.home", "");
        addIfDir(roots, Path.of(home, "Downloads"));
        addIfDir(roots, Path.of(home, "Desktop"));
        if (OsInfo.isWindows()) {
            String temp = System.getenv("TEMP");
            if (temp != null) {
                addIfDir(roots, Path.of(temp));
            }
        } else {
            addIfDir(roots, Path.of("/tmp"));
        }
        return new ArrayList<>(roots);
    }

    public static BinaryAudit scan(List<Path> roots, boolean deep) throws Exception {
        List<Path> candidates = new ArrayList<>();
        for (Path root : roots) {
            if (!Files.exists(root)) {
                continue;
            }
            if (Files.isRegularFile(root)) {
                candidates.add(root);
                continue;
            }
            int maxDepth = deep ? 4 : 2;
            Files.walkFileTree(root, Set.of(), maxDepth, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    if (!attrs.isRegularFile() || attrs.size() <= 0 || attrs.size() > MAX_FILE_BYTES) {
                        return FileVisitResult.CONTINUE;
                    }
                    String lower = file.getFileName().toString().toLowerCase(Locale.ROOT);
                    if (isTargetOrDisguiseCandidate(lower)) {
                        candidates.add(file);
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path file, IOException exc) {
                    return FileVisitResult.CONTINUE;
                }
            });
        }

        int threads = Math.max(2, Math.min(8, Runtime.getRuntime().availableProcessors()));
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        List<Finding> findings = new CopyOnWriteArrayList<>();
        AtomicInteger scanned = new AtomicInteger(0);
        List<Future<?>> futures = new ArrayList<>(candidates.size());

        for (Path file : candidates) {
            futures.add(pool.submit(() -> {
                try {
                    Finding f = inspectBinary(file, scanned);
                    if (f != null) {
                        findings.add(f);
                    }
                } catch (Exception ignored) {
                }
            }));
        }

        for (Future<?> f : futures) {
            f.get();
        }
        pool.shutdown();

        return new BinaryAudit(scanned.get(), new ArrayList<>(findings));
    }

    private static Finding inspectBinary(Path file, AtomicInteger scanned) throws IOException {
        String lowerName = file.getFileName().toString().toLowerCase(Locale.ROOT);
        String fullLower = file.toAbsolutePath().toString().toLowerCase(Locale.ROOT);
        byte[] data = Files.readAllBytes(file);
        if (data.length < 64) {
            return null;
        }

        boolean isPe = data[0] == 'M' && data[1] == 'Z';
        boolean isElf = data[0] == 0x7F && data[1] == 'E' && data[2] == 'L' && data[3] == 'F';
        boolean isMachO = isMachOMagic(data);
        if (!isPe && !isElf && !isMachO) {
            return null;
        }
        scanned.incrementAndGet();

        int weight = 0;
        boolean hasDirectCheatSignal = false;
        List<String> reasons = new ArrayList<>();

        if (isDisguisedExtension(lowerName)) {
            weight += 60;
            hasDirectCheatSignal = true;
            reasons.add("Disguised executable: non-executable extension containing native binary header");
        }

        for (String bad : CHEAT_FILE_NAMES) {
            if (lowerName.contains(bad)) {
                weight += 55;
                hasDirectCheatSignal = true;
                reasons.add("Filename matches known cheat/injector/autoclicker: " + bad);
                break;
            }
        }

        if (!hasDirectCheatSignal && isLegitClientOrRuntimeBinary(lowerName, fullLower)) {
            return null;
        }

        boolean inTemp = fullLower.contains("\\appdata\\local\\temp\\") || fullLower.contains("\\windows\\temp\\") || fullLower.startsWith("/tmp/");
        int packerScore = isPe ? peScore(data, reasons) : 0;

        String ascii = extractAsciiLower(data, 512 * 1024);
        List<String> jniHits = new ArrayList<>();
        for (String sym : JNI_SYMBOLS) {
            if (ascii.contains(sym)) {
                jniHits.add(sym);
            }
        }
        List<String> apiHits = new ArrayList<>();
        for (String api : CLICKER_INJECT_STRINGS) {
            if (ascii.contains(api)) {
                apiHits.add(api);
            }
        }

        boolean mentionsMc = ascii.contains("minecraft") || ascii.contains("lwjgl")
                || ascii.contains("net/minecraft") || ascii.contains("javaw.exe");

        if (jniHits.size() >= 2 && mentionsMc) {
            weight += 60;
            hasDirectCheatSignal = true;
            reasons.add("JNI/JVMTI JVM injection symbols + Minecraft target: " + String.join(", ", jniHits));
        } else if (jniHits.size() >= 3) {
            weight += 35;
            hasDirectCheatSignal = true;
            reasons.add("JNI/JVMTI native hook symbols: " + String.join(", ", jniHits));
        }

        if (apiHits.size() >= 3 && mentionsMc) {
            weight += 45;
            hasDirectCheatSignal = true;
            reasons.add("Injection/autoclicker API cluster targeting Minecraft: " + String.join(", ", apiHits));
        } else if (apiHits.contains("virtualallocex") && apiHits.contains("writeprocessmemory")
                && apiHits.contains("createremotethread")) {
            weight += 40;
            hasDirectCheatSignal = true;
            reasons.add("Classic DLL injection API triplet (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread)");
        }

        if (packerScore > 0) {
            if (hasDirectCheatSignal || (inTemp && lowerName.endsWith(".dll"))) {
                weight += packerScore;
            } else {
                return null;
            }
        }

        if (weight < 40) {
            return null;
        }

        if (OsInfo.isWindows() && isPe) {
            String sig = checkAuthenticode(file);
            if ("Valid".equalsIgnoreCase(sig) && !hasDirectCheatSignal) {
                return null;
            }
            if (sig != null && !"Valid".equalsIgnoreCase(sig)) {
                reasons.add("Authenticode digital signature: " + sig);
            }
        }

        String sev = weight >= 65 ? "CRITICAL" : (weight >= 45 ? "HIGH" : "SUSPICIOUS");
        String format = isPe ? "PE" : (isElf ? "ELF" : "Mach-O");
        return new Finding(
                "INJECTABLE_BINARY", sev, Math.min(100, weight),
                "Suspicious " + format + " binary: " + file.getFileName(),
                file.toAbsolutePath().toString(),
                reasons
        );
    }

    private static String checkAuthenticode(Path file) {
        String escaped = file.toAbsolutePath().toString().replace("'", "''");
        List<String> lines = ProcessInspector.execLines(
                "powershell", "-NoProfile", "-Command",
                "(Get-AuthenticodeSignature -LiteralPath '" + escaped + "').Status"
        );
        return lines.isEmpty() ? null : lines.get(0).trim();
    }

    private static int peScore(byte[] data, List<String> reasons) {
        int score = 0;
        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        int peOff = buf.getInt(0x3C);
        if (peOff < 0 || peOff + 24 > data.length) {
            return 0;
        }
        if (data[peOff] != 'P' || data[peOff + 1] != 'E' || data[peOff + 2] != 0 || data[peOff + 3] != 0) {
            return 0;
        }
        int sections = Short.toUnsignedInt(buf.getShort(peOff + 6));
        int optSize = Short.toUnsignedInt(buf.getShort(peOff + 20));
        int secTable = peOff + 24 + optSize;

        int highEnt = 0;
        int rwx = 0;
        for (int i = 0; i < sections && i < 64; i++) {
            int off = secTable + i * 40;
            if (off + 40 > data.length) {
                break;
            }
            String secName = readFixedAscii(data, off, 8).toLowerCase(Locale.ROOT);
            long rawSize = Integer.toUnsignedLong(buf.getInt(off + 16));
            long rawOff = Integer.toUnsignedLong(buf.getInt(off + 20));
            long chars = Integer.toUnsignedLong(buf.getInt(off + 36));
            if (PACKER_SECTIONS.contains(secName)) {
                score += 25;
                reasons.add("Packed/protected PE section: " + secName);
            }
            if ((chars & 0xE0000000L) == 0xE0000000L) {
                rwx++;
            }
            if (rawSize >= 4096 && calcEntropy(data, rawOff, rawSize) >= 7.35) {
                highEnt++;
            }
        }
        if (rwx > 0) {
            score += 20;
            reasons.add("PE has RWX (Read+Write+Execute) memory section (" + rwx + ")");
        }
        if (highEnt > 0) {
            score += 15;
            reasons.add("High-entropy packed PE section (" + highEnt + ")");
        }
        return score;
    }

    private static boolean isMachOMagic(byte[] d) {
        int b0 = d[0] & 0xFF;
        int b1 = d[1] & 0xFF;
        int b2 = d[2] & 0xFF;
        int b3 = d[3] & 0xFF;
        return (b0 == 0xCF && b1 == 0xFA && b2 == 0xED && b3 == 0xFE)
                || (b0 == 0xCE && b1 == 0xFA && b2 == 0xED && b3 == 0xFE)
                || (b0 == 0xCA && b1 == 0xFE && b2 == 0xBA && b3 == 0xBE);
    }

    private static boolean isLegitClientOrRuntimeBinary(String lowerName, String fullLower) {
        for (String p : LEGIT_CLIENT_PATHS) {
            if (fullLower.contains(p)) {
                return true;
            }
        }
        for (String dll : LEGIT_DLL_NAMES) {
            if (lowerName.contains(dll)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isTargetOrDisguiseCandidate(String lower) {
        return lower.endsWith(".exe") || lower.endsWith(".dll") || lower.endsWith(".so")
                || lower.endsWith(".dylib") || lower.endsWith(".scr")
                || isDisguisedExtension(lower);
    }

    private static boolean isDisguisedExtension(String lower) {
        return lower.endsWith(".png") || lower.endsWith(".jpg") || lower.endsWith(".jpeg")
                || lower.endsWith(".pdf") || lower.endsWith(".txt") || lower.endsWith(".mp3");
    }

    private static double calcEntropy(byte[] data, long offset, long size) {
        if (offset < 0 || offset >= data.length || size <= 0) {
            return 0.0;
        }
        int len = (int) Math.min(size, data.length - offset);
        int start = (int) offset;
        int[] freq = new int[256];
        for (int i = start; i < start + len; i++) {
            freq[data[i] & 0xFF]++;
        }
        double e = 0.0;
        double dLen = len;
        for (int f : freq) {
            if (f > 0) {
                double p = f / dLen;
                e -= p * (Math.log(p) / Math.log(2.0));
            }
        }
        return e;
    }

    private static String readFixedAscii(byte[] data, int off, int maxLen) {
        int end = off;
        int limit = Math.min(data.length, off + maxLen);
        while (end < limit && data[end] != 0) {
            end++;
        }
        return new String(data, off, end - off, StandardCharsets.US_ASCII).trim();
    }

    private static String extractAsciiLower(byte[] data, int limit) {
        int len = Math.min(data.length, limit);
        StringBuilder sb = new StringBuilder(len / 2);
        for (int i = 0; i < len; i++) {
            int b = data[i] & 0xFF;
            sb.append(b >= 32 && b <= 126 ? (char) Character.toLowerCase(b) : ' ');
        }
        return sb.toString();
    }

    private static void addIfDir(Set<Path> set, Path p) {
        if (Files.isDirectory(p)) {
            set.add(p.toAbsolutePath().normalize());
        }
    }
}
