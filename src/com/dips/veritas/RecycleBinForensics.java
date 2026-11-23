package com.dips.veritas;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;

public final class RecycleBinForensics {
    public record DeletedItem(
            String id,
            String originalPath,
            String fileName,
            long sizeBytes,
            Instant deletedAt,
            Path dataPath,
            boolean recoverable,
            boolean suspicious
    ) {
    }

    private static final List<String> CHEAT_WORDS = List.of(
            "vape", "slinky", "drip", "entropy", "whiteout", "koid", "itami", "lithiumlite",
            "karma", "doomsday", "prestige", "glock", "autoclick", "injector", "cheatengine",
            "processhacker", "wurst", "meteor", "liquidbounce", "raven"
    );

    private RecycleBinForensics() {
    }

    public static List<DeletedItem> listDeleted() {
        List<DeletedItem> items = new ArrayList<>();
        if (OsInfo.isWindows()) {
            scanWindowsRecycleBin(items);
        } else {
            scanUnixTrash(items);
        }
        items.sort(Comparator.comparing(DeletedItem::deletedAt).reversed());
        return items;
    }

    public static List<Finding> audit(List<DeletedItem> items) {
        List<Finding> findings = new ArrayList<>();
        for (DeletedItem item : items) {
            String lower = item.originalPath().toLowerCase(Locale.ROOT);
            long minsAgo = Duration.between(item.deletedAt(), Instant.now()).toMinutes();

            boolean cheatMatch = false;
            for (String kw : CHEAT_WORDS) {
                if (lower.contains(kw)) {
                    findings.add(new Finding(
                            "RECYCLE_BIN", "CRITICAL", 60,
                            "Deleted cheat artifact in Recycle Bin: " + item.fileName(),
                            item.originalPath(),
                            List.of(
                                    "Deleted at: " + item.deletedAt(),
                                    "Recoverable: " + (item.recoverable() ? "YES (ID " + item.id() + ")" : "Metadata only"),
                                    "Matched keyword: " + kw
                            )
                    ));
                    cheatMatch = true;
                    break;
                }
            }
            if (!cheatMatch && minsAgo >= 0 && minsAgo <= 45
                    && (lower.endsWith(".exe") || lower.endsWith(".dll") || lower.endsWith(".jar") || lower.endsWith(".zip"))) {
                findings.add(new Finding(
                        "RECYCLE_BIN", "HIGH", 35,
                        "Executable/JAR deleted " + minsAgo + " min ago: " + item.fileName(),
                        item.originalPath(),
                        List.of(
                                "Deleted at: " + item.deletedAt(),
                                "Recoverable: " + (item.recoverable() ? "YES (ID " + item.id() + ")" : "No")
                        )
                ));
            }
        }
        return findings;
    }

    public static Path recover(DeletedItem item, Path destDir) throws IOException {
        if (!item.recoverable() || item.dataPath() == null || !Files.exists(item.dataPath())) {
            throw new IOException("Data file is no longer present for item " + item.id());
        }
        Files.createDirectories(destDir);
        String safeName = item.fileName().replaceAll("[\\\\/:*?\"<>|]", "_");
        if (safeName.isBlank()) {
            safeName = "recovered_" + item.id();
        }
        Path out = destDir.resolve(safeName);
        if (Files.isDirectory(item.dataPath())) {
            copyDir(item.dataPath(), out);
        } else {
            Files.copy(item.dataPath(), out, StandardCopyOption.REPLACE_EXISTING);
        }
        return out;
    }

    private static void copyDir(Path src, Path dst) throws IOException {
        try (Stream<Path> walk = Files.walk(src)) {
            for (Path p : walk.toList()) {
                Path target = dst.resolve(src.relativize(p));
                if (Files.isDirectory(p)) {
                    Files.createDirectories(target);
                } else {
                    Files.createDirectories(target.getParent());
                    Files.copy(p, target, StandardCopyOption.REPLACE_EXISTING);
                }
            }
        }
    }

    private static void scanWindowsRecycleBin(List<DeletedItem> items) {
        Path rb = Path.of("C:\\$Recycle.Bin");
        if (!Files.isDirectory(rb)) {
            return;
        }
        int[] seq = {1};
        try (Stream<Path> sids = Files.list(rb)) {
            for (Path sidDir : sids.toList()) {
                if (!Files.isDirectory(sidDir)) {
                    continue;
                }
                try (Stream<Path> entries = Files.list(sidDir)) {
                    for (Path iFile : entries.toList()) {
                        String name = iFile.getFileName().toString();
                        if (!Files.isRegularFile(iFile) || !name.startsWith("$I")) {
                            continue;
                        }
                        DeletedItem parsed = parseIFile(iFile, sidDir, String.valueOf(seq[0]));
                        if (parsed != null) {
                            items.add(parsed);
                            seq[0]++;
                        }
                    }
                } catch (Exception ignored) {
                }
            }
        } catch (Exception ignored) {
        }
    }

    private static DeletedItem parseIFile(Path iFile, Path sidDir, String id) {
        try {
            byte[] data = Files.readAllBytes(iFile);
            if (data.length < 32) {
                return null;
            }
            ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
            long version = buf.getLong(0);
            long origSize = buf.getLong(8);
            long fileTime = buf.getLong(16);
            Instant deletedAt = Instant.ofEpochMilli((fileTime - 116444736000000000L) / 10000L);

            String origPath;
            if (version == 2 && data.length >= 28) {
                int charLen = buf.getInt(24);
                int byteLen = Math.min(data.length - 28, Math.max(0, charLen * 2));
                origPath = new String(data, 28, byteLen, StandardCharsets.UTF_16LE).replace("\0", "").trim();
            } else {
                origPath = new String(data, 24, data.length - 24, StandardCharsets.UTF_16LE).replace("\0", "").trim();
            }
            if (origPath.isEmpty()) {
                return null;
            }

            String rName = "$R" + iFile.getFileName().toString().substring(2);
            Path rFile = sidDir.resolve(rName);
            boolean rec = Files.exists(rFile);
            String fileName = Path.of(origPath).getFileName() == null ? origPath : Path.of(origPath).getFileName().toString();
            String lower = origPath.toLowerCase(Locale.ROOT);
            boolean sus = lower.endsWith(".exe") || lower.endsWith(".dll") || lower.endsWith(".jar")
                    || CHEAT_WORDS.stream().anyMatch(lower::contains);

            return new DeletedItem(id, origPath, fileName, origSize, deletedAt, rec ? rFile : null, rec, sus);
        } catch (Exception e) {
            return null;
        }
    }

    private static void scanUnixTrash(List<DeletedItem> items) {
        String home = System.getProperty("user.home", "");
        Path trashFiles = OsInfo.isMac()
                ? Path.of(home, ".Trash")
                : Path.of(home, ".local", "share", "Trash", "files");
        Path trashInfoDir = Path.of(home, ".local", "share", "Trash", "info");
        if (!Files.isDirectory(trashFiles)) {
            return;
        }
        int seq = 1;
        try (Stream<Path> s = Files.list(trashFiles)) {
            for (Path p : s.toList()) {
                String name = p.getFileName().toString();
                long sz = Files.isRegularFile(p) ? Files.size(p) : 0;
                Instant deletedAt = Files.getLastModifiedTime(p).toInstant();
                String origPath = p.toString();

                if (OsInfo.isLinux()) {
                    Path infoFile = trashInfoDir.resolve(name + ".trashinfo");
                    if (Files.isReadable(infoFile)) {
                        for (String line : Files.readAllLines(infoFile, StandardCharsets.UTF_8)) {
                            if (line.startsWith("Path=")) {
                                origPath = java.net.URLDecoder.decode(line.substring(5).trim(), StandardCharsets.UTF_8);
                            } else if (line.startsWith("DeletionDate=")) {
                                try {
                                    deletedAt = java.time.LocalDateTime.parse(line.substring(13).trim())
                                            .atZone(java.time.ZoneId.systemDefault()).toInstant();
                                } catch (Exception ignored) {
                                }
                            }
                        }
                    }
                }

                String lower = origPath.toLowerCase(Locale.ROOT);
                boolean sus = lower.endsWith(".jar") || lower.endsWith(".so") || lower.endsWith(".dylib")
                        || CHEAT_WORDS.stream().anyMatch(lower::contains);
                items.add(new DeletedItem(String.valueOf(seq++), origPath, name, sz, deletedAt, p, true, sus));
            }
        } catch (IOException ignored) {
        }
    }
}
