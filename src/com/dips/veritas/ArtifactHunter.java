package com.dips.veritas;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Stream;

public final class ArtifactHunter {
    private static final Set<String> CHEAT_CONFIG_DIRS = Set.of(
            ".vape", "vape", "vapev4", "vapelite", "slinky", "drip", "driplite",
            "entropy", "whiteout", "doomsday", "prestige", "koid", "itami",
            "liquidbounce", "wurst", "meteor-client", "future", "rusherhack",
            "rise", "raven", "augustus", "novoline", "tenacity", "fdpclient"
    );

    public record ArtifactAudit(int dirsChecked, List<Finding> findings) {
    }

    private ArtifactHunter() {
    }

    public static ArtifactAudit scan(List<Path> mcDirs) {
        List<Finding> findings = new ArrayList<>();
        int[] checked = {0};

        Set<Path> roots = new LinkedHashSet<>();
        String home = System.getProperty("user.home", "");
        roots.add(Path.of(home));
        if (OsInfo.isWindows()) {
            String app = System.getenv("APPDATA");
            String local = System.getenv("LOCALAPPDATA");
            if (app != null) roots.add(Path.of(app));
            if (local != null) roots.add(Path.of(local));
        } else if (OsInfo.isMac()) {
            roots.add(Path.of(home, "Library", "Application Support"));
        } else {
            roots.add(Path.of(home, ".config"));
            roots.add(Path.of(home, ".local", "share"));
        }
        roots.addAll(mcDirs);

        for (Path root : roots) {
            if (!Files.isDirectory(root)) {
                continue;
            }
            try (Stream<Path> s = Files.list(root)) {
                for (Path child : s.toList()) {
                    checked[0]++;
                    String name = child.getFileName().toString().toLowerCase(Locale.ROOT);
                    if (CHEAT_CONFIG_DIRS.contains(name)) {
                        findings.add(new Finding(
                                "CHEAT_CONFIG", "CRITICAL", 55,
                                "Hidden cheat client config/data folder detected: " + child.getFileName(),
                                child.toAbsolutePath().toString(),
                                List.of("Cheat client folder left on disk (often survives self-destruct)")
                        ));
                    }
                }
            } catch (Exception ignored) {
            }
        }

        for (Path mcDir : mcDirs) {
            inspectOptionsTxt(mcDir.resolve("options.txt"), findings);
        }

        return new ArtifactAudit(checked[0], findings);
    }

    private static void inspectOptionsTxt(Path options, List<Finding> findings) {
        if (!Files.isRegularFile(options)) {
            return;
        }
        try {
            for (String line : Files.readAllLines(options, StandardCharsets.UTF_8)) {
                if (line.startsWith("gamma:")) {
                    String valStr = line.substring(6).trim();
                    try {
                        double gamma = Double.parseDouble(valStr);
                        if (gamma > 2.0) {
                            findings.add(new Finding(
                                    "FULLBRIGHT_CFG", "INFO", 5,
                                    "Modified Fullbright gamma in options.txt (gamma:" + valStr + ")",
                                    options.toAbsolutePath().toString(),
                                    List.of("Vanilla max gamma is 1.0 (informational; allowed on some servers)")
                            ));
                        }
                    } catch (NumberFormatException ignored) {
                    }
                    break;
                }
            }
        } catch (IOException ignored) {
        }
    }
}
