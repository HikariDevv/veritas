package com.dips.veritas;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class AccountAuditor {
    private static final Pattern NAME_FIELD = Pattern.compile("\"(?:name|username)\"\\s*:\\s*\"([A-Za-z0-9_]{3,16})\"");

    private AccountAuditor() {
    }

    public static List<String> discoverAccounts(List<Path> mcDirs) {
        Set<String> usernames = new LinkedHashSet<>();
        for (Path dir : mcDirs) {
            scanJsonForNames(dir.resolve("launcher_accounts.json"), usernames);
            scanJsonForNames(dir.resolve("usercache.json"), usernames);
            scanJsonForNames(dir.resolve("settings").resolve("game").resolve("accounts.json"), usernames);
            scanJsonForNames(dir.resolve("accounts.json"), usernames);
        }
        return new ArrayList<>(usernames);
    }

    private static void scanJsonForNames(Path file, Set<String> out) {
        if (!Files.isRegularFile(file)) {
            return;
        }
        try {
            long sz = Files.size(file);
            if (sz <= 0 || sz > 2 * 1024 * 1024) {
                return;
            }
            String text = Files.readString(file, StandardCharsets.UTF_8);
            Matcher m = NAME_FIELD.matcher(text);
            while (m.find() && out.size() < 40) {
                String name = m.group(1);
                if (!name.equalsIgnoreCase("default") && !name.equalsIgnoreCase("latest")
                        && !name.equalsIgnoreCase("release") && !name.equalsIgnoreCase("snapshot")) {
                    out.add(name);
                }
            }
        } catch (IOException ignored) {
        }
    }
}
