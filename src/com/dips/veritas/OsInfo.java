package com.dips.veritas;

import java.util.Locale;

public final class OsInfo {
    public enum Platform {
        WINDOWS, MACOS, LINUX, OTHER
    }

    private static final Platform CURRENT = detect();

    private OsInfo() {
    }

    public static Platform current() {
        return CURRENT;
    }

    public static boolean isWindows() {
        return CURRENT == Platform.WINDOWS;
    }

    public static boolean isMac() {
        return CURRENT == Platform.MACOS;
    }

    public static boolean isLinux() {
        return CURRENT == Platform.LINUX;
    }

    public static String displayName() {
        return System.getProperty("os.name", "Unknown") + " (" + System.getProperty("os.arch", "?") + ")";
    }

    private static Platform detect() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (os.contains("win")) {
            return Platform.WINDOWS;
        }
        if (os.contains("mac") || os.contains("darwin")) {
            return Platform.MACOS;
        }
        if (os.contains("nux") || os.contains("nix") || os.contains("aix")) {
            return Platform.LINUX;
        }
        return Platform.OTHER;
    }
}
