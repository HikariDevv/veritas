package com.dips.veritas;

import java.util.Locale;

public final class ConsoleUi {
    private static boolean colorEnabled = detectColorSupport();

    private ConsoleUi() {
    }

    private static boolean detectColorSupport() {
        if (System.getenv("NO_COLOR") != null) {
            return false;
        }
        if ("1".equals(System.getenv("VERITAS_COLOR"))) {
            return true;
        }
        if (!OsInfo.isWindows()) {
            return true;
        }
        return System.getenv("WT_SESSION") != null
                || System.getenv("TERM") != null
                || System.getenv("ANSICON") != null
                || System.getenv("ConEmuANSI") != null;
    }

    public static void setColorEnabled(boolean enabled) {
        colorEnabled = enabled;
    }

    public static String bold(String s) {
        return wrap("1", s);
    }

    public static String dim(String s) {
        return wrap("90", s);
    }

    public static String red(String s) {
        return wrap("91", s);
    }

    public static String green(String s) {
        return wrap("92", s);
    }

    public static String yellow(String s) {
        return wrap("93", s);
    }

    public static String blue(String s) {
        return wrap("94", s);
    }

    public static String magenta(String s) {
        return wrap("95", s);
    }

    public static String cyan(String s) {
        return wrap("96", s);
    }

    public static String white(String s) {
        return wrap("97", s);
    }

    public static String severityBadge(String severity) {
        return switch (severity) {
            case "CRITICAL" -> bold(red("CRITICAL"));
            case "HIGH" -> red("HIGH");
            case "SUSPICIOUS" -> yellow("SUSPICIOUS");
            case "INFO" -> cyan("INFO");
            default -> bold(green("CLEAN"));
        };
    }

    public static String verdictFromScore(int score) {
        if (score >= 75) {
            return "CRITICAL";
        }
        if (score >= 45) {
            return "HIGH";
        }
        if (score >= 20) {
            return "SUSPICIOUS";
        }
        return "CLEAN";
    }

    public static String formatBytes(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        }
        double kb = bytes / 1024.0;
        if (kb < 1024.0) {
            return String.format(Locale.ROOT, "%.2f KB", kb);
        }
        double mb = kb / 1024.0;
        if (mb < 1024.0) {
            return String.format(Locale.ROOT, "%.2f MB", mb);
        }
        return String.format(Locale.ROOT, "%.2f GB", mb / 1024.0);
    }

    public static void printBanner(String version) {
        System.out.println(bold(blue("==================================================================")));
        System.out.println(bold(cyan("  VERITAS v" + version)) + dim("  |  ") + white("Minecraft SS Forensics, USB, Trash & Browser"));
        System.out.println(bold(blue("==================================================================")));
    }

    private static String wrap(String code, String text) {
        if (!colorEnabled) {
            return text;
        }
        return "\u001B[" + code + "m" + text + "\u001B[0m";
    }
}
