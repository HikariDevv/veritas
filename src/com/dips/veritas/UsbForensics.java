package com.dips.veritas;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class UsbForensics {
    public record UsbDevice(String name, String serial, String driveLetter, String sizeInfo, boolean connected) {
    }

    public record UsbAudit(List<UsbDevice> devices, List<Finding> findings) {
    }

    private UsbForensics() {
    }

    public static UsbAudit inspect() {
        List<UsbDevice> devices = new ArrayList<>();
        List<Finding> findings = new ArrayList<>();

        if (OsInfo.isWindows()) {
            inspectWindows(devices, findings);
        } else if (OsInfo.isMac()) {
            inspectMac(devices);
        } else {
            inspectLinux(devices);
        }

        return new UsbAudit(devices, findings);
    }

    private static void inspectWindows(List<UsbDevice> out, List<Finding> findings) {
        Map<String, String> activeLetters = new LinkedHashMap<>();
        List<String> vols = ProcessInspector.execLines(
                "powershell", "-NoProfile", "-Command",
                "Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=2' | ForEach-Object { \"$($_.DeviceID)|$($_.VolumeName)|$($_.Size)\" }"
        );
        for (String line : vols) {
            String[] p = line.split("\\|", 3);
            if (p.length >= 2 && p[0].contains(":")) {
                String letter = p[0].trim();
                String label = p[1].trim().isEmpty() ? "Removable USB" : p[1].trim();
                long bytes = parseLongSafe(p.length >= 3 ? p[2].trim() : "0");
                String sz = bytes > 0 ? ConsoleUi.formatBytes(bytes) : "Unknown";
                activeLetters.put(letter, label + " (" + sz + ")");
                out.add(new UsbDevice(label, "Active Volume", letter, sz, true));
                findings.add(new Finding(
                        "USB_CONNECTED", "SUSPICIOUS", 15,
                        "Removable USB drive currently connected: " + letter + " (" + label + ")",
                        letter + "\\",
                        List.of("Capacity: " + sz, "Verify no injectable cheats or portable launchers are stored on this USB")
                ));
            }
        }

        List<String> regLines = ProcessInspector.execLines(
                "reg", "query", "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR"
        );
        for (String line : regLines) {
            String trimmed = line.trim();
            if (!trimmed.startsWith("HKEY_") || !trimmed.contains("\\USBSTOR\\")) {
                continue;
            }
            String deviceKey = trimmed.substring(trimmed.lastIndexOf('\\') + 1);
            String friendly = cleanUsbStorName(deviceKey);

            List<String> serials = ProcessInspector.execLines("reg", "query", trimmed);
            String serial = "Unknown";
            for (String sl : serials) {
                String st = sl.trim();
                if (st.startsWith("HKEY_") && st.length() > trimmed.length() + 1) {
                    serial = st.substring(st.lastIndexOf('\\') + 1);
                    break;
                }
            }
            out.add(new UsbDevice(friendly, serial, "-", "USB History", false));
        }

        long disconnectedCount = out.stream().filter(d -> !d.connected()).count();
        if (disconnectedCount > 0) {
            findings.add(new Finding(
                    "USB_HISTORY", "INFO", 5,
                    "USB storage history detected (" + disconnectedCount + " previously connected device(s))",
                    "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR",
                    List.of("Use menu option [5] USB Forensics to view all connected & disconnected USB serials")
            ));
        }
    }

    private static void inspectMac(List<UsbDevice> out) {
        for (String line : ProcessInspector.execLines("diskutil", "list", "external")) {
            String t = line.trim();
            if (t.startsWith("/dev/disk")) {
                out.add(new UsbDevice("External USB Disk", t, t, "Mounted", true));
            }
        }
        String currentName = null;
        for (String line : ProcessInspector.execLines("system_profiler", "SPUSBDataType")) {
            String t = line.trim();
            if (t.endsWith(":") && !t.startsWith("USB") && !t.startsWith("Host")) {
                currentName = t.substring(0, t.length() - 1);
            } else if (t.startsWith("Serial Number:") && currentName != null) {
                String serial = t.substring("Serial Number:".length()).trim();
                out.add(new UsbDevice(currentName, serial, "USB Bus", "Connected", true));
                currentName = null;
            }
        }
    }

    private static void inspectLinux(List<UsbDevice> out) {
        for (String line : ProcessInspector.execLines("lsblk", "-d", "-n", "-o", "NAME,TRAN,SIZE,SERIAL,MODEL")) {
            String lower = line.toLowerCase(Locale.ROOT);
            if (lower.contains("usb")) {
                String[] parts = line.trim().split("\\s+", 5);
                String dev = "/dev/" + parts[0];
                String sz = parts.length > 2 ? parts[2] : "USB";
                String ser = parts.length > 3 ? parts[3] : "Unknown";
                String model = parts.length > 4 ? parts[4] : "USB Storage";
                out.add(new UsbDevice(model, ser, dev, sz, true));
            }
        }
    }

    private static String cleanUsbStorName(String raw) {
        String s = raw.replace("Disk&Ven_", "")
                .replace("&Prod_", " ")
                .replace("&Rev_", " rev ")
                .replace('_', ' ');
        return s.trim();
    }

    private static long parseLongSafe(String s) {
        try {
            return Long.parseLong(s);
        } catch (Exception e) {
            return 0;
        }
    }
}
