package com.dips.veritas;

import java.net.NetworkInterface;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class EnvironmentAuditor {
    public record EnvAudit(String hardwareModel, boolean isVm, List<String> vpnAdapters, List<Finding> findings) {
    }

    private static final List<String> VM_KEYWORDS = List.of(
            "vmware", "virtualbox", "vbox", "qemu", "kvm", "xen", "bochs", "parallels", "virtual machine"
    );

    private static final List<String> VPN_KEYWORDS = List.of(
            "wireguard", "wintun", "tap-windows", "openvpn", "nordlynx", "proton",
            "mullvad", "warp", "cloudflare", "tailscale", "zerotier", "hamachi", "radmin", "utun"
    );

    private EnvironmentAuditor() {
    }

    public static EnvAudit inspect() {
        List<Finding> findings = new ArrayList<>();
        String model = detectHardwareModel();
        String lowerModel = model.toLowerCase(Locale.ROOT);
        boolean isVm = false;
        for (String kw : VM_KEYWORDS) {
            if (lowerModel.contains(kw)) {
                isVm = true;
                findings.add(new Finding(
                        "VM_ENVIRONMENT", "HIGH", 35,
                        "Virtual Machine / Cloud PC environment detected: " + model,
                        "Hardware Model",
                        List.of("Matched VM signature: " + kw, "VMs are often used to isolate cheats during screenshares")
                ));
                break;
            }
        }

        Set<String> vpns = new LinkedHashSet<>();
        try {
            Enumeration<NetworkInterface> ifaces = NetworkInterface.getNetworkInterfaces();
            while (ifaces.hasMoreElements()) {
                NetworkInterface ni = ifaces.nextElement();
                if (!ni.isUp() || ni.isLoopback()) {
                    continue;
                }
                String label = (ni.getName() + " " + ni.getDisplayName()).toLowerCase(Locale.ROOT);
                for (String kw : VPN_KEYWORDS) {
                    if (label.contains(kw)) {
                        vpns.add(ni.getDisplayName());
                        break;
                    }
                }
            }
        } catch (Exception ignored) {
        }

        if (!vpns.isEmpty()) {
            findings.add(new Finding(
                    "VPN_ACTIVE", "INFO", 5,
                    "Active VPN / virtual tunnel interface detected (" + vpns.size() + ")",
                    String.join(", ", vpns),
                    List.of("Active VPN adapter may mask IP or route cheat auth traffic")
            ));
        }

        return new EnvAudit(model, isVm, new ArrayList<>(vpns), findings);
    }

    private static String detectHardwareModel() {
        if (OsInfo.isWindows()) {
            List<String> lines = ProcessInspector.execLines(
                    "powershell", "-NoProfile", "-Command",
                    "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; (Get-CimInstance Win32_ComputerSystem | ForEach-Object { ($_.Manufacturer + ' ' + $_.Model).Trim() })"
            );
            for (String line : lines) {
                String t = line.trim();
                if (!t.isBlank() && !t.startsWith("En l") && !t.startsWith("At line")) {
                    return t;
                }
            }
        } else if (OsInfo.isMac()) {
            List<String> lines = ProcessInspector.execLines("sysctl", "-n", "hw.model");
            if (!lines.isEmpty()) {
                return lines.get(0).trim();
            }
        } else {
            Path p = Path.of("/sys/class/dmi/id/product_name");
            if (Files.isReadable(p)) {
                try {
                    return Files.readString(p).trim();
                } catch (Exception ignored) {
                }
            }
        }
        return "Physical PC";
    }
}
