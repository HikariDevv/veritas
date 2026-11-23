<div align="center">

<img src="app/assets/veritas.png" alt="Veritas" width="68" height="68" />

# VERITAS

**Desktop Screenshare Forensics & Live RAM Scanner**

Minecraft (1.7.10–1.21+) · GTA V / FiveM · Roblox

[![Release](https://img.shields.io/badge/release-v1.0.0-f59e0b?style=flat-square&labelColor=0d0d10)](https://github.com/HikariDevv/veritas/releases/tag/v1.0.0)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-27272a?style=flat-square&labelColor=0d0d10)](#installation)
[![Java](https://img.shields.io/badge/engine-Java%2017%2B-27272a?style=flat-square&labelColor=0d0d10)](#build-from-source)
[![Electron](https://img.shields.io/badge/ui-Electron-27272a?style=flat-square&labelColor=0d0d10)](#installation)
[![License](https://img.shields.io/badge/license-MIT-27272a?style=flat-square&labelColor=0d0d10)](LICENSE)

[Download v1.0.0](https://github.com/HikariDevv/veritas/releases/tag/v1.0.0) · [Modules](#forensic-modules) · [Installation](#installation) · [CLI](#cli-usage)

</div>

---

## Overview

**Veritas** is a local screenshare forensic tool built to detect external C++ injectors, manual-mapped DLLs, Replace Method tampering, and post-boot file deletions while keeping false positives out of official clients and runtimes.

All execution traces, Recycle Bin deletions, and tamper checks are filtered against **PC Boot Time** (`LastBootUpTime`) so staff only inspect activity from the current session.

---

## Forensic Modules

| Module | Detection Scope | Win | macOS | Linux |
| :--- | :--- | :---: | :---: | :---: |
| **Live RAM Memory** | Manual-mapped PE DLLs in private executable memory and residual C++ cheat strings inside `javaw.exe`, `GTA5.exe`, `FiveM`, `RobloxPlayerBeta.exe`, and `explorer.exe` (`VirtualQueryEx` + `ReadProcessMemory` / `/proc/pid/maps` / `lsof`) | Yes | Yes | Yes |
| **Session Execution** | Current-session runs since PC boot via ROT13 `UserAssist` (exact timestamps + run count), `Prefetch`, and `Recent` — flags binaries deleted after execution | Yes | Yes | Yes |
| **Replace & Bytecode** | Modified JAR manifests, Created-vs-Modified timestamp mismatches, NTFS `Zone.Identifier` download URLs, and packed/unsigned binaries | Yes | Yes | Yes |
| **Bypass & Services** | Audits 9 Windows forensic services (`SysMain`, `EventLog`, `DPS`, `PcaSvc`, `DiagTrack`, `Dnscache`, `BAM`, `DusmSvc`, `WinDefend`), Defender Exclusions, EventLog clears (`ID 104`), and Clock changes (`ID 1`) | Yes | — | — |
| **Recycle Bin** | Parses `$I` / `$R` deletion metadata since PC boot with 1-click file recovery to `Desktop/veritas-recovered/` | Yes | Yes | Yes |
| **USB History** | Connected and historically disconnected USB devices (`USBSTOR`) with serial numbers | Yes | Yes | Yes |
| **Browser & DNS** | Chrome, Edge, Brave, Opera, Firefox history, Windows DNS Cache recovery, and macOS `QuarantineEventsV2` | Yes | Yes | Yes |
| **VM, VPN & Alts** | Virtual machine detection, active VPN tunnels, macro software, and Minecraft alt accounts | Yes | Yes | Yes |
| **File Inspector** | Drag-and-drop any `.jar`, `.dll`, or `.exe` for SHA-256, Replace Method check, `Zone.Identifier`, Authenticode signature, and VirusTotal lookup | Yes | Yes | Yes |
| **Veritas AI** | Offline Q&A assistant (English & Spanish) with quick staff queries over the active scan | Yes | Yes | Yes |

---

## Game Support & Trusted Whitelist

- **Minecraft (`1.7.10` – `1.21+`):** External C++ & ghost clients, JNI/JVMTI agents, packed temp DLLs, Replace Method mods, and hidden cheat configs.
- **GTA V / FiveM:** Mod menus, executors, and DX11/ImGui hooks.
- **Roblox:** Executors and script injectors.
- **Zero-False-Positive Whitelist:** Official launchers and native libraries (**Lunar Client**, **Badlion**, **Feather**, **LabyMod**, **Fabric**, **Forge**, **NeoForge**, **Quilt**, **PrismLauncher**, **Modrinth**, **LWJGL**, **OpenAL**, **GLFW**, **Discord RPC**, and JRE runtimes).

---

## Installation

### Prebuilt Release
Download from [**Releases v1.0.0**](https://github.com/HikariDevv/veritas/releases/tag/v1.0.0):
- **`veritas-desktop-v1.0.0.zip`** — Electron Desktop App + Java Engine + Win32 RAM Scanner
- **`veritas-1.0.0.jar`** — Standalone Java 17+ CLI engine

### Run Desktop App From Source
Requires **Node.js 18+** and **Java 17+**.

```bash
git clone https://github.com/HikariDevv/veritas.git
cd veritas/app
npm install
npm start
```

---

## CLI Usage

Run headless scans directly from any terminal on Windows, macOS, or Linux:

```bash
java -jar veritas-1.0.0.jar scan --txt veritas-report.txt
```

Deep bytecode scan on a specific folder:

```bash
java -jar veritas-1.0.0.jar scan --deep /path/to/mods --txt deep-report.txt
```

Recover a deleted Recycle Bin item by ID:

```bash
java -jar veritas-1.0.0.jar recover 1
```

---

## Build From Source

```bash
javac --release 17 -encoding UTF-8 -d build src/com/dips/veritas/*.java
jar cfe dist/veritas-1.0.0.jar com.dips.veritas.Main -C build .
```

---

## Project Layout

```text
veritas/
├── src/com/dips/veritas/
└── app/
    ├── main.js
    ├── preload.js
    ├── renderer/
    └── assets/
```

---

<div align="center">
<sub>MIT License · <a href="https://github.com/HikariDevv">HikariDevv</a></sub>
</div>
