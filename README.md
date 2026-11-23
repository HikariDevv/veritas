<div align="center">

<img src="app/assets/veritas.png" alt="Veritas" width="72" height="72" />

# VERITAS

**Cross-Platform Screenshare Forensics & Live RAM Inspection Suite**

Minecraft (1.7.10–1.21+) · GTA V / FiveM · Roblox

[![Release](https://img.shields.io/badge/release-v1.0.0-f59e0b?style=flat-square&labelColor=111114)](https://github.com/HikariDevv/veritas/releases/tag/v1.0.0)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-27272a?style=flat-square&labelColor=111114)](#quick-start)
[![Java](https://img.shields.io/badge/engine-Java%2017%2B-27272a?style=flat-square&labelColor=111114)](#build-from-source)
[![Electron](https://img.shields.io/badge/desktop-Electron-27272a?style=flat-square&labelColor=111114)](#quick-start)
[![License](https://img.shields.io/badge/license-MIT-27272a?style=flat-square&labelColor=111114)](LICENSE)

[Download v1.0.0](https://github.com/HikariDevv/veritas/releases/tag/v1.0.0) · [Capabilities](#forensic-modules) · [Quick Start](#quick-start) · [CLI Usage](#standalone-cli)

</div>

---

## Overview

**Veritas** is a local desktop screenshare scanner designed to uncover external C++ injectors, manual-mapped DLLs, Replace Method tampering, and post-boot file deletions without false-flagging legitimate clients or system runtimes.

Everything runs locally with **strict current-session filtering** (>= PC Boot Time) so staff see what was executed, injected, or deleted since the machine turned on—not noise from weeks ago.

---

## Forensic Modules

| Module | What It Detects | Win | macOS | Linux |
| :--- | :--- | :---: | :---: | :---: |
| **Live RAM Memory** | Manual-mapped / unlinked PE DLLs (RWX/RX) and residual C++ cheat/hook strings in javaw.exe, GTA5.exe, FiveM, RobloxPlayerBeta.exe, and explorer.exe (VirtualQueryEx + ReadProcessMemory / /proc/pid/maps / lsof) | Yes | Yes | Yes |
| **Session Execution Traces** | Programs executed **since PC boot** via ROT13 UserAssist (exact 64-bit timestamps + run count), Prefetch, and Recent—flags binaries deleted right after execution (self-destruct) | Yes | Yes | Yes |
| **Replace Method & Bytecode** | Modified JAR manifests, Created-vs-Modified timestamp anomalies, NTFS Zone.Identifier download origin, and packed/unsigned native binaries | Yes | Yes | Yes |
| **Bypass & Anti-Tamper** | 9 Windows forensic services (SysMain, EventLog, DPS, PcaSvc, DiagTrack, Dnscache, BAM, DusmSvc, WinDefend), **Windows Defender Exclusions**, EventLog clears (ID 104), and System Clock changes (ID 1) | Yes | — | — |
| **Recycle Bin & Recovery** | Parses $I/$R deletion metadata since PC boot with **1-click file recovery** to Desktop/veritas-recovered/ | Yes | Yes | Yes |
| **USB Storage History** | Currently connected and historically disconnected USB drives (USBSTOR) with serial numbers | Yes | Yes | Yes |
| **Browser & DNS Forensics** | Chrome, Edge, Brave, Opera, Firefox history, Windows DNS Cache recovery (even after clearing browser history), and macOS QuarantineEventsV2 | Yes | Yes | Yes |
| **Environment, Macros & Alts** | VM detection, active VPN tunnels, macro software, and Minecraft alt accounts | Yes | Yes | Yes |
| **Single File Inspector** | Drag-and-drop any .jar, .dll, or .exe for SHA-256, Replace Method check, Zone.Identifier URL, Authenticode signature, and VirusTotal lookup | Yes | Yes | Yes |
| **Veritas AI Assistant** | Offline natural-language Q&A (English & Spanish) + one-click staff FAQs over the active scan | Yes | Yes | Yes |

---

## Multi-Game Coverage & Zero False Positives

- **Minecraft (1.7.10 – 1.21+):** Ghost & C++ external clients, JNI/JVMTI agents, packed temp DLLs, Replace Method mods, and hidden cheat configs.
- **GTA V / FiveM:** Mod menus, executors, and DX11/ImGui hooks.
- **Roblox:** Windows/macOS executors and script injectors.
- **Trusted Client Whitelist:** Official launchers and native libraries (**Lunar Client**, **Badlion**, **Feather**, **LabyMod**, **Fabric**, **Forge**, **NeoForge**, **Quilt**, **PrismLauncher**, **Modrinth**, **LWJGL**, **OpenAL**, **GLFW**, **Discord RPC**, and JRE runtimes) are whitelisted to prevent false positives.

---

## Quick Start

### Option 1 — Prebuilt Release
Download the latest package from [**Releases v1.0.0**](https://github.com/HikariDevv/veritas/releases/tag/v1.0.0):
- **eritas-desktop-v1.0.0.zip** — Electron Desktop App + Java Engine + Win32 RAM Scanner
- **eritas-1.0.0.jar** — Standalone Java 17+ CLI engine

### Option 2 — Run Desktop App From Source
Requires **Node.js 18+** and **Java 17+**.

``bash
git clone https://github.com/HikariDevv/veritas.git
cd veritas/app
npm install
npm start
``

---

## Standalone CLI

Run headless forensic scans directly from any terminal on Windows, macOS, or Linux:

``bash
# Standard 12-stage screenshare scan + exact .TXT forensic log
java -jar veritas-1.0.0.jar scan --txt veritas-report.txt

# Deep bytecode scan on a custom folder
java -jar veritas-1.0.0.jar scan --deep /path/to/mods --txt deep-report.txt

# Recover a deleted Recycle Bin item by ID
java -jar veritas-1.0.0.jar recover 1
``

---

## Build From Source

``bash
javac --release 17 -encoding UTF-8 -d build src/com/dips/veritas/*.java
jar cfe dist/veritas-1.0.0.jar com.dips.veritas.Main -C build .
``

---

## Project Structure

``text
veritas/
├── src/com/dips/veritas/   # 12-stage Java 17+ cross-platform forensic engine
└── app/
    ├── main.js             # Electron main process, UserAssist/Defender & RAM IPC
    ├── preload.js          # Context-isolated renderer bridge
    ├── renderer/           # Total-black desktop UI & offline Veritas AI analyst
    └── assets/             # Veritas V. vector icons (PNG & multi-size ICO)
``

---

<div align="center">
<sub>Built by <a href="https://github.com/HikariDevv">HikariDevv</a> · MIT License</sub>
</div>