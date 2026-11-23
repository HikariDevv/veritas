# Veritas

Cross-platform screenshare forensic scanner for **Minecraft**, **GTA V / FiveM**, and **Roblox**, combining a 12-stage Java 17+ inspection engine, a native Win32 live RAM scanner, and an Electron desktop interface.

## Highlights

- **Live RAM Memory Forensics (javaw.exe, GTA5.exe, FiveM, RobloxPlayerBeta.exe, explorer.exe)**
  - Detects manual-mapped / unlinked PE DLLs in private executable memory and residual C++ cheat/hook strings even after self-destruct.
  - Native /proc/<pid>/maps inspection on Linux and lsof inspection on macOS.
- **Current-Session Precision (Since PC Boot)**
  - Decodes Windows UserAssist (ROT13 + 64-bit timestamps + run count), Prefetch, Recent, and Recycle Bin deletions filtered strictly against LastBootUpTime.
- **Replace Method & Bytecode Audit**
  - Inspects JAR manifests, NTFS Zone.Identifier ADS, timestamp anomalies, and packed/unsigned binaries while whitelisting official launchers (Lunar, Badlion, Feather, LabyMod, Fabric, Forge, Prism, Modrinth).
- **Bypass & System Forensics**
  - Audits 9 Windows forensic services, Windows Defender Exclusions, EventLog clears (ID 104), System Clock changes (ID 1), connected/disconnected USB serials, Browser History, DNS Cache, VM/VPN adapters, and Minecraft alts.
- **1-Click Recycle Bin Recovery & File Inspector**
  - Recover deleted files directly to Desktop/veritas-recovered/ or drop any .jar/.dll/.exe for SHA-256, timestamp check, Authenticode status, and VirusTotal lookup.
- **Veritas AI Assistant**
  - Local offline Q&A assistant with quick screenshare prompts and English/Spanish natural-language queries over the active scan.

## Quick Start

### Desktop App (Windows / macOS / Linux)
Requires **Node.js 18+** and **Java 17+**.

``bash
cd app
npm install
npm start
``

### Standalone CLI Engine (Java 17+)
``bash
java -jar veritas-1.0.0.jar scan --txt report.txt
``

## Build From Source

``bash
javac --release 17 -encoding UTF-8 -d build src/com/dips/veritas/*.java
jar cfe dist/veritas-1.0.0.jar com.dips.veritas.Main -C build .
``