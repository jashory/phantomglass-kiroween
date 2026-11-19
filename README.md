# PhantomGlass — Zero-Trust Permission, Binary EXIF & Secret Exorcist

> **Kiroween 2026 Submission — Frankenstein Category**  
> **Author:** HM Shihabuddin Jashory (`@jashory`) | **Architecture:** 100% Zero-Cloud Defensive Security Lab + Standalone MCP Server

**Live HTTPS Deployment:** [https://jashory.github.io/phantomglass-kiroween/](https://jashory.github.io/phantomglass-kiroween/)  
**Companion Chrome Manifest V3 Side-Panel Extension (`v1.0.0`):** [https://github.com/jashory/phantomglass-kiroween/releases/tag/v1.0.0](https://github.com/jashory/phantomglass-kiroween/releases/tag/v1.0.0)

---

## Why PhantomGlass Exists (The Real-World Trigger)

Modern mobile apps rarely need root access or zero-day exploits to harvest private user data. A single blanket **Gallery**, **Microphone**, or **Location** permission—often granted just to use normal messaging or photo sharing—lets background services scan unposted camera-roll photos, GPS coordinates, and financial screenshots (a practice that recently led to an **805M EUR / 887M USD** European regulatory fine against Meta).

**PhantomGlass** is a **Frankenstein-category** defensive chimera stitching **six seemingly incompatible software worlds** into one offline, zero-cloud privacy instrument:

1. **Organ #1 — Raw Client-Side Binary Forensic Microscope (`web/src/engines/exifBinaryParser.ts`)**: Bounds-checked `DataView` parser extracting JPEG APP1 TIFF/EXIF IFD0, ExifIFD, GPSIFD decimal coordinates, PNG `tEXt`/`iTXt`/`zTXt`/`eXIf` chunks, and hidden post-EOI/IEND trailing payloads directly in local RAM—plus a genuine **JPEG APP1 Binary Splicer** for 1-click judge testing.
2. **Organ #2 — Cryptographic Pixel & Metadata Exorcist (`web/src/engines/mediaExorcist.ts`)**: Re-encodes image pixel buffers through an offscreen HTML5 Canvas, then **independently re-parses the output buffer** through Organ #1 to prove `0` EXIF tags, `0` GPS coordinates, and `0` trailing bytes remain before 1-click clean download.
3. **Organ #3 — `AndroidManifest.xml` Silent-Harvesting Blast-Radius Engine & 60fps 3D Topology (`web/src/engines/permissionGraphEngine.ts` + `ThreatTopology3D.tsx`)**: Detects multi-permission exfiltration chains (`READ_MEDIA_IMAGES` + `ACCESS_MEDIA_LOCATION` + `INTERNET`), visualizes active threat vectors in a lightweight 60fps 3D containment sphere, and generates Android 14 (API 34) verified `adb shell pm revoke` (strictly for `ANDROID_RUNTIME_REVOCABLE` permissions) and `adb shell appops set <pkg> SYSTEM_ALERT_WINDOW deny` commands.
4. **Organ #4 — Zero-Leak Shannon-Entropy & Luhn Secret Air-Gap + Standalone Local MCP Server (`web/src/engines/secretAirGapEngine.ts` + `mcp-server/index.mjs`)**: Scrubs AWS keys, GitHub PATs, private keys, Luhn-validated payment cards, IBANs, NIDs, and high-entropy credentials strictly locally (`0` cloud bytes) and exposes all forensic engines over JSON-RPC 2.0 stdio **Model Context Protocol (MCP)**.
5. **Organ #5 — Client-Side PDF Binary `/OpenAction`, `/JavaScript` & Post-`%%EOF` Microscope (`web/src/engines/pdfForensicEngine.ts`)**: Scans raw PDF binary bytes locally for auto-exec `/OpenAction`, embedded `/JavaScript` (`/JS`), `/Launch`, `/EmbeddedFiles`, `/Info` author/creator leakage, and covert post-`%%EOF` trailing bytes.
6. **Organ #6 — Companion Chrome Manifest V3 Side-Panel Extension (`extension/`)**: Installable browser side-panel extension with instant Air-Gap Prompt & Log Redaction and 1-click Live Active-Tab DOM & Storage Secret/Tracker Audit (`0` bytes of network egress), plus a built-in **Chaos Stress-Test Harness** (`4/4` malformed binary probes survived with `0` uncaught exceptions).

---

## Real-World Cloud VM & Cloud Android 14 (API 34) Emulator Verification
- **Real Camera JPEG (`exiftool 13.50` Samsung `SM-S928B` + GPS `23.1667 N, 89.2081 E` + 64B Covert Trailer):** Uploaded to the live GitHub Pages deployment inside an isolated Cloud Ubuntu 26.04 VM, exorcised, and verified via `exiftool 13.50` + Python PIL (`1280x960 RGB`, `0` residual EXIF/GPS tags, `0` trailing bytes, `0` outbound network requests).
- **Real Cloud KVM Android 14 (API 34) Emulator APK Verification:** Built and installed a real signed target APK (`com.phantomglass.testtarget`) on a hardware-accelerated Android 14 emulator (`emulator-5554`), granted runtime permissions, and executed all 5 PhantomGlass-generated `adb shell pm revoke` and `adb shell appops set` commands with `5/5 EXIT CODE 0` and verified `granted=false` in `dumpsys package`.

## Live Screenshots (`3:2` High-Resolution Workbench)
| Binary EXIF/GPS & PDF Forensic Microscope | 60fps 3D Android Permission Topology & ADB Revoker | Tracked `.kiro/` Specs, Hooks & Live MCP Inspector |
| :---: | :---: | :---: |
| ![Binary Exorcist](screenshots/01_binary_exif_exorcist.jpg) | ![3D Permission Graph](screenshots/02_3d_android_permission_graph.jpg) | ![Kiro Specs & MCP](screenshots/03_kiro_architecture_and_mcp.jpg) |

---

## Authentic `.kiro/` Spec-Driven Architecture

This repository was designed around Kiro's complete `.kiro/` ecosystem (tracked in full at the repository root):

- `.kiro/specs/phantomglass-core/` — Formal **EARS** `requirements.md`, Mermaid `design.md`, and `tasks.md`
- `.kiro/specs/binary-exorcist-engine/` — Dedicated binary TIFF/EXIF splicer & chaos-resilience spec
- `.kiro/steering/` — Always-on privacy constitution, file-matched forensic engine rules, and manual release gate checklist
- `.kiro/hooks/` — Kiro v1 `PostFileSave` hooks (`zero-leak-security-audit.json` & `spec-sync-guard.json`)
- `.kiro/settings/mcp.json` — Pre-wired local `phantomglass-forensics` MCP server (`node ./mcp-server/index.mjs`)

---

## Quick Verification (Zero External Keys Required)

```bash
# 1. Run automated forensic engine, MCP stdio JSON-RPC, and zero-leak verification tests
node --test tests/forensic-engines.test.mjs

# 2. Run the standalone MCP server directly over stdio
node ./mcp-server/index.mjs

# 3. Build or run the Swiss-Precision Web Workbench locally
cd web && npm install && npm run build
```

## License
MIT License — 100% Open Source & Defensive Security Only.
