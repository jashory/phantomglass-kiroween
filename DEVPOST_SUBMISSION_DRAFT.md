# Devpost Submission Draft — PhantomGlass (Kiroween 2026)

## Project Title
**PhantomGlass — Zero-Trust Permission, Binary EXIF & Secret Exorcist**

## Tagline
A Frankenstein 4-organ offline forensic lab & local MCP server that stops silent camera-roll, Android permission, and secret leaks before a single byte leaves your device.

## Selected Category
- **Frankenstein** (Eligible for Overall 1st/2nd/3rd Place + Best Startup Project + Best Frankenstein)

## Inspiration
Recent regulatory enforcement—including Italy's **EUR 805M (USD 887M)** fine over blanket Android camera-roll cloud processing—proved a stark reality: modern mobile apps no longer need root exploits or zero-days to harvest private unshared photos, home GPS coordinates, or microphone audio. Standard everyday permissions granted by normal users chain together into silent background data harvesting.

We built **PhantomGlass** to invert that surveillance model into a **100% zero-cloud, browser-native defensive shield** where `0` bytes ever leave local RAM.

## What It Does (4 Stitched-Together Frankenstein Organs)
1. **Organ #1 — Raw Client-Side Binary EXIF/GPS/PNG Forensic Microscope**: Bounds-checked `DataView` binary parser decoding JPEG APP1 TIFF/EXIF IFD0, ExifIFD, GPSIFD decimal coordinates, PNG metadata chunks (`tEXt`/`iTXt`/`zTXt`/`eXIf`), and hidden post-EOI/IEND trailing bytes—plus a genuine **JPEG APP1 Binary Splicer** for 1-click judge testing.
2. **Organ #2 — Cryptographic Canvas Pixel Exorcist & Self-Verification Pass**: Re-encodes image pixel buffers through an offscreen HTML5 Canvas, then independently re-parses the clean output buffer through Organ #1 to prove `0` EXIF tags, `0` GPS coordinates, and `0` trailing bytes survive before 1-click clean download.
3. **Organ #3 — AndroidManifest.xml Blast-Radius Auditor & 60fps 3D Containment Topology**: Parses any pasted `AndroidManifest.xml` (or 4 real-world app profiles), detects multi-permission silent-harvesting chains, renders an interactive 60fps 3D permission orbit topology, and generates ready-to-run `adb shell pm revoke` commands.
4. **Organ #4 — Zero-Leak Shannon-Entropy & Luhn Air-Gap Redactor + Standalone Local MCP Server**: Strips AWS keys, GitHub PATs, private keys, Luhn-validated payment cards, IBANs, NIDs, and high-entropy credentials strictly in local RAM (`0` cloud bytes) and exposes all forensic engines over JSON-RPC 2.0 stdio **Model Context Protocol (MCP)**.

## How We Used Kiro (Spec-Driven Development, Steering, Hooks & MCP)
The entire `.kiro/` directory is tracked in our public repository:
- **Specs (`.kiro/specs/phantomglass-core/` & `.kiro/specs/binary-exorcist-engine/`)**: Formal EARS-syntax `requirements.md`, Mermaid architecture & sequence `design.md`, and completed `tasks.md`.
- **Steering (`.kiro/steering/`)**: `always`-included privacy constitution (`0` outbound bytes), `fileMatch`-scoped forensic binary safety standards (`web/src/engines/**`), and a `manual` Kiroween release gate audit.
- **Agent Hooks (`.kiro/hooks/`)**: Kiro v1 `PostFileSave` hooks (`zero-leak-security-audit.json` and `spec-sync-guard.json`) enforcing zero-fetch integrity and automated test runs.
- **MCP Integration (`.kiro/settings/mcp.json`)**: Pre-wired to `./mcp-server/index.mjs` exposing 4 zero-dependency forensic tools directly inside Kiro.

## Links
- **Live HTTPS App:** https://jashory.github.io/phantomglass-kiroween/
- **Public GitHub Repository (including `.kiro/`):** https://github.com/jashory/phantomglass-kiroween
- **Demo Video (Phase Last):** [To be recorded & attached before Dec 4 deadline]
