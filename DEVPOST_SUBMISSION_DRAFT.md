# Devpost Submission Draft — PhantomGlass v2.0 (Kiroween 2026)

## Project Title
**PhantomGlass — Zero-Trust Mobile, Binary Media, Secret & Columnar Dataset Exorcist**

## Tagline
A Frankenstein 7-organ zero-cloud forensic lab & 7-tool local MCP server that stops silent Android 8–17 / iOS permission, EXIF/PDF, secret, and gigabyte CSV dataset leaks before a single byte leaves your device.

## Selected Category
- **Frankenstein** (Eligible for Overall 1st/2nd/3rd Place + Best Startup Project + Best Student Project + Best Frankenstein)

## Inspiration
Recent regulatory enforcement—including Italy's **805M EUR (887M USD)** fine over blanket Android camera-roll cloud processing—proved a stark reality: modern mobile apps no longer need root exploits or zero-days to harvest private unshared photos, home GPS coordinates, or microphone audio. Meanwhile, engineering and AI teams routinely leak PII and credentials when uploading massive, bloated CSV dumps to external converters or cloud LLM workspaces.

We built **PhantomGlass v2.0** to invert that surveillance and leak model into a **100% zero-cloud, browser-native defensive shield** where `0` bytes ever leave local RAM.

## What It Does (7 Stitched-Together Frankenstein Organs)
1. **Organ #1 — Raw Client-Side Binary EXIF/GPS/PNG Forensic Microscope**: Bounds-checked `DataView` binary parser decoding JPEG APP1 TIFF/EXIF IFD0, ExifIFD, GPSIFD decimal coordinates, PNG metadata chunks (`tEXt`/`iTXt`/`zTXt`/`eXIf`), and hidden post-EOI/IEND trailing bytes—plus a genuine **JPEG APP1 Binary Splicer** for 1-click judge testing.
2. **Organ #2 — Cryptographic Canvas Pixel Exorcist & Self-Verification Pass**: Re-encodes image pixel buffers through an offscreen HTML5 Canvas, then independently re-parses the clean output buffer through Organ #1 to prove `0` EXIF tags, `0` GPS coordinates, and `0` trailing bytes survive before 1-click clean download.
3. **Organ #3 — Universal Mobile Privacy Forensics (Android 8–17 [API 26–37] + Apple iOS `Info.plist` / `PrivacyInfo.xcprivacy`) & 60fps 3D Containment Topology**: Audits any Android 8 through Android 17 manifest with OS-version-accurate `adb shell pm revoke` + `appops set` commands (verified exit 0 on a real Cloud KVM Android 14 emulator), AND audits Apple iOS `Info.plist` & `PrivacyInfo.xcprivacy` for silent photo-library scraping, ATT IDFA tracking, ATS cleartext downgrades (`NSAllowsArbitraryLoads`), and Required Reason API fingerprinting—emitting a 1-click hardened `PrivacyInfo.xcprivacy` XML patch.
4. **Organ #4 — Zero-Leak Shannon-Entropy & Luhn Air-Gap Redactor**: Strips AWS keys, GitHub PATs, private keys, Luhn-validated payment cards, IBANs, NIDs, and high-entropy credentials strictly in local RAM (`0` cloud bytes).
5. **Organ #5 — Client-Side Binary PDF `/OpenAction`, `/JavaScript` & Post-`%%EOF` Microscope**: Inspects raw PDF bytes locally for embedded auto-exec triggers, phishing URIs, metadata leaks, and trailing payloads.
6. **Organ #6 — Companion Chrome Manifest V3 Side-Panel Extension & 7-Tool Standalone Local MCP Server**: Installable MV3 extension (`0` network egress) + zero-dependency Node.js stdio JSON-RPC 2.0 MCP server exposing 7 forensic tools (`audit_android_permissions`, `audit_ios_plist`, `scrub_and_shrink_csv`, `scan_text_secrets`, `inspect_image_exif_bytes`, `generate_privacy_hardening_policy`, `verify_zero_egress_attestation`).
7. **Organ #7 — Zero-Cloud Forensic Columnar Dataset Shrinker, PII Scrubber & Slice Extractor**: Auto-profiles local CSV/TSV files (or 1-click 6,000-row & 25,000-row enterprise leak benchmarks), drops bloat columns, scrubs PII/cloud keys or deterministically pseudonymizes identifiers, dictionary-encodes kept columns into a native gzip-compressed `PGCOL1` archive (`*.pgcol.gz`, achieving 90–98%+ byte reduction), and emits a **WebCrypto SHA-256 Chain-of-Custody Attestation JSON** (`cloudBytesSent: 0`).

## How We Used Kiro (Spec-Driven Development, Steering, Hooks & 7-Tool MCP)
The entire `.kiro/` directory is tracked in our public repository:
- **Specs (`.kiro/specs/phantomglass-core/`, `binary-exorcist-engine/`, `universal-mobile-forensics/`, `columnar-dataset-scrubber/`)**: Formal EARS-syntax `requirements.md`, Mermaid architecture `design.md`, and verified `tasks.md`.
- **Steering (`.kiro/steering/`)**: `always`-included zero-cloud privacy constitution (`0` outbound bytes), `fileMatch`-scoped forensic binary safety standards (`web/src/engines/**`), and a `manual` Kiroween release gate audit.
- **Agent Hooks (`.kiro/hooks/`)**: Kiro v1 `PostFileSave` hooks (`zero-leak-security-audit.json` and `spec-sync-guard.json`) enforcing zero-fetch integrity and automated test runs.
- **MCP Integration (`.kiro/settings/mcp.json`)**: Pre-wired to `./mcp-server/index.mjs` exposing 7 zero-dependency forensic tools directly inside Kiro.

## Links
- **Devpost Submission Draft (`#1312523`):** https://devpost.com/software/phantomglass-zero-cloud-forensic-mcp-exorcist
- **Live HTTPS App (v2.0):** https://jashory.github.io/phantomglass-kiroween/
- **Public GitHub Repository (including `.kiro/` + MIT License):** https://github.com/jashory/phantomglass-kiroween
- **Chrome MV3 Extension Release (`v1.0.0`):** https://github.com/jashory/phantomglass-kiroween/releases/tag/v1.0.0
- **Demo Video (Phase Last):** [To be recorded with Shihab Sir RVC v2 voiceover & attached before Dec 4 deadline]
