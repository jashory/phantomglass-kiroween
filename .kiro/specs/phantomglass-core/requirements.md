# Requirements Document — PhantomGlass Core Platform

## Introduction
PhantomGlass is a Frankenstein-category Zero-Trust Privacy Forensic Lab and Permission Exorcist built for **Kiroween 2026**. It stitches together four seemingly incompatible software worlds—(1) a raw client-side binary EXIF/GPS/PNG forensic parser, (2) a cryptographic Canvas pixel re-encoding & metadata exorcist, (3) an Android `AndroidManifest.xml` silent-permission blast-radius graph with interactive 3D containment topology, and (4) a live local Model Context Protocol (MCP) security server—into a single 100% browser-native, zero-cloud defensive instrument.

## Requirements

### Requirement 1: Zero-Cloud Binary Media Forensic Inspection
**User Story:** As a privacy-conscious user or security researcher, I want to inspect any JPEG or PNG image directly in local browser RAM without uploading it to any cloud server, so that I can uncover hidden GPS coordinates, device fingerprints, timestamps, software tags, and appended trailing payloads.

#### Acceptance Criteria
- WHEN a user drops or selects a JPEG or PNG file OR loads a built-in synthetic binary forensic specimen THE SYSTEM SHALL parse JPEG APP1/TIFF/EXIF IFD0, ExifIFD, and GPSIFD tags or PNG tEXt/iTXt/zTXt chunks entirely inside local memory with `0` outbound network bytes.
- WHEN a file contains GPS latitude/longitude rational tags THE SYSTEM SHALL decode exact decimal coordinates and flag the privacy severity as `CRITICAL`.
- WHEN an image contains appended trailing bytes past the JPEG EOI (`0xFFD9`) or PNG `IEND` marker THE SYSTEM SHALL report the exact trailing byte count as a potential steganographic/container anomaly.

### Requirement 2: Cryptographic Media Exorcism & Verifiable Purge Proof
**User Story:** As a mobile user affected by silent background camera-roll scraping, I want to strip 100% of hidden EXIF, GPS, XMP, IPTC, and trailing bytes from my images before sharing or storing them, so that third-party apps cannot harvest my physical location or device identity.

#### Acceptance Criteria
- WHEN the user triggers the Exorcise action THE SYSTEM SHALL re-encode the image pixel buffer via an offscreen HTML5 Canvas into a clean binary container, re-run the binary forensic parser on the newly produced blob, and mathematically verify `0` EXIF tags, `0` GPS tags, and `0` trailing bytes remain.
- WHEN exorcism completes THE SYSTEM SHALL display exact Before vs. After byte deltas, tag purge count, and enable 1-click download of the verified sanitized file.

### Requirement 3: Android Permission Chain & Silent-Harvesting Blast-Radius Audit
**User Story:** As an everyday smartphone user or security auditor, I want to paste an `AndroidManifest.xml` or inspect real-world app permission profiles, so that I can detect silent background data-harvesting chains (such as Gallery + Location + Boot + Internet) that require no root access.

#### Acceptance Criteria
- WHEN a user supplies an `AndroidManifest.xml` document OR selects one of the realistic app permission profiles THE SYSTEM SHALL parse all `<uses-permission>` entries, compute multi-permission exfiltration chains, and assign a deterministic `0–100` Blast-Radius Risk Score.
- WHEN dangerous permission combinations are detected (e.g., `READ_MEDIA_IMAGES` + `ACCESS_MEDIA_LOCATION` + `INTERNET`) THE SYSTEM SHALL highlight the exact chain vector in the interactive 3D containment topology and generate ready-to-run Android ADB revocation commands and iOS/Android privacy hardening steps.

### Requirement 4: Zero-Leak Shannon-Entropy & PII Air-Gap Redactor
**User Story:** As a developer or freelancer handling sensitive contracts, production configs, or identity records, I want to scrub secrets and PII strictly in local browser memory before pasting text into any external AI or messaging service, so that credentials and personal identifiers never leak.

#### Acceptance Criteria
- WHEN the user enters text or selects a 1-click forensic scenario THE SYSTEM SHALL run deterministic structural matchers (Luhn-validated payment cards, AWS access keys, GitHub PATs, private key blocks, NID/SSN/IBAN, phone numbers, emails) combined with Shannon entropy analysis strictly in local memory.
- WHEN redaction executes THE SYSTEM SHALL output a side-by-side clean redacted payload using deterministic placeholder tokens (e.g., `[REDACTED_AWS_KEY_1]`) alongside a live network telemetry meter confirming `0 bytes` transmitted externally.

### Requirement 5: Live Model Context Protocol (MCP) & Kiro Spec Transparency
**User Story:** As a developer using Kiro or any MCP-compatible AI agent, I want PhantomGlass's forensic engines exposed as a real local stdio MCP server and inspectable directly inside the web workbench, so that automated coding workflows can enforce zero-leak security continuously.

#### Acceptance Criteria
- WHEN an MCP client initializes `mcp-server/index.mjs` over stdio THE SYSTEM SHALL advertise and execute 4 real forensic tools (`audit_android_permissions`, `scan_text_secrets`, `inspect_image_exif_bytes`, `generate_privacy_hardening_policy`) using valid JSON-RPC 2.0 responses.
- WHEN a judge opens the Kiro Architecture tab inside the web workbench THE SYSTEM SHALL display the live `.kiro/` spec structure, steering rules, hooks, and interactive MCP tool playground.
