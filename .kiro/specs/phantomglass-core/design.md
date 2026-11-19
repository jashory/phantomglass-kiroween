# Technical Design — PhantomGlass Core Platform

## 1. Architecture Overview (Frankenstein 4-Organ Chimera)
PhantomGlass unifies four traditionally separate engineering domains into one cohesive zero-cloud runtime with zero backend servers and zero third-party AI telemetry:

```mermaid
flowchart TB
    User["User / Security Auditor (100% Local Browser RAM)"]
    UI["Swiss-Precision Forensic Workbench (React 19 + TypeScript + Tailwind)"]
    Organ1["Organ 1: Raw Binary EXIF / GPS / PNG Parser (DataView)"]
    Organ2["Organ 2: Canvas Pixel Re-Encoder & Verified Purge Engine"]
    Organ3["Organ 3: AndroidManifest Permission Chain Engine + 3D Canvas Topology"]
    Organ4["Organ 4: Shannon-Entropy & Luhn PII Air-Gap Redactor"]
    MCP["Standalone Node.js stdio MCP Server (mcp-server/index.mjs)"]
    Kiro[".kiro/ Specs + Steering + Hooks + mcp.json"]

    User --> UI
    UI --> Organ1
    Organ1 --> Organ2
    UI --> Organ3
    UI --> Organ4
    Kiro -.->|"Drives Spec & Automation"| UI
    Kiro -.->|"Wires MCP Tools"| MCP
```

## 2. End-to-End Media Exorcism Sequence

```mermaid
sequenceDiagram
    participant U as User / Judge
    participant P as exifBinaryParser.ts
    participant E as mediaExorcist.ts
    participant V as Self-Verification Pass

    U->>P: Drop JPEG/PNG OR Load Binary Specimen
    P-->>U: Parsed IFD0/ExifIFD/GPSIFD Tags + Trailing Bytes + Risk Score
    U->>E: Click "Exorcise & Verify"
    E->>E: Decode ImageBitmap -> Clean Offscreen Canvas -> Re-encode Blob
    E->>V: Re-parse Output ArrayBuffer through exifBinaryParser.ts
    V-->>U: Proof: 0 EXIF Tags, 0 GPS Tags, 0 Trailing Bytes + Byte Delta + Download
```

## 3. Core Data Models & Interfaces

- `ExifTagEntry`: `{ id: string; group: 'IFD0' | 'ExifIFD' | 'GPS' | 'PNG_CHUNK' | 'TRAILER'; name: string; value: string; severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'; }`
- `BinaryForensicReport`: `{ fileName: string; mimeType: string; byteLength: number; format: 'JPEG' | 'PNG' | 'UNKNOWN'; tags: ExifTagEntry[]; gpsCoordinates: { lat: number; lon: number } | null; trailingBytes: number; riskScore: number; hexPreview: string; }`
- `PermissionChainFinding`: `{ id: string; title: string; severity: 'CRITICAL' | 'HIGH' | 'MEDIUM'; permissions: string[]; mechanism: string; realWorldPrecedent: string; adbRevokeCommands: string[]; }`
- `SecretRedactionResult`: `{ redactedText: string; findings: SecretFinding[]; totalSecretsBlocked: number; entropyAnomalies: number; cloudBytesSent: 0; }`

## 4. Security & Zero-Leak Guarantee
- Zero `fetch()` calls to any analytics, telemetry, or third-party AI inference API.
- All binary parsing uses bounds-checked `DataView` reads to prevent out-of-bounds memory exceptions on malformed or crafted files.
- Interactive 3D topology uses pure lightweight 60fps HTML5 2D-projected 3D Canvas math respecting `prefers-reduced-motion` and avoiding heavyweight GPU context loss.
