# Requirements Document — Binary Exorcist & Synthetic Specimen Engine

## Introduction
Hackathon judges often test apps without wanting to upload personal photos from their work laptops. To guarantee deterministic, zero-friction forensic evaluation, the Binary Exorcist Engine must both parse arbitrary user-supplied JPEG/PNG binaries AND synthesize 100% genuine, spec-compliant binary JPEG images embedded with realistic EXIF/GPS/Software metadata and trailing payload bytes on demand.

## Requirements

### Requirement 1: Spec-Compliant Synthetic JPEG/EXIF Specimen Synthesis
**User Story:** As a hackathon judge evaluating PhantomGlass in under 60 seconds, I want to click one button to generate a real binary JPEG file containing genuine TIFF/EXIF/GPS tags and hidden trailing bytes, so that I can verify the binary parser and exorcist without uploading private files.

#### Acceptance Criteria
- WHEN the user clicks a 1-click specimen button THE SYSTEM SHALL render a clean forensic test image, splice a genuine binary `APP1 (0xFFE1)` Exif/TIFF segment (with Make, Model, Software, DateTime, and GPS Rational IFD entries) plus appended trailing bytes past `0xFFD9`, and feed that real `Uint8Array` into the exact same binary parser used for user uploads.
- WHEN the user clicks Exorcise on that synthetic specimen THE SYSTEM SHALL prove via independent re-parsing that 100% of spliced EXIF/GPS tags and trailing bytes were eliminated.

### Requirement 2: Malformed Binary Resilience (Chaos Guard)
**User Story:** As a security engineer testing malformed files, I want the binary parser to safely handle truncated headers, invalid TIFF offsets, or corrupted chunk lengths without throwing uncaught runtime exceptions.

#### Acceptance Criteria
- WHEN a truncated or malformed byte buffer is passed to `parseImageForensics()` THE SYSTEM SHALL clamp all `DataView` offsets within `byteLength` and return a structured `BinaryForensicReport` cleanly without crashing the UI.
