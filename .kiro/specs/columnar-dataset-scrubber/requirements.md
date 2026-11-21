# Requirements Document — Organ #7: Zero-Cloud Columnar Dataset Shrinker & PII Scrubber

## Introduction
Enterprise engineers, researchers, and AI teams frequently hold bloated multi-gigabyte CSV/TSV exports packed with repeated JSON debug columns, unredacted customer PII (emails, phones, NIDs, IBANs, Luhn payment cards), and leaked cloud keys. Uploading these files to cloud converters or LLM workspaces creates severe compliance exposure. Organ #7 solves this strictly inside local RAM with 0 outbound network bytes.

## Requirements

### Requirement 1: Automated Column Risk & Bloat Profiling
- WHEN a user drops a local CSV/TSV file OR loads a 1-click multi-megabyte enterprise leak benchmark THE SYSTEM SHALL profile every column locally and classify it into `CLEAN`, `PII_RISK`, `SECRET_RISK`, or `HIGH_BLOAT`.
- WHEN profiling finishes THE SYSTEM SHALL recommend per-column containment policies (`KEEP`, `SCRUB_PII`, `PSEUDONYMIZE_SHA256`, `DROP_COLUMN`).

### Requirement 2: Surgical Row Slicing, PII Scrubbing & Columnar Dictionary Compression
- WHEN the user executes Exorcise & Shrink THE SYSTEM SHALL project kept columns, apply row substring/range slicing, scrub Shannon-entropy/Luhn/regex secrets, deterministically pseudonymize designated PII columns, and dictionary-encode all kept columns into a gzip-compressed `PGCOL1` binary archive (`*.pgcol.gz`) alongside a clean sliced CSV.

### Requirement 3: Cryptographic SHA-256 Chain-of-Custody Attestation
- WHEN dataset exorcism completes THE SYSTEM SHALL compute real WebCrypto SHA-256 hashes of the source bytes, clean CSV output, and `.pgcol.gz` archive, emitting a verifiable `PHANTOMGLASS-CHAIN-OF-CUSTODY-V2` JSON attestation with `cloudBytesSent: 0`.
