# Implementation Plan — Organ #7: Zero-Cloud Columnar Dataset Shrinker

- [x] 1. Build zero-dependency browser engine `web/src/engines/columnarScrubberEngine.ts` with RFC-4180 CSV/TSV parsing, column risk profiling, PII scrubbing, pseudonymization, `PGCOL1` dictionary columnar encoding, Web `CompressionStream('gzip')`, and WebCrypto SHA-256 Chain-of-Custody attestation.
- [x] 2. Add 1-click multi-megabyte realistic enterprise telemetry leak benchmarks (`6,000` rows ~4 MB & `25,000` rows ~16.5 MB) for instant Chief-Judge testing.
- [x] 3. Wire interactive Tab 4 (`4. Dataset Shrinker`) in `web/src/App.tsx` with per-column policy selectors, surgical row filter, before/after byte telemetry, and 3-artifact download (`.csv`, `.pgcol.gz`, attestation JSON).
- [x] 4. Expose matching Node.js stdio MCP tool `scrub_and_shrink_csv` + `verify_zero_egress_attestation` in `mcp-server/index.mjs` and verify via Cloud CI automated tests.
