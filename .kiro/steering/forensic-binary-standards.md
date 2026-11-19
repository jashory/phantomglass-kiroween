---
inclusion: fileMatch
fileMatchPattern: "web/src/engines/**"
---

# Forensic Binary & Security Engine Standards

## Rules for `web/src/engines/**`
1. **Pure TypeScript Portability:** Core engines (`exifBinaryParser.ts`, `permissionGraphEngine.ts`, `secretAirGapEngine.ts`) must remain pure, side-effect-free TypeScript functions with zero DOM coupling (except `mediaExorcist.ts` Canvas re-encoding) so both the Vite web app and Node.js automated test suites / MCP server share identical forensic logic.
2. **Strict Bounds Checking:** Before every `view.getUint16()`, `view.getUint32()`, or slice operation, explicitly verify `offset >= 0 && offset + width <= view.byteLength`.
3. **Deterministic Risk Scoring:** Risk scores (`0–100`) must be deterministic and reproducible across identical inputs, with explicit per-finding explanations and actionable remediation commands.
4. **Independent Re-Verification:** After media exorcism, always re-parse the output `ArrayBuffer` through `parseImageForensics()` to prove mathematically that `0` metadata tags and `0` trailing bytes remain.
