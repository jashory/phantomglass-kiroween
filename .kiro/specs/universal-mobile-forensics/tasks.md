# Implementation Plan — Universal Mobile Privacy Forensics (Android 8–17 + Apple iOS)

- [x] 1. Upgrade `web/src/engines/permissionGraphEngine.ts` with full API 26–37 (Android 8–17) version matrix, `targetSdkVersion` auto-detection, OS security deltas, and AppOps-safe revocation generator.
- [x] 2. Implement `web/src/engines/iosPrivacyEngine.ts` supporting `Info.plist`, `PrivacyInfo.xcprivacy`, ATT/ATS/Required-Reason API detection, 3 real-world presets, and hardened XML patch export.
- [x] 3. Integrate dual Android 8–17 / Apple iOS switcher + API selector directly into Tab 2 (`2. Mobile 3D Audit`) of `web/src/App.tsx`.
- [x] 4. Mirror Android API 26–37 and `audit_ios_plist` in `mcp-server/index.mjs` and cover with Cloud CI unit tests.
