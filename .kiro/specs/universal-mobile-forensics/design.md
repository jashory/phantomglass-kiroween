# Design Document — Universal Mobile Privacy Forensics (Android 8–17 + Apple iOS)

```mermaid
flowchart TD
    A[User Selects Platform: Android 8-17 or Apple iOS] --> B{Parser Router}
    B -->|Android XML| C[permissionGraphEngine.ts API 26-37 Matrix]
    B -->|iOS Plist XML| D[iosPrivacyEngine.ts Info.plist & xcprivacy]
    C --> E[Unified PermissionNode 3D Sphere]
    D --> E
    C --> F[OS-Version-Accurate ADB + AppOps Commands]
    D --> G[Hardened PrivacyInfo.xcprivacy Patch + iOS Lockdown Steps]
```

## Key Invariants
1. Zero non-runtime install-time permissions (`FOREGROUND_SERVICE_*`, `INTERNET`, `WAKE_LOCK`) ever emitted into `adb shell pm revoke`.
2. Unified `PermissionNode[]` schema drives the exact same 60fps `ThreatTopology3D` sphere seamlessly across both Android 8–17 and Apple iOS.
3. Mirror parity in `mcp-server/index.mjs` via `audit_android_permissions(manifestText, packageName, apiLevel)` and `audit_ios_plist(plistXml)`.
