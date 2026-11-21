# Requirements Document — Universal Mobile Privacy Forensics (Android 8–17 + Apple iOS)

## Introduction
Mobile privacy enforcement boundaries differ sharply across Android 8 (API 26) through Android 17 (API 37) and Apple iOS (`Info.plist` / `PrivacyInfo.xcprivacy`). Passing non-runtime or version-mismatched permissions to `adb shell pm revoke` crashes remediation scripts, while iOS apps evade scrutiny via ATT domains, `LSApplicationQueriesSchemes`, `NSAllowsArbitraryLoads`, and Apple Required Reason APIs.

## Requirements

### Requirement 1: Universal Android 8–17 (API 26–37) Version-Aware Auditing
- WHEN a user selects any Android target from Android 8 (API 26) to Android 17 (API 37) OR pastes an `AndroidManifest.xml` with `android:targetSdkVersion` THE SYSTEM SHALL filter `adb shell pm revoke` strictly to runtime-revocable permissions valid on that API level and route special permissions (`SYSTEM_ALERT_WINDOW`, `MANAGE_EXTERNAL_STORAGE`, `RECEIVE_BOOT_COMPLETED`, `SCHEDULE_EXACT_ALARM`) to exact `adb shell appops set` commands.

### Requirement 2: Apple iOS `Info.plist` & `PrivacyInfo.xcprivacy` Forensic Auditing
- WHEN a user switches Organ #3 to Apple iOS mode and pastes an `Info.plist` / `PrivacyInfo.xcprivacy` XML OR selects a 1-click iOS preset THE SYSTEM SHALL detect blanket Photo Library, Always GPS, Background Audio, ATT IDFA tracking, ATS cleartext HTTP (`NSAllowsArbitraryLoads`), URL-scheme fingerprinting, and Apple Required Reason APIs, project them onto the 60fps 3D Threat Topology, and generate a 1-click hardened `PrivacyInfo.xcprivacy` XML patch.
