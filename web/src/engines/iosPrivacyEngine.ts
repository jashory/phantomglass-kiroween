/**
 * PhantomGlass Organ #3B: Apple iOS Info.plist & PrivacyInfo.xcprivacy Forensic Auditor
 * Pure zero-cloud XML/plist parser detecting silent camera-roll, ATT cross-app tracking,
 * background persistence, ATS cleartext downgrades, and Apple Required Reason API fingerprinting.
 */

import type { PermissionNode } from './permissionGraphEngine';

export interface IosChainFinding {
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  matchedKeys: string[];
  mechanism: string;
  realWorldPrecedent: string;
  remediationSteps: string[];
}

export interface IosPrivacyFinding {
  key: string;
  label: string;
  category: PermissionNode['category'];
  risk: PermissionNode['risk'];
  valuePreview: string;
}

export interface IosPrivacyAuditReport {
  platform: 'ios';
  bundleId: string;
  findings: IosPrivacyFinding[];
  nodes: PermissionNode[];
  chains: IosChainFinding[];
  requiredReasonApis: string[];
  trackingDomains: string[];
  allowsArbitraryLoads: boolean;
  privacyTrackingDeclared: boolean;
  blastRadiusScore: number;
  riskLevel: 'CLEAN' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  hardeningSteps: string[];
  hardenedXcprivacyXml: string;
  cloudBytesSent: 0;
}

const IOS_KEY_META: Record<
  string,
  { label: string; category: PermissionNode['category']; risk: PermissionNode['risk'] }
> = {
  NSPhotoLibraryUsageDescription: { label: 'iOS Full Photo Library', category: 'MEDIA', risk: 'CRITICAL' },
  NSPhotoLibraryAddUsageDescription: { label: 'Photo Library Write', category: 'MEDIA', risk: 'MEDIUM' },
  NSCameraUsageDescription: { label: 'iOS Camera', category: 'SENSOR', risk: 'HIGH' },
  NSMicrophoneUsageDescription: { label: 'iOS Microphone', category: 'SENSOR', risk: 'CRITICAL' },
  NSLocationAlwaysAndWhenInUseUsageDescription: {
    label: 'iOS 24/7 Always GPS',
    category: 'SENSOR',
    risk: 'CRITICAL'
  },
  NSLocationAlwaysUsageDescription: { label: 'iOS Legacy Always GPS', category: 'SENSOR', risk: 'CRITICAL' },
  NSLocationWhenInUseUsageDescription: { label: 'iOS Foreground GPS', category: 'SENSOR', risk: 'MEDIUM' },
  NSContactsUsageDescription: { label: 'iOS Contacts Graph', category: 'IDENTITY', risk: 'HIGH' },
  NSUserTrackingUsageDescription: { label: 'IDFA Cross-App ATT', category: 'IDENTITY', risk: 'CRITICAL' },
  NSLocalNetworkUsageDescription: { label: 'LAN Device Scanner', category: 'NETWORK', risk: 'HIGH' },
  NSBluetoothAlwaysUsageDescription: { label: 'Always Bluetooth Beacon', category: 'SENSOR', risk: 'HIGH' },
  NSCalendarsFullAccessUsageDescription: { label: 'Full Calendar Read', category: 'IDENTITY', risk: 'HIGH' },
  NSHealthShareUsageDescription: { label: 'HealthKit Biometrics', category: 'IDENTITY', risk: 'CRITICAL' },
  NSFaceIDUsageDescription: { label: 'Biometric FaceID Prompt', category: 'IDENTITY', risk: 'LOW' },
  NSAllowsArbitraryLoads: { label: 'Cleartext HTTP (ATS Off)', category: 'NETWORK', risk: 'CRITICAL' },
  LSApplicationQueriesSchemes: { label: 'Installed-App Fingerprinting', category: 'IDENTITY', risk: 'HIGH' },
  UIBackgroundModes: { label: 'iOS Background Persistence', category: 'PERSISTENCE', risk: 'HIGH' },
  BGTaskSchedulerPermittedIdentifiers: { label: 'Scheduled BG Wake Tasks', category: 'PERSISTENCE', risk: 'MEDIUM' },
  NSPrivacyTracking: { label: 'Declared Ad Tracking', category: 'NETWORK', risk: 'CRITICAL' },
  NSPrivacyAccessedAPICategoryFileTimestamp: {
    label: 'File Timestamp Fingerprint',
    category: 'IDENTITY',
    risk: 'HIGH'
  },
  NSPrivacyAccessedAPICategorySystemBootTime: {
    label: 'System BootTime Fingerprint',
    category: 'IDENTITY',
    risk: 'HIGH'
  },
  NSPrivacyAccessedAPICategoryDiskSpace: {
    label: 'Disk-Space Fingerprint',
    category: 'IDENTITY',
    risk: 'MEDIUM'
  },
  NSPrivacyAccessedAPICategoryUserDefaults: {
    label: 'Shared UserDefaults Access',
    category: 'PERSISTENCE',
    risk: 'MEDIUM'
  }
};

export interface IosPreset {
  id: string;
  name: string;
  bundleId: string;
  badge: 'CRITICAL' | 'HIGH' | 'CLEAN';
  plistXml: string;
}

export const IOS_PLIST_PRESETS: IosPreset[] = [
  {
    id: 'ios-social-harvester',
    name: 'iOS Social Mega-App (Full Photos + Always GPS + ATT + BG Audio)',
    bundleId: 'com.social.megafeed.ios',
    badge: 'CRITICAL',
    plistXml: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>com.social.megafeed.ios</string>
  <key>NSPhotoLibraryUsageDescription</key>
  <string>Allow full photo library access for AI cloud memories and creative collage suggestions.</string>
  <key>NSMicrophoneUsageDescription</key>
  <string>Used for voice notes and ambient audio enhancement.</string>
  <key>NSLocationAlwaysAndWhenInUseUsageDescription</key>
  <string>Continuous background location for hyper-local discovery.</string>
  <key>NSContactsUsageDescription</key>
  <string>Sync address book to find contacts.</string>
  <key>NSUserTrackingUsageDescription</key>
  <string>Track across apps and websites to deliver personalized ads.</string>
  <key>NSLocalNetworkUsageDescription</key>
  <string>Discover devices on your local Wi-Fi network.</string>
  <key>UIBackgroundModes</key>
  <array>
    <string>audio</string>
    <string>location</string>
    <string>fetch</string>
  </array>
  <key>LSApplicationQueriesSchemes</key>
  <array>
    <string>whatsapp</string>
    <string>tg</string>
    <string>binance</string>
    <string>metamask</string>
  </array>
  <key>NSPrivacyTracking</key>
  <true/>
  <key>NSPrivacyTrackingDomains</key>
  <array>
    <string>graph-telemetry.megafeed-ads.example</string>
    <string>pixel-collector.adnet.example</string>
  </array>
  <key>NSPrivacyAccessedAPICategorySystemBootTime</key>
  <string>35F9.1</string>
  <key>NSPrivacyAccessedAPICategoryDiskSpace</key>
  <string>E174.1</string>
</dict>
</plist>`
  },
  {
    id: 'ios-free-vpn-ats',
    name: 'iOS Free Utility / VPN (ATS Cleartext + Fingerprinting APIs)',
    bundleId: 'com.freeboost.cleaner.ios',
    badge: 'CRITICAL',
    plistXml: `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>com.freeboost.cleaner.ios</string>
  <key>NSAppTransportSecurity</key>
  <dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
  </dict>
  <key>NSUserTrackingUsageDescription</key>
  <string>Enable ad partner attribution.</string>
  <key>NSLocalNetworkUsageDescription</key>
  <string>Scan local subnet hosts.</string>
  <key>NSBluetoothAlwaysUsageDescription</key>
  <string>Detect nearby beacons.</string>
  <key>NSPrivacyTracking</key>
  <true/>
  <key>NSPrivacyAccessedAPICategoryFileTimestamp</key>
  <string>C617.1</string>
  <key>NSPrivacyAccessedAPICategorySystemBootTime</key>
  <string>35F9.1</string>
  <key>NSPrivacyAccessedAPICategoryDiskSpace</key>
  <string>85F4.1</string>
</dict>
</plist>`
  },
  {
    id: 'ios-zero-trust-vault',
    name: 'Hardened Zero-Cloud iOS Privacy Vault (Clean Baseline)',
    bundleId: 'io.phantomglass.iosvault',
    badge: 'CLEAN',
    plistXml: `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>io.phantomglass.iosvault</string>
  <key>NSFaceIDUsageDescription</key>
  <string>Unlock local encrypted vault strictly on-device.</string>
  <key>NSPrivacyTracking</key>
  <false/>
  <key>NSPrivacyTrackingDomains</key>
  <array/>
</dict>
</plist>`
  }
];

function extractPlistStringValue(xml: string, key: string): string | null {
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`<key>\\s*${escaped}\\s*<\\/key>\\s*<string>([\\s\\S]*?)<\\/string>`, 'i');
  const m = xml.match(re);
  return m ? m[1].trim() : null;
}

function extractPlistBoolValue(xml: string, key: string): boolean | null {
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`<key>\\s*${escaped}\\s*<\\/key>\\s*<(true|false)\\s*\\/>`, 'i');
  const m = xml.match(re);
  if (!m) return null;
  return m[1].toLowerCase() === 'true';
}

function extractPlistArrayStrings(xml: string, key: string): string[] {
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`<key>\\s*${escaped}\\s*<\\/key>\\s*<array>([\\s\\S]*?)<\\/array>`, 'i');
  const m = xml.match(re);
  if (!m) return [];
  return [...m[1].matchAll(/<string>([\s\S]*?)<\/string>/gi)]
    .map((x) => x[1].trim())
    .filter(Boolean);
}

export function buildHardenedXcprivacyXml(bundleId: string): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- PhantomGlass Zero-Cloud Hardened PrivacyInfo.xcprivacy for ${bundleId} -->
<plist version="1.0">
<dict>
  <key>NSPrivacyTracking</key>
  <false/>
  <key>NSPrivacyTrackingDomains</key>
  <array/>
  <key>NSPrivacyCollectedDataTypes</key>
  <array/>
  <key>NSPrivacyAccessedAPITypes</key>
  <array/>
</dict>
</plist>`;
}

export function auditIosPrivacyManifest(plistText: string): IosPrivacyAuditReport {
  const safeXml = String(plistText || '').slice(0, 512_000);
  const bundleId =
    extractPlistStringValue(safeXml, 'CFBundleIdentifier') ||
    safeXml.match(/bundle[_-]?id\s*[:=]\s*["']?([a-zA-Z0-9._-]+)["']?/i)?.[1] ||
    'com.audited.iosapp';

  const findings: IosPrivacyFinding[] = [];
  const presentKeys = new Set<string>();

  for (const [key, meta] of Object.entries(IOS_KEY_META)) {
    const strVal = extractPlistStringValue(safeXml, key);
    const boolVal = extractPlistBoolValue(safeXml, key);
    const arrVal = extractPlistArrayStrings(safeXml, key);

    if (boolVal === true) {
      presentKeys.add(key);
      findings.push({ key, ...meta, valuePreview: 'true (ENABLED)' });
    } else if (arrVal.length > 0) {
      presentKeys.add(key);
      findings.push({
        key,
        ...meta,
        valuePreview: `${arrVal.length} entries: ${arrVal.slice(0, 5).join(', ')}`
      });
    } else if (strVal !== null) {
      presentKeys.add(key);
      findings.push({ key, ...meta, valuePreview: strVal.slice(0, 140) || 'Declared' });
    } else if (
      boolVal === null &&
      safeXml.includes(key) &&
      key !== 'NSPrivacyTracking' &&
      key !== 'NSAllowsArbitraryLoads'
    ) {
      presentKeys.add(key);
      findings.push({ key, ...meta, valuePreview: 'Present in manifest' });
    }
  }

  const requiredReasonApis = [
    'NSPrivacyAccessedAPICategoryFileTimestamp',
    'NSPrivacyAccessedAPICategorySystemBootTime',
    'NSPrivacyAccessedAPICategoryDiskSpace',
    'NSPrivacyAccessedAPICategoryUserDefaults'
  ].filter((k) => presentKeys.has(k));

  const trackingDomains = extractPlistArrayStrings(safeXml, 'NSPrivacyTrackingDomains');
  const bgModes = extractPlistArrayStrings(safeXml, 'UIBackgroundModes');
  const querySchemes = extractPlistArrayStrings(safeXml, 'LSApplicationQueriesSchemes');
  const allowsArbitraryLoads = extractPlistBoolValue(safeXml, 'NSAllowsArbitraryLoads') === true;
  const privacyTrackingDeclared = extractPlistBoolValue(safeXml, 'NSPrivacyTracking') === true;

  const chains: IosChainFinding[] = [];

  if (
    presentKeys.has('NSPhotoLibraryUsageDescription') &&
    (presentKeys.has('UIBackgroundModes') ||
      presentKeys.has('NSPrivacyTracking') ||
      presentKeys.has('NSUserTrackingUsageDescription'))
  ) {
    const matched = [
      'NSPhotoLibraryUsageDescription',
      ...['UIBackgroundModes', 'NSPrivacyTracking', 'NSUserTrackingUsageDescription'].filter((k) =>
        presentKeys.has(k)
      )
    ];
    chains.push({
      id: 'ios-camera-roll-harvest',
      title: 'Silent Unshared iOS Photo Library & Background Upload Chain',
      severity: 'CRITICAL',
      matchedKeys: matched,
      mechanism:
        'Full Photo Library permission combined with iOS Background Fetch/Tracking allows silent indexing of unposted camera-roll photos, family faces, and embedded GPS EXIF metadata.',
      realWorldPrecedent:
        'Apple introduced iOS Limited Photo Library Picker specifically to neutralize blanket PHPhotoLibrary scraping.',
      remediationSteps: [
        'iOS Settings -> Privacy & Security -> Photos -> Switch app to "Limited Access" or "None".',
        'Disable Background App Refresh for this bundle under Settings -> General -> Background App Refresh.',
        'Replace PHPhotoLibrary broad queries with PHPickerViewController (zero permission prompt required).'
      ]
    });
  }

  if (
    presentKeys.has('NSLocationAlwaysAndWhenInUseUsageDescription') ||
    presentKeys.has('NSLocationAlwaysUsageDescription') ||
    (presentKeys.has('NSMicrophoneUsageDescription') && bgModes.includes('audio'))
  ) {
    const matched = [
      'NSLocationAlwaysAndWhenInUseUsageDescription',
      'NSLocationAlwaysUsageDescription',
      'NSMicrophoneUsageDescription',
      'UIBackgroundModes'
    ].filter((k) => presentKeys.has(k));
    chains.push({
      id: 'ios-bg-sensor-surveillance',
      title: 'Persistent iOS Background Sensor (Always GPS / Audio) Chain',
      severity: 'CRITICAL',
      matchedKeys: matched,
      mechanism:
        'Combines Always-On Location or Background Audio mode to maintain continuous sensor telemetry while the app is suspended.',
      realWorldPrecedent:
        'High-risk pattern audited by Apple App Store Review Guideline 5.1.1 and EU GDPR regulators.',
      remediationSteps: [
        'iOS Settings -> Privacy & Security -> Location Services -> Change from "Always" to "While Using" & turn OFF "Precise Location".',
        'Audit live yellow/orange microphone & location status-bar indicators via iOS App Privacy Report.'
      ]
    });
  }

  if (
    presentKeys.has('NSUserTrackingUsageDescription') ||
    privacyTrackingDeclared ||
    requiredReasonApis.length >= 2 ||
    querySchemes.length >= 3
  ) {
    const matched = [
      ...['NSUserTrackingUsageDescription', 'NSPrivacyTracking', 'LSApplicationQueriesSchemes'].filter((k) =>
        presentKeys.has(k)
      ),
      ...requiredReasonApis
    ];
    chains.push({
      id: 'ios-cross-app-fingerprinting',
      title: 'Cross-App ATT IDFA, URL-Scheme & Required-Reason Device Fingerprinting',
      severity: 'CRITICAL',
      matchedKeys: matched,
      mechanism:
        'Pairs ATT tracking domains with installed-app scheme probing (LSApplicationQueriesSchemes) and boot-time/disk-space fingerprinting APIs to re-identify users even after IDFA reset.',
      realWorldPrecedent:
        'Apple Spring 2024 PrivacyInfo.xcprivacy enforcement explicitly targeted SystemBootTime & DiskSpace fingerprinting SDKs.',
      remediationSteps: [
        'iOS Settings -> Privacy & Security -> Tracking -> Toggle OFF "Allow Apps to Request to Track".',
        'Deploy PhantomGlass hardened PrivacyInfo.xcprivacy with NSPrivacyTracking=false and empty tracking domains.',
        'Enable iCloud Private Relay / DNS-level tracker blocking for declared NSPrivacyTrackingDomains.'
      ]
    });
  }

  if (allowsArbitraryLoads) {
    chains.push({
      id: 'ios-ats-cleartext-downgrade',
      title: 'App Transport Security (ATS) Cleartext HTTP Downgrade',
      severity: 'CRITICAL',
      matchedKeys: ['NSAllowsArbitraryLoads'],
      mechanism:
        'NSAllowsArbitraryLoads=true disables mandatory TLS 1.2+ transport encryption, exposing in-transit media, tokens, and PII to Wi-Fi MITM interception.',
      realWorldPrecedent:
        'OWASP MASVS-NETWORK-1 critical compliance failure across iOS enterprise penetration tests.',
      remediationSteps: [
        'Remove NSAllowsArbitraryLoads or set it strictly to <false/> in Info.plist.',
        'Enforce TLS 1.3 with certificate pinning for all first-party API hosts.'
      ]
    });
  }

  const nodes: PermissionNode[] = findings.map((f) => ({
    id: f.key,
    label: f.label,
    category: f.category,
    risk: f.risk
  }));

  const nodeRisk = nodes.reduce(
    (acc, n) => acc + (n.risk === 'CRITICAL' ? 10 : n.risk === 'HIGH' ? 6 : n.risk === 'MEDIUM' ? 3 : 1),
    0
  );
  const chainRisk = chains.reduce((acc, c) => acc + (c.severity === 'CRITICAL' ? 24 : 14), 0);
  const blastRadiusScore = findings.length === 0 ? 0 : Math.min(100, Math.round(nodeRisk * 0.55 + chainRisk));

  const riskLevel: IosPrivacyAuditReport['riskLevel'] =
    blastRadiusScore === 0
      ? 'CLEAN'
      : blastRadiusScore >= 75
        ? 'CRITICAL'
        : blastRadiusScore >= 45
          ? 'HIGH'
          : blastRadiusScore >= 20
            ? 'MEDIUM'
            : 'LOW';

  const hardeningSteps: string[] = [];
  if (presentKeys.has('NSPhotoLibraryUsageDescription')) {
    hardeningSteps.push('iOS Photos: Switch from "Full Access" to "Limited Access" or "None" and migrate app code to PHPickerViewController.');
  }
  if (privacyTrackingDeclared || presentKeys.has('NSUserTrackingUsageDescription')) {
    hardeningSteps.push('iOS ATT: Deny "Allow Apps to Request to Track" globally and strip third-party ad-attribution domains.');
  }
  if (allowsArbitraryLoads) {
    hardeningSteps.push('iOS ATS: Remove NSAllowsArbitraryLoads=true to enforce mandatory HTTPS / TLS 1.2+ everywhere.');
  }
  if (requiredReasonApis.length > 0) {
    hardeningSteps.push(
      `Apple Privacy Manifest: Audit ${requiredReasonApis.length} Required Reason API(s) (${requiredReasonApis.join(', ')}) to ensure zero covert device fingerprinting.`
    );
  }
  if (hardeningSteps.length === 0) {
    hardeningSteps.push('Zero dangerous iOS Info.plist or PrivacyInfo.xcprivacy tracking chains detected.');
  }

  return {
    platform: 'ios',
    bundleId,
    findings,
    nodes,
    chains,
    requiredReasonApis,
    trackingDomains,
    allowsArbitraryLoads,
    privacyTrackingDeclared,
    blastRadiusScore,
    riskLevel,
    hardeningSteps,
    hardenedXcprivacyXml: buildHardenedXcprivacyXml(bundleId),
    cloudBytesSent: 0
  };
}
