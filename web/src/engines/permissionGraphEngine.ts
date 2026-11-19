/**
 * PhantomGlass Organ #3: AndroidManifest.xml Permission Chain & Silent-Harvesting Blast-Radius Engine
 * Detects how ordinary user-granted permissions (Gallery, Mic, Location, Boot, Internet) chain into
 * silent background data harvesting without root access.
 */

export interface PermissionChainFinding {
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  matchedPermissions: string[];
  mechanism: string;
  realWorldPrecedent: string;
  adbRevokeCommands: string[];
}

export interface PermissionNode {
  id: string;
  label: string;
  category: 'MEDIA' | 'SENSOR' | 'IDENTITY' | 'NETWORK' | 'PERSISTENCE';
  risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
}

export interface PermissionAuditReport {
  packageName: string;
  permissions: string[];
  nodes: PermissionNode[];
  chains: PermissionChainFinding[];
  blastRadiusScore: number;
  riskLevel: 'CLEAN' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  hardeningSteps: string[];
  cloudBytesSent: 0;
}

const PERMISSION_META: Record<
  string,
  { label: string; category: PermissionNode['category']; risk: PermissionNode['risk'] }
> = {
  READ_MEDIA_IMAGES: { label: 'Gallery Images', category: 'MEDIA', risk: 'CRITICAL' },
  READ_MEDIA_VIDEO: { label: 'Gallery Videos', category: 'MEDIA', risk: 'HIGH' },
  READ_EXTERNAL_STORAGE: { label: 'Full Storage Read', category: 'MEDIA', risk: 'CRITICAL' },
  ACCESS_MEDIA_LOCATION: { label: 'Photo EXIF GPS', category: 'MEDIA', risk: 'CRITICAL' },
  RECORD_AUDIO: { label: 'Microphone', category: 'SENSOR', risk: 'CRITICAL' },
  CAMERA: { label: 'Camera', category: 'SENSOR', risk: 'HIGH' },
  ACCESS_FINE_LOCATION: { label: 'Precise GPS', category: 'SENSOR', risk: 'CRITICAL' },
  ACCESS_BACKGROUND_LOCATION: { label: '24/7 Background GPS', category: 'SENSOR', risk: 'CRITICAL' },
  READ_CONTACTS: { label: 'Contacts Graph', category: 'IDENTITY', risk: 'HIGH' },
  READ_SMS: { label: 'SMS / 2FA OTPs', category: 'IDENTITY', risk: 'CRITICAL' },
  RECEIVE_SMS: { label: 'Live SMS Listener', category: 'IDENTITY', risk: 'CRITICAL' },
  QUERY_ALL_PACKAGES: { label: 'Installed Apps List', category: 'IDENTITY', risk: 'HIGH' },
  SYSTEM_ALERT_WINDOW: { label: 'Screen Overlay', category: 'PERSISTENCE', risk: 'HIGH' },
  BIND_ACCESSIBILITY_SERVICE: { label: 'Accessibility Spy', category: 'PERSISTENCE', risk: 'CRITICAL' },
  RECEIVE_BOOT_COMPLETED: { label: 'Auto-Start on Boot', category: 'PERSISTENCE', risk: 'MEDIUM' },
  FOREGROUND_SERVICE_MICROPHONE: { label: 'Persistent Mic Service', category: 'PERSISTENCE', risk: 'CRITICAL' },
  WAKE_LOCK: { label: 'Background Wake Lock', category: 'PERSISTENCE', risk: 'MEDIUM' },
  INTERNET: { label: 'Cloud Egress', category: 'NETWORK', risk: 'MEDIUM' },
  ACCESS_NETWORK_STATE: { label: 'Network State', category: 'NETWORK', risk: 'LOW' }
};

interface ChainRule {
  id: string;
  title: string;
  severity: PermissionChainFinding['severity'];
  required: string[];
  amplifiers: string[];
  mechanism: string;
  realWorldPrecedent: string;
}

const CHAIN_RULES: ChainRule[] = [
  {
    id: 'silent-camera-roll-harvest',
    title: 'Silent Unshared Camera-Roll & EXIF Cloud Harvesting',
    severity: 'CRITICAL',
    required: ['READ_MEDIA_IMAGES', 'INTERNET'],
    amplifiers: ['ACCESS_MEDIA_LOCATION', 'READ_MEDIA_VIDEO', 'RECEIVE_BOOT_COMPLETED', 'READ_EXTERNAL_STORAGE'],
    mechanism:
      'Normal user-approved Gallery access + background Internet allows continuous scanning of unposted private photos, household faces, document screenshots, and EXIF GPS metadata—no root or zero-day exploit needed.',
    realWorldPrecedent:
      'Italian Garante fined Meta EUR 805M (USD 887M) over blanket Android camera-roll cloud processing.'
  },
  {
    id: 'ambient-mic-profiling',
    title: 'Persistent Microphone & Acoustic Profiling Chain',
    severity: 'CRITICAL',
    required: ['RECORD_AUDIO', 'INTERNET'],
    amplifiers: ['FOREGROUND_SERVICE_MICROPHONE', 'WAKE_LOCK', 'ACCESS_FINE_LOCATION'],
    mechanism:
      'Standard voice-note Microphone permission paired with wake locks or background services exposes ambient speech and device context to outbound telemetry.'
  ,
    realWorldPrecedent:
      'Repeatedly flagged in mobile SDK telemetry audits where voice features hold persistent audio privileges.'
  },
  {
    id: 'bg-location-stalking',
    title: '24/7 Background Physical Movement Tracking',
    severity: 'CRITICAL',
    required: ['ACCESS_BACKGROUND_LOCATION', 'INTERNET'],
    amplifiers: ['ACCESS_FINE_LOCATION', 'RECEIVE_BOOT_COMPLETED', 'WAKE_LOCK'],
    mechanism:
      'Combines boot persistence with background GPS to log home, work, and daily routes even while the app UI is closed.',
    realWorldPrecedent:
      'FTC & European data-broker enforcement actions against SDKs selling raw mobile location histories.'
  },
  {
    id: 'sms-otp-interception',
    title: 'SMS / Banking 2FA OTP Interception Vector',
    severity: 'CRITICAL',
    required: ['READ_SMS', 'INTERNET'],
    amplifiers: ['RECEIVE_SMS', 'READ_CONTACTS'],
    mechanism:
      'Allows reading incoming SMS verification codes and financial alerts and streaming them off-device.',
    realWorldPrecedent:
      'Primary attack vector in mobile banking trojans and predatory loan-shark Android apps.'
  },
  {
    id: 'overlay-phishing-chain',
    title: 'Overlay & Installed-App Phishing Vector',
    severity: 'HIGH',
    required: ['SYSTEM_ALERT_WINDOW', 'INTERNET'],
    amplifiers: ['BIND_ACCESSIBILITY_SERVICE', 'QUERY_ALL_PACKAGES'],
    mechanism:
      'Detects which banking/crypto apps are installed and draws invisible overlays or captures screen inputs.',
    realWorldPrecedent:
      'Documented across watering-hole & trojanized utility apps targeting mobile credentials.'
  }
];

export interface ManifestPreset {
  id: string;
  name: string;
  packageName: string;
  badge: string;
  xml: string;
}

export const MANIFEST_PRESETS: ManifestPreset[] = [
  {
    id: 'social-mega-app',
    name: 'Social Mega-App (Camera-Roll + Mic + GPS)',
    packageName: 'com.social.megafeed',
    badge: 'CRITICAL',
    xml: `<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.social.megafeed">
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.READ_MEDIA_IMAGES" />
    <uses-permission android:name="android.permission.READ_MEDIA_VIDEO" />
    <uses-permission android:name="android.permission.ACCESS_MEDIA_LOCATION" />
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE_MICROPHONE" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <uses-permission android:name="android.permission.ACCESS_BACKGROUND_LOCATION" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
    <uses-permission android:name="android.permission.WAKE_LOCK" />
</manifest>`
  },
  {
    id: 'free-vpn-utility',
    name: 'Free Utility / Flashlight Spyware Profile',
    packageName: 'com.fastfree.flashlight.vpn',
    badge: 'CRITICAL',
    xml: `<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.fastfree.flashlight.vpn">
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.READ_SMS" />
    <uses-permission android:name="android.permission.RECEIVE_SMS" />
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />
    <uses-permission android:name="android.permission.QUERY_ALL_PACKAGES" />
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
</manifest>`
  },
  {
    id: 'chat-messenger',
    name: 'Chat Messenger (Blanket Media + Mic + Contacts)',
    packageName: 'com.instant.chatapp',
    badge: 'HIGH',
    xml: `<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.instant.chatapp">
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.READ_MEDIA_IMAGES" />
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <uses-permission android:name="android.permission.WAKE_LOCK" />
</manifest>`
  },
  {
    id: 'zero-trust-hardened',
    name: 'Hardened Zero-Trust Offline Tool (Clean Baseline)',
    packageName: 'io.phantomglass.localvault',
    badge: 'CLEAN',
    xml: `<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="io.phantomglass.localvault">
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
</manifest>`
  }
];

export function auditManifestPermissions(manifestText: string): PermissionAuditReport {
  const pkgMatch = manifestText.match(/package\s*=\s*["']([^"']+)["']/);
  const packageName = pkgMatch ? pkgMatch[1] : 'com.audited.application';

  const xmlMatches = [...manifestText.matchAll(/android\.permission\.([A-Z0-9_]+)/g)].map((m) => m[1]);
  const rawList =
    xmlMatches.length > 0
      ? xmlMatches
      : manifestText
          .split(/[\s,;]+/)
          .map((s) => s.trim().replace(/^android\.permission\./, '').toUpperCase())
          .filter((s) => /^[A-Z][A-Z0-9_]{3,}$/.test(s));

  const permissions = [...new Set(rawList)];
  const permSet = new Set(permissions);
  const hasGallery = permSet.has('READ_MEDIA_IMAGES') || permSet.has('READ_EXTERNAL_STORAGE');

  const nodes: PermissionNode[] = permissions.map((p) => {
    const meta = PERMISSION_META[p];
    return {
      id: p,
      label: meta ? meta.label : p.replace(/_/g, ' ').toLowerCase(),
      category: meta ? meta.category : 'IDENTITY',
      risk: meta ? meta.risk : 'LOW'
    };
  });

  const chains: PermissionChainFinding[] = [];
  for (const rule of CHAIN_RULES) {
    const reqMet = rule.required.every((r) => (r === 'READ_MEDIA_IMAGES' ? hasGallery : permSet.has(r)));
    if (!reqMet) continue;

    const matchedReq = rule.required.map((r) =>
      r === 'READ_MEDIA_IMAGES' && !permSet.has('READ_MEDIA_IMAGES') ? 'READ_EXTERNAL_STORAGE' : r
    );
    const matchedAmp = rule.amplifiers.filter((a) => permSet.has(a));
    const matchedPermissions = [...new Set([...matchedReq, ...matchedAmp])];
    const revocable = matchedPermissions.filter(
      (p) => !['INTERNET', 'RECEIVE_BOOT_COMPLETED', 'WAKE_LOCK', 'ACCESS_NETWORK_STATE'].includes(p)
    );

    chains.push({
      id: rule.id,
      title: rule.title,
      severity: rule.severity,
      matchedPermissions,
      mechanism: rule.mechanism,
      realWorldPrecedent: rule.realWorldPrecedent,
      adbRevokeCommands: revocable.map(
        (p) => `adb shell pm revoke ${packageName} android.permission.${p}`
      )
    });
  }

  const nodeRisk = nodes.reduce(
    (acc, n) => acc + (n.risk === 'CRITICAL' ? 9 : n.risk === 'HIGH' ? 6 : n.risk === 'MEDIUM' ? 3 : 1),
    0
  );
  const chainRisk = chains.reduce((acc, c) => acc + (c.severity === 'CRITICAL' ? 24 : 14), 0);
  const blastRadiusScore = permissions.length === 0 ? 0 : Math.min(100, Math.round(nodeRisk * 0.55 + chainRisk));

  const riskLevel: PermissionAuditReport['riskLevel'] =
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
  if (hasGallery) {
    hardeningSteps.push(
      'Android 14+ / iOS: Switch Photos permission from "Allow all" to "Select limited photos" or "Don\'t allow".'
    );
    hardeningSteps.push(
      'In-App Privacy: Disable "Camera Roll Cloud Processing" and "AI Creative Suggestions" inside app settings.'
    );
  }
  if (permSet.has('RECORD_AUDIO')) {
    hardeningSteps.push('Restrict Microphone to "Ask every time" so background voice capture cannot trigger silently.');
  }
  if (permSet.has('ACCESS_BACKGROUND_LOCATION') || permSet.has('ACCESS_FINE_LOCATION')) {
    hardeningSteps.push('Disable "Precise Location" and revoke "Allow all the time" background GPS.');
  }
  if (permSet.has('READ_SMS')) {
    hardeningSteps.push('Immediately revoke SMS read access — non-default messaging apps have zero legitimate need for SMS OTPs.');
  }
  if (hardeningSteps.length === 0) {
    hardeningSteps.push('Zero dangerous permission chains detected. Maintain least-privilege posture.');
  }

  return {
    packageName,
    permissions,
    nodes,
    chains,
    blastRadiusScore,
    riskLevel,
    hardeningSteps,
    cloudBytesSent: 0
  };
}
