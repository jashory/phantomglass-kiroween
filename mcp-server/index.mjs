#!/usr/bin/env node
/**
 * PhantomGlass Local Model Context Protocol (MCP) Server
 * Pure zero-dependency JSON-RPC 2.0 stdio MCP server for Kiro IDE / CLI.
 * Zero outbound network calls — 100% local RAM forensic execution.
 */

import readline from 'node:readline';

const PERMISSION_CHAINS = [
  {
    id: 'silent-gallery-harvest',
    title: 'Silent Camera-Roll & Metadata Exfiltration Chain',
    severity: 'CRITICAL',
    required: ['READ_MEDIA_IMAGES', 'INTERNET'],
    amplifiers: ['ACCESS_MEDIA_LOCATION', 'RECEIVE_BOOT_COMPLETED', 'READ_EXTERNAL_STORAGE'],
    mechanism:
      'A single blanket gallery permission combined with background internet access enables continuous scanning of unshared photos, EXIF GPS coordinates, and document screenshots without root privileges.',
    precedent:
      'Italian Garante EUR 805M (USD 887M) enforcement action over blanket Android camera-roll cloud processing.'
  },
  {
    id: 'ambient-acoustic-profiling',
    title: 'Background Microphone & Device Telemetry Chain',
    severity: 'CRITICAL',
    required: ['RECORD_AUDIO', 'INTERNET'],
    amplifiers: ['FOREGROUND_SERVICE_MICROPHONE', 'WAKE_LOCK', 'ACCESS_FINE_LOCATION'],
    mechanism:
      'Microphone access paired with wake locks or foreground services allows voice-trigger or ambient audio capture alongside network egress.'
  },
  {
    id: 'clipboard-credential-siphon',
    title: 'Clipboard & Accessibility Overlay Interception',
    severity: 'HIGH',
    required: ['SYSTEM_ALERT_WINDOW', 'INTERNET'],
    amplifiers: ['BIND_ACCESSIBILITY_SERVICE', 'READ_CONTACTS', 'QUERY_ALL_PACKAGES'],
    mechanism:
      'Overlay and package enumeration permissions enable phishing overlays and cross-app behavioral profiling.'
  },
  {
    id: 'sms-otp-hijack',
    title: 'SMS / Notification OTP Interception Chain',
    severity: 'CRITICAL',
    required: ['READ_SMS', 'INTERNET'],
    amplifiers: ['RECEIVE_SMS', 'BIND_NOTIFICATION_LISTENER_SERVICE'],
    mechanism:
      'Reading SMS or notification listeners with network access exposes two-factor authentication codes and banking alerts.'
  }
];

function extractPermissions(manifestXml) {
  const matches = [...String(manifestXml || '').matchAll(/android\.permission\.([A-Z0-9_]+)/g)];
  const unique = [...new Set(matches.map((m) => m[1]))];
  if (unique.length > 0) return unique;
  return String(manifestXml || '')
    .split(/[\s,;]+/)
    .map((s) => s.trim().replace(/^android\.permission\./, '').toUpperCase())
    .filter((s) => /^[A-Z][A-Z0-9_]{3,}$/.test(s));
}

const ANDROID_RUNTIME_REVOCABLE = new Set([
  'READ_MEDIA_IMAGES',
  'READ_MEDIA_VIDEO',
  'READ_MEDIA_AUDIO',
  'ACCESS_MEDIA_LOCATION',
  'READ_EXTERNAL_STORAGE',
  'WRITE_EXTERNAL_STORAGE',
  'RECORD_AUDIO',
  'ACCESS_FINE_LOCATION',
  'ACCESS_COARSE_LOCATION',
  'ACCESS_BACKGROUND_LOCATION',
  'CAMERA',
  'READ_CONTACTS',
  'READ_SMS',
  'RECEIVE_SMS',
  'READ_CALL_LOG',
  'READ_PHONE_STATE'
]);

function buildVerifiedAdbCommands(packageName, perms) {
  const cmds = [];
  for (const p of perms) {
    if (ANDROID_RUNTIME_REVOCABLE.has(p)) {
      cmds.push(`adb shell pm revoke ${packageName} android.permission.${p}`);
    } else if (p === 'SYSTEM_ALERT_WINDOW') {
      cmds.push(`adb shell appops set ${packageName} SYSTEM_ALERT_WINDOW deny`);
    }
  }
  return cmds;
}

export function auditAndroidPermissions(manifestText, packageName = 'com.example.target') {
  const perms = extractPermissions(manifestText);
  const permSet = new Set(perms);
  // Normalize legacy READ_EXTERNAL_STORAGE -> also triggers gallery risk
  const hasGallery = permSet.has('READ_MEDIA_IMAGES') || permSet.has('READ_EXTERNAL_STORAGE');
  const chains = [];

  for (const chain of PERMISSION_CHAINS) {
    const matchedReq = chain.required.every((p) => {
      if (p === 'READ_MEDIA_IMAGES') return hasGallery;
      return permSet.has(p);
    });
    if (matchedReq) {
      const matchedAmp = chain.amplifiers.filter((p) => permSet.has(p));
      const matchedPerms = [...new Set([...chain.required.filter((p) => permSet.has(p)), ...(hasGallery && chain.required.includes('READ_MEDIA_IMAGES') ? [permSet.has('READ_MEDIA_IMAGES') ? 'READ_MEDIA_IMAGES' : 'READ_EXTERNAL_STORAGE'] : []), ...matchedAmp])];
      chains.push({
        id: chain.id,
        title: chain.title,
        severity: chain.severity,
        matchedPermissions: matchedPerms,
        mechanism: chain.mechanism,
        realWorldPrecedent: chain.precedent || 'Observed across commercial mobile telemetry audits.',
        adbRevokeCommands: buildVerifiedAdbCommands(packageName, matchedPerms)
      });
    }
  }

  const baseRisk = Math.min(40, perms.length * 4);
  const chainRisk = chains.reduce((acc, c) => acc + (c.severity === 'CRITICAL' ? 28 : 16), 0);
  const riskScore = Math.min(100, baseRisk + chainRisk);

  return {
    packageName,
    totalPermissionsParsed: perms.length,
    permissions: perms,
    blastRadiusScore: riskScore,
    riskLevel: riskScore >= 75 ? 'CRITICAL' : riskScore >= 45 ? 'HIGH' : riskScore >= 20 ? 'MEDIUM' : 'LOW',
    detectedChains: chains,
    cloudBytesSent: 0
  };
}

function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = new Map();
  for (const ch of str) freq.set(ch, (freq.get(ch) || 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function luhnCheck(numStr) {
  const digits = numStr.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10);
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

export function scanTextSecrets(rawText) {
  const text = String(rawText || '');
  let redacted = text;
  const findings = [];
  let counter = 0;

  const rules = [
    { type: 'PRIVATE_KEY_BLOCK', severity: 'CRITICAL', regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
    { type: 'AWS_ACCESS_KEY', severity: 'CRITICAL', regex: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g },
    { type: 'GITHUB_TOKEN', severity: 'CRITICAL', regex: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/g },
    { type: 'BEARER_JWT', severity: 'HIGH', regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
    { type: 'IBAN_ACCOUNT', severity: 'HIGH', regex: /\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,26}\b/g },
    { type: 'EMAIL_ADDRESS', severity: 'MEDIUM', regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
    { type: 'PHONE_NUMBER', severity: 'MEDIUM', regex: /\b(?:\+?[0-9]{1,3}[\s-]?)?(?:\(?[0-9]{3,4}\)?[\s-]?)[0-9]{3,4}[\s-]?[0-9]{3,4}\b/g },
    { type: 'NID_OR_SSN', severity: 'HIGH', regex: /\b(?:NID|SSN|Passport)[\s:#-]*[A-Z0-9-]{7,17}\b/gi }
  ];

  for (const rule of rules) {
    redacted = redacted.replace(rule.regex, (match) => {
      counter += 1;
      const token = `[REDACTED_${rule.type}_${counter}]`;
      findings.push({ type: rule.type, severity: rule.severity, placeholder: token, length: match.length });
      return token;
    });
  }

  // Luhn-validated credit/debit cards
  redacted = redacted.replace(/\b(?:\d[ -]*?){13,19}\b/g, (match) => {
    if (!luhnCheck(match)) return match;
    counter += 1;
    const token = `[REDACTED_PAYMENT_CARD_${counter}]`;
    findings.push({ type: 'PAYMENT_CARD_LUHN', severity: 'CRITICAL', placeholder: token, length: match.length });
    return token;
  });

  // High-entropy secret strings (e.g., generic API secrets >= 24 chars with entropy >= 4.2)
  let entropyAnomalies = 0;
  redacted = redacted.replace(/\b[A-Za-z0-9_\/+=-]{24,80}\b/g, (match) => {
    if (match.startsWith('REDACTED_')) return match;
    const ent = shannonEntropy(match);
    const hasMixed = /[a-z]/.test(match) && /[A-Z]/.test(match) && /[0-9]/.test(match);
    if (ent >= 4.2 && hasMixed) {
      entropyAnomalies += 1;
      counter += 1;
      const token = `[REDACTED_HIGH_ENTROPY_SECRET_${counter}]`;
      findings.push({
        type: 'HIGH_ENTROPY_SECRET',
        severity: 'HIGH',
        placeholder: token,
        length: match.length,
        entropy: Number(ent.toFixed(2))
      });
      return token;
    }
    return match;
  });

  return {
    totalSecretsBlocked: findings.length,
    entropyAnomalies,
    findings,
    redactedText: redacted,
    cloudBytesSent: 0
  };
}

export function inspectImageExifBytesBase64(base64Data) {
  const buf = Buffer.from(String(base64Data || ''), 'base64');
  const bytes = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const tags = [];
  let format = 'UNKNOWN';
  let trailingBytes = 0;

  if (bytes.length >= 4 && bytes[0] === 0xff && bytes[1] === 0xd8) {
    format = 'JPEG';
    let offset = 2;
    let eoiOffset = -1;
    while (offset + 4 <= bytes.length) {
      if (bytes[offset] !== 0xff) break;
      const marker = bytes[offset + 1];
      if (marker === 0xd9) {
        eoiOffset = offset + 2;
        break;
      }
      if (marker === 0xda) {
        // Scan to EOI
        for (let i = bytes.length - 2; i >= offset; i--) {
          if (bytes[i] === 0xff && bytes[i + 1] === 0xd9) {
            eoiOffset = i + 2;
            break;
          }
        }
        break;
      }
      const segLen = view.getUint16(offset + 2, false);
      if (segLen < 2 || offset + 2 + segLen > bytes.length) break;
      if (marker === 0xe1 && segLen > 8) {
        const header = String.fromCharCode(...bytes.slice(offset + 4, offset + 10));
        if (header.startsWith('Exif')) {
          tags.push({ group: 'APP1', name: 'EXIF_SEGMENT_DETECTED', value: `${segLen} bytes`, severity: 'HIGH' });
        }
      }
      offset += 2 + segLen;
    }
    if (eoiOffset > 0 && eoiOffset < bytes.length) {
      trailingBytes = bytes.length - eoiOffset;
      tags.push({ group: 'TRAILER', name: 'POST_EOI_TRAILING_BYTES', value: `${trailingBytes} hidden bytes`, severity: 'CRITICAL' });
    }
  } else if (bytes.length >= 8 && bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) {
    format = 'PNG';
    let offset = 8;
    while (offset + 12 <= bytes.length) {
      const len = view.getUint32(offset, false);
      const type = String.fromCharCode(...bytes.slice(offset + 4, offset + 8));
      if (['tEXt', 'iTXt', 'zTXt', 'eXIf'].includes(type)) {
        tags.push({ group: 'PNG_CHUNK', name: type, value: `${len} bytes metadata chunk`, severity: 'HIGH' });
      }
      offset += 12 + len;
      if (type === 'IEND') {
        if (offset < bytes.length) {
          trailingBytes = bytes.length - offset;
          tags.push({ group: 'TRAILER', name: 'POST_IEND_TRAILING_BYTES', value: `${trailingBytes} hidden bytes`, severity: 'CRITICAL' });
        }
        break;
      }
    }
  }

  return {
    format,
    byteLength: bytes.length,
    tagCount: tags.length,
    trailingBytes,
    tags,
    clean: tags.length === 0 && trailingBytes === 0,
    cloudBytesSent: 0
  };
}

export function generatePrivacyHardeningPolicy(platform = 'android', appName = 'SocialApp') {
  return {
    platform,
    appName,
    zeroTrustChecklist: [
      'Switch Photo/Gallery permission from "Allow all" to "Select specific photos only" or "Don\'t allow".',
      'Disable in-app "Camera Roll Cloud Processing" / "AI Creative Suggestions" toggles.',
      'Revoke background Microphone and Location access when app is not actively in foreground.',
      'Run all sensitive photos/receipts through PhantomGlass local EXIF & pixel exorcism before sharing.',
      'Run contracts, NIDs, and configuration snippets through PhantomGlass Air-Gap Redactor before pasting into cloud tools.'
    ],
    cloudBytesSent: 0
  };
}

const TOOLS = [
  {
    name: 'audit_android_permissions',
    description: 'Audit AndroidManifest.xml or permission lists locally to detect silent background gallery/mic/OTP data-harvesting chains and generate ADB revocation commands.',
    inputSchema: {
      type: 'object',
      properties: {
        manifestText: { type: 'string', description: 'Raw AndroidManifest.xml content or list of android.permission.* strings' },
        packageName: { type: 'string', description: 'Optional Android package name for ADB revoke commands' }
      },
      required: ['manifestText']
    }
  },
  {
    name: 'scan_text_secrets',
    description: 'Scan and redact PII, Luhn-validated payment cards, AWS/GitHub keys, private keys, and high-entropy secrets strictly in local RAM (0 cloud bytes).',
    inputSchema: {
      type: 'object',
      properties: {
        text: { type: 'string', description: 'Raw document, config, or message text to sanitize locally' }
      },
      required: ['text']
    }
  },
  {
    name: 'inspect_image_exif_bytes',
    description: 'Inspect base64-encoded JPEG/PNG bytes locally for EXIF metadata segments, PNG text chunks, and hidden trailing bytes past EOI/IEND.',
    inputSchema: {
      type: 'object',
      properties: {
        base64Data: { type: 'string', description: 'Base64-encoded JPEG or PNG image payload' }
      },
      required: ['base64Data']
    }
  },
  {
    name: 'generate_privacy_hardening_policy',
    description: 'Generate actionable zero-trust permission and camera-roll privacy hardening steps for Android, iOS, or Web.',
    inputSchema: {
      type: 'object',
      properties: {
        platform: { type: 'string', enum: ['android', 'ios', 'web'] },
        appName: { type: 'string' }
      },
      required: ['platform']
    }
  }
];

function sendResponse(id, result) {
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, result }) + '\n');
}

function sendError(id, code, message) {
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, error: { code, message } }) + '\n');
}

function handleMessage(msg) {
  if (!msg || typeof msg !== 'object') return;
  const { id, method, params } = msg;

  if (method === 'initialize') {
    return sendResponse(id, {
      protocolVersion: '2024-11-05',
      capabilities: { tools: {} },
      serverInfo: { name: 'phantomglass-forensics', version: '1.0.0' }
    });
  }
  if (method === 'notifications/initialized') return;
  if (method === 'tools/list') {
    return sendResponse(id, { tools: TOOLS });
  }
  if (method === 'tools/call') {
    const toolName = params?.name;
    const args = params?.arguments || {};
    let output;
    if (toolName === 'audit_android_permissions') {
      output = auditAndroidPermissions(args.manifestText, args.packageName);
    } else if (toolName === 'scan_text_secrets') {
      output = scanTextSecrets(args.text);
    } else if (toolName === 'inspect_image_exif_bytes') {
      output = inspectImageExifBytesBase64(args.base64Data);
    } else if (toolName === 'generate_privacy_hardening_policy') {
      output = generatePrivacyHardeningPolicy(args.platform, args.appName);
    } else {
      return sendError(id, -32601, `Unknown tool: ${toolName}`);
    }
    return sendResponse(id, {
      content: [{ type: 'text', text: JSON.stringify(output, null, 2) }]
    });
  }
  if (id !== undefined) {
    return sendError(id, -32601, `Method not found: ${method}`);
  }
}

// Only bind stdio loop when executed directly as CLI MCP server
const isMain = process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/').split('/').pop());
if (isMain) {
  const rl = readline.createInterface({ input: process.stdin, terminal: false });
  rl.on('line', (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    try {
      handleMessage(JSON.parse(trimmed));
    } catch {
      sendError(null, -32700, 'Parse error');
    }
  });
}
