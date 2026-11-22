import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { spawn } from 'node:child_process';
import {
  auditAndroidPermissions,
  auditIosPlist,
  scrubAndShrinkCsv,
  scanTextSecrets,
  inspectImageExifBytesBase64,
  verifyZeroEgressAttestation
} from '../mcp-server/index.mjs';

const ROOT = path.resolve(import.meta.dirname, '..');

test('.kiro spec-driven v2.0 structure, hooks, steering, and mcp.json exist and are valid', () => {
  const requiredFiles = [
    '.kiro/specs/phantomglass-core/requirements.md',
    '.kiro/specs/phantomglass-core/design.md',
    '.kiro/specs/phantomglass-core/tasks.md',
    '.kiro/specs/binary-exorcist-engine/requirements.md',
    '.kiro/specs/binary-exorcist-engine/design.md',
    '.kiro/specs/binary-exorcist-engine/tasks.md',
    '.kiro/specs/universal-mobile-forensics/requirements.md',
    '.kiro/specs/universal-mobile-forensics/design.md',
    '.kiro/specs/universal-mobile-forensics/tasks.md',
    '.kiro/specs/columnar-dataset-scrubber/requirements.md',
    '.kiro/specs/columnar-dataset-scrubber/design.md',
    '.kiro/specs/columnar-dataset-scrubber/tasks.md',
    '.kiro/steering/product-and-privacy-constitution.md',
    '.kiro/steering/forensic-binary-standards.md',
    '.kiro/steering/kiroween-release-gate.md',
    '.kiro/hooks/zero-leak-security-audit.json',
    '.kiro/hooks/spec-sync-guard.json',
    '.kiro/settings/mcp.json'
  ];
  for (const rel of requiredFiles) {
    assert.ok(fs.existsSync(path.join(ROOT, rel)), `Missing required Kiro file: ${rel}`);
  }
  const mcpJson = JSON.parse(fs.readFileSync(path.join(ROOT, '.kiro/settings/mcp.json'), 'utf8'));
  assert.ok(mcpJson.mcpServers['phantomglass-forensics'], 'MCP server entry missing');
  const hook1 = JSON.parse(fs.readFileSync(path.join(ROOT, '.kiro/hooks/zero-leak-security-audit.json'), 'utf8'));
  assert.equal(hook1.version, 'v1');
});

test('Universal Android 8-17 (API 26-37) auditor emits version-accurate ADB & AppOps commands', () => {
  const xml = `
    <manifest package="com.social.harvester">
      <uses-permission android:name="android.permission.INTERNET" />
      <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
      <uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE" />
      <uses-permission android:name="android.permission.READ_MEDIA_IMAGES" />
      <uses-permission android:name="android.permission.ACCESS_MEDIA_LOCATION" />
      <uses-permission android:name="android.permission.RECORD_AUDIO" />
      <uses-permission android:name="android.permission.FOREGROUND_SERVICE_MICROPHONE" />
      <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />
      <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
    </manifest>
  `;

  // Android 8 (API 26): must NOT emit API 33 READ_MEDIA_IMAGES or API 30 MANAGE_EXTERNAL_STORAGE AppOp
  const rApi26 = auditAndroidPermissions(xml, 'com.social.harvester', 26);
  assert.equal(rApi26.cloudBytesSent, 0);
  const cmds26 = rApi26.detectedChains.flatMap((c) => c.adbRevokeCommands);
  assert.ok(cmds26.some((c) => c.includes('pm revoke com.social.harvester android.permission.READ_EXTERNAL_STORAGE')));
  assert.ok(!cmds26.some((c) => c.includes('READ_MEDIA_IMAGES')), 'API 26 must not emit API 33 READ_MEDIA_IMAGES');
  assert.ok(!cmds26.some((c) => c.includes('MANAGE_EXTERNAL_STORAGE')), 'API 26 must not emit API 30 MANAGE_EXTERNAL_STORAGE');

  // Android 14–17 (API 34–37): must emit READ_MEDIA_IMAGES + AppOps, and NEVER FOREGROUND_SERVICE_MICROPHONE
  const rApi37 = auditAndroidPermissions(xml, 'com.social.harvester', 37);
  const cmds37 = rApi37.detectedChains.flatMap((c) => c.adbRevokeCommands);
  assert.ok(cmds37.some((c) => c.includes('pm revoke com.social.harvester android.permission.READ_MEDIA_IMAGES')));
  assert.ok(cmds37.some((c) => c.includes('appops set com.social.harvester SYSTEM_ALERT_WINDOW deny')));
  assert.ok(cmds37.some((c) => c.includes('appops set com.social.harvester MANAGE_EXTERNAL_STORAGE deny')));
  assert.ok(cmds37.some((c) => c.includes('appops set com.social.harvester RUN_ANY_IN_BACKGROUND ignore')));
  assert.ok(
    !cmds37.some((c) => c.includes('pm revoke com.social.harvester android.permission.FOREGROUND_SERVICE_MICROPHONE')),
    'Non-runtime FOREGROUND_SERVICE_MICROPHONE must never be passed to pm revoke'
  );
});

test('Apple iOS Info.plist & PrivacyInfo.xcprivacy auditor detects camera-roll, ATT, ATS & fingerprinting', () => {
  const plist = `
    <plist version="1.0"><dict>
      <key>CFBundleIdentifier</key><string>com.harvester.ios</string>
      <key>NSPhotoLibraryUsageDescription</key><string>Full photo library</string>
      <key>NSUserTrackingUsageDescription</key><string>Track ads</string>
      <key>NSAllowsArbitraryLoads</key><true/>
      <key>NSPrivacyTracking</key><true/>
      <key>UIBackgroundModes</key><array><string>audio</string><string>fetch</string></array>
      <key>NSPrivacyTrackingDomains</key><array><string>ads.tracker.example</string></array>
      <key>NSPrivacyAccessedAPICategorySystemBootTime</key><string>35F9.1</string>
    </dict></plist>
  `;
  const rep = auditIosPlist(plist);
  assert.equal(rep.platform, 'ios');
  assert.equal(rep.bundleId, 'com.harvester.ios');
  assert.equal(rep.allowsArbitraryLoads, true);
  assert.equal(rep.privacyTrackingDeclared, true);
  assert.equal(rep.cloudBytesSent, 0);
  assert.ok(rep.blastRadiusScore >= 75);
  assert.ok(rep.detectedChains.some((c) => c.id === 'ios-camera-roll-harvest'));
  assert.ok(rep.detectedChains.some((c) => c.id === 'ios-ats-cleartext-downgrade'));
});

test('Organ #7 Columnar CSV Shrinker scrubs PII, drops bloat, achieves >75% shrink & emits SHA-256 proof', () => {
  const bloat = '{"trace_env":"k8s-prod-worker-042","redundant_headers":"000000000000000000000000000000000000000000000000000000000000"}';
  const rows = ['id,region,email,note,raw_debug_bloat'];
  for (let i = 0; i < 400; i++) {
    rows.push(`EVT-${i},us-east-1,user${i % 10}@corp.example,"AWS=AKIAIOSFODNN7EXAMPLE card=4532-0151-1283-0366","${bloat.replace(/"/g, '""')}"`);
  }
  const res = scrubAndShrinkCsv(rows.join('\n'), {
    dropColumns: ['raw_debug_bloat'],
    pseudonymizeColumns: ['email']
  });
  assert.equal(res.cloudBytesSent, 0);
  assert.equal(res.rowsScanned, 400);
  assert.equal(res.rowsExported, 400);
  assert.ok(res.shrinkRatioPercent >= 75, `Expected >=75% shrink, got ${res.shrinkRatioPercent}%`);
  assert.ok(res.piiCellsScrubbed >= 800, `Expected >=800 scrubbed secrets, got ${res.piiCellsScrubbed}`);
  assert.equal(res.pseudonymizedCells, 400);
  assert.ok(!res.cleanCsvPreview.includes('AKIAIOSFODNN7EXAMPLE'));
  assert.ok(!res.cleanCsvPreview.includes('4532-0151-1283-0366'));
  assert.ok(res.cleanCsvPreview.includes('PSEUDO_'));
  assert.equal(res.inputSha256.length, 64);
  assert.equal(res.columnarGzipSha256.length, 64);
});

test('Air-Gap secret scanner blocks AWS keys, Google/Firebase AIza keys, OpenAI/HF tokens, GitHub PATs, Luhn cards, and high-entropy tokens', () => {
  const gkey = 'AIzaSy' + 'D00000000000000000000000000EXAMPLE';
  const sample = `
    AWS=AKIAIOSFODNN7EXAMPLE
    GOOGLE=${gkey}
    OPENAI=sk-proj-1234567890abcdefghijklmnop
    HF=hf_1234567890abcdefghijklmnop
    GH=ghp_9xK2mP7qR4sT8vW1yZ3bC6dF9hJ2kL5nQ8rU
    CARD=4532-0151-1283-0366
    SECRET=Q9vX4mR8pL2kN7wT3zB6cF1hJ5dS9yG4uA8eM2qW
  `;
  const res = scanTextSecrets(sample);
  assert.equal(res.cloudBytesSent, 0);
  assert.ok(res.totalSecretsBlocked >= 7, `Expected >=7 secrets blocked, got ${res.totalSecretsBlocked}`);
  assert.ok(res.findings.some((f) => f.type === 'GOOGLE_FIREBASE_API_KEY' && f.severity === 'CRITICAL'));
  assert.ok(res.findings.some((f) => f.type === 'OPENAI_ANTHROPIC_KEY' && f.severity === 'CRITICAL'));
  assert.ok(res.findings.some((f) => f.type === 'HUGGINGFACE_TOKEN' && f.severity === 'CRITICAL'));
  assert.ok(!res.redactedText.includes('AKIAIOSFODNN7EXAMPLE'));
  assert.ok(!res.redactedText.includes(gkey));
  assert.ok(!res.redactedText.includes('4532-0151-1283-0366'));
});

test('Binary JPEG inspector flags EXIF APP1 segments and hidden post-EOI trailing payloads', () => {
  const exifPayload = Buffer.from('Exif\0\0II*\0\x08\0\0\0', 'binary');
  const segLen = Buffer.alloc(2);
  segLen.writeUInt16BE(exifPayload.length + 2, 0);
  const fakeJpeg = Buffer.concat([
    Buffer.from([0xff, 0xd8, 0xff, 0xe1]),
    segLen,
    exifPayload,
    Buffer.from([0xff, 0xd9]),
    Buffer.from('HIDDEN_TRACKER_PAYLOAD')
  ]);
  const report = inspectImageExifBytesBase64(fakeJpeg.toString('base64'));
  assert.equal(report.format, 'JPEG');
  assert.equal(report.clean, false);
  assert.equal(report.trailingBytes, 'HIDDEN_TRACKER_PAYLOAD'.length);
});

test('Standalone 7-tool stdio MCP server responds to initialize, tools/list, and tools/call cleanly', async () => {
  const child = spawn(process.execPath, [path.join(ROOT, 'mcp-server/index.mjs')], {
    stdio: ['pipe', 'pipe', 'pipe']
  });

  const responses = [];
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    for (const line of chunk.split('\n')) {
      if (line.trim()) responses.push(JSON.parse(line));
    }
  });

  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }) + '\n');
  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }) + '\n');
  child.stdin.write(
    JSON.stringify({
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: { name: 'audit_ios_plist', arguments: { plistXml: '<plist><dict><key>NSAllowsArbitraryLoads</key><true/></dict></plist>' } }
    }) + '\n'
  );
  child.stdin.write(
    JSON.stringify({
      jsonrpc: '2.0',
      id: 4,
      method: 'tools/call',
      params: { name: 'verify_zero_egress_attestation', arguments: { payloadLabel: 'ci-probe', payloadText: 'clean' } }
    }) + '\n'
  );
  child.stdin.end();

  await new Promise((resolve) => child.on('close', resolve));
  assert.equal(responses.length, 4);
  assert.equal(responses[0].result.serverInfo.version, '2.0.0');
  assert.equal(responses[1].result.tools.length, 7);
  const iosOut = JSON.parse(responses[2].result.content[0].text);
  assert.equal(iosOut.allowsArbitraryLoads, true);
  assert.equal(iosOut.cloudBytesSent, 0);
  const attOut = JSON.parse(responses[3].result.content[0].text);
  assert.equal(attOut.sha256.length, 64);
  assert.equal(attOut.cloudBytesSent, 0);
});

test('Zero outbound fetch/network telemetry inside all core local forensic engines', () => {
  const engineDir = path.join(ROOT, 'web/src/engines');
  const files = fs.readdirSync(engineDir);
  assert.ok(files.includes('iosPrivacyEngine.ts'));
  assert.ok(files.includes('columnarScrubberEngine.ts'));
  for (const file of files) {
    const content = fs.readFileSync(path.join(engineDir, file), 'utf8');
    assert.ok(!/\bfetch\s*\(/.test(content), `Forbidden fetch() call detected in ${file}`);
    assert.ok(!/XMLHttpRequest/.test(content), `Forbidden XMLHttpRequest detected in ${file}`);
  }
});

test('Companion Chrome Manifest V3 Side-Panel Extension files are valid and zero-cloud', () => {
  const manifestPath = path.join(ROOT, 'extension/manifest.json');
  assert.ok(fs.existsSync(manifestPath), 'extension/manifest.json missing');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  assert.equal(manifest.manifest_version, 3);
  assert.ok(manifest.permissions.includes('sidePanel'));
  assert.ok(fs.existsSync(path.join(ROOT, 'extension/sidepanel.html')));
  const spJs = fs.readFileSync(path.join(ROOT, 'extension/sidepanel.js'), 'utf8');
  assert.ok(!/\bfetch\s*\(/.test(spJs), 'Extension must have 0 outbound fetch calls');
});

test('Chaos resilience: truncated binary buffers & attestation helper never throw', () => {
  const truncated = Buffer.from([0xff, 0xd8, 0xff, 0xe1, 0x00, 0xff]).toString('base64');
  const res = inspectImageExifBytesBase64(truncated);
  assert.equal(res.format, 'JPEG');
  assert.equal(res.cloudBytesSent, 0);
  const att = verifyZeroEgressAttestation('empty', '');
  assert.equal(att.byteLength, 0);
});
