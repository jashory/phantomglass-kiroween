import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { spawn } from 'node:child_process';
import {
  auditAndroidPermissions,
  scanTextSecrets,
  inspectImageExifBytesBase64
} from '../mcp-server/index.mjs';

const ROOT = path.resolve(import.meta.dirname, '..');

test('.kiro spec-driven structure, hooks, steering, and mcp.json exist and are valid', () => {
  const requiredFiles = [
    '.kiro/specs/phantomglass-core/requirements.md',
    '.kiro/specs/phantomglass-core/design.md',
    '.kiro/specs/phantomglass-core/tasks.md',
    '.kiro/specs/binary-exorcist-engine/requirements.md',
    '.kiro/specs/binary-exorcist-engine/design.md',
    '.kiro/specs/binary-exorcist-engine/tasks.md',
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

test('Android permission auditor detects silent camera-roll harvesting chain & generates ADB revokes', () => {
  const xml = `
    <manifest package="com.social.harvester">
      <uses-permission android:name="android.permission.INTERNET" />
      <uses-permission android:name="android.permission.READ_MEDIA_IMAGES" />
      <uses-permission android:name="android.permission.ACCESS_MEDIA_LOCATION" />
      <uses-permission android:name="android.permission.RECORD_AUDIO" />
    </manifest>
  `;
  const report = auditAndroidPermissions(xml, 'com.social.harvester');
  assert.equal(report.cloudBytesSent, 0);
  assert.ok(report.blastRadiusScore >= 60, `Expected high score, got ${report.blastRadiusScore}`);
  assert.ok(report.detectedChains.some((c) => c.id === 'silent-gallery-harvest'));
  assert.ok(
    report.detectedChains[0].adbRevokeCommands.some((cmd) =>
      cmd.includes('adb shell pm revoke com.social.harvester android.permission.READ_MEDIA_IMAGES')
    )
  );
});

test('Air-Gap secret scanner blocks AWS keys, GitHub PATs, Luhn cards, and high-entropy tokens', () => {
  const sample = `
    AWS=AKIAIOSFODNN7EXAMPLE
    GH=ghp_9xK2mP7qR4sT8vW1yZ3bC6dF9hJ2kL5nQ8rU
    CARD=4532-0151-1283-0366
    SECRET=Q9vX4mR8pL2kN7wT3zB6cF1hJ5dS9yG4uA8eM2qW
  `;
  const res = scanTextSecrets(sample);
  assert.equal(res.cloudBytesSent, 0);
  assert.ok(res.totalSecretsBlocked >= 4, `Expected >=4 secrets blocked, got ${res.totalSecretsBlocked}`);
  assert.ok(!res.redactedText.includes('AKIAIOSFODNN7EXAMPLE'));
  assert.ok(!res.redactedText.includes('4532-0151-1283-0366'));
});

test('Binary JPEG inspector flags EXIF APP1 segments and hidden post-EOI trailing payloads', () => {
  // Minimal valid JPEG header + APP1 Exif marker + EOI + trailing payload
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

test('Standalone stdio MCP server responds to initialize, tools/list, and tools/call cleanly', async () => {
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
      params: { name: 'scan_text_secrets', arguments: { text: 'Key AKIAIOSFODNN7EXAMPLE' } }
    }) + '\n'
  );
  child.stdin.end();

  await new Promise((resolve) => child.on('close', resolve));
  assert.equal(responses.length, 3);
  assert.equal(responses[0].result.serverInfo.name, 'phantomglass-forensics');
  assert.equal(responses[1].result.tools.length, 4);
  const parsedToolOut = JSON.parse(responses[2].result.content[0].text);
  assert.equal(parsedToolOut.totalSecretsBlocked, 1);
  assert.equal(parsedToolOut.cloudBytesSent, 0);
});

test('Zero outbound fetch/network telemetry inside core local forensic engines', () => {
  const engineDir = path.join(ROOT, 'web/src/engines');
  for (const file of fs.readdirSync(engineDir)) {
    const content = fs.readFileSync(path.join(engineDir, file), 'utf8');
    assert.ok(!/\bfetch\s*\(/.test(content), `Forbidden fetch() call detected in ${file}`);
    assert.ok(!/XMLHttpRequest/.test(content), `Forbidden XMLHttpRequest detected in ${file}`);
  }
});
