import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { execSync } from 'node:child_process';
import { chromium } from 'playwright';

const OUT_DIR = process.env.CLOUD_OUT_DIR || path.resolve('cloud_vm_output');
fs.mkdirSync(OUT_DIR, { recursive: true });

const LIVE_URL = 'https://jashory.github.io/phantomglass-kiroween/';
const EXT_DIR = path.resolve('extension');

async function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function runDesktopAndMobileAudit() {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 960 }, deviceScaleFactor: 1 });
  const page = await context.newPage();

  const consoleErrors = [];
  const thirdPartyRequests = [];
  page.on('console', (msg) => {
    if (msg.type() === 'error') consoleErrors.push(msg.text());
  });
  page.on('pageerror', (err) => consoleErrors.push(String(err)));
  page.on('request', (req) => {
    const u = req.url();
    if (!u.startsWith('https://jashory.github.io/') && !u.startsWith('data:') && !u.startsWith('blob:')) {
      thirdPartyRequests.push(u);
    }
  });

  await page.goto(LIVE_URL, { waitUntil: 'networkidle', timeout: 45000 });
  await sleep(1000);

  // Verify default Unified Pipeline view & click Load Haunted Incident Bundle
  const loadBtn = page.getByRole('button', { name: /Load Haunted Incident Bundle/i }).first();
  await loadBtn.waitFor({ state: 'visible', timeout: 15000 });
  await loadBtn.click();
  await sleep(1800);

  // Screenshot 1 (3:2 1440x960): Unified 7-Organ Pipeline with Haunted Bundle + Kill-Chains
  await page.screenshot({ path: path.join(OUT_DIR, '01_v3_unified_pipeline_haunted.jpg'), type: 'jpeg', quality: 92 });

  // Click Exorcise Entire Bundle
  const exorciseBtn = page.getByRole('button', { name: /Exorcise Entire Bundle/i }).first();
  await exorciseBtn.waitFor({ state: 'visible', timeout: 15000 });
  await exorciseBtn.click();
  await sleep(1800);

  // Screenshot 2 (3:2 1440x960): Exorcised Risk 0 + SHA-256 Chain of Custody
  await page.screenshot({ path: path.join(OUT_DIR, '02_v3_unified_exorcised_zero_risk.jpg'), type: 'jpeg', quality: 92 });

  // Switch to Tab 5 (Kiro Hooks & MCP) & trigger live rogue telemetry block
  const kiroTab = page.getByRole('button', { name: /Kiro Hooks & MCP/i }).first();
  await kiroTab.click();
  await sleep(1000);
  const rogueBtn = page.getByRole('button', { name: /Inject Rogue Telemetry Leak/i }).first();
  if (await rogueBtn.isVisible().catch(() => false)) {
    await rogueBtn.click();
    await sleep(1000);
  }
  await page.screenshot({ path: path.join(OUT_DIR, '03_v3_kiro_hook_interceptor_live.jpg'), type: 'jpeg', quality: 92 });

  // Mobile 390x844 overflow check
  const mobileCtx = await browser.newContext({ viewport: { width: 390, height: 844 } });
  const mPage = await mobileCtx.newPage();
  await mPage.goto(LIVE_URL, { waitUntil: 'networkidle', timeout: 45000 });
  await sleep(800);
  const mobileOverflow = await mPage.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 2);
  await mobileCtx.close();

  await browser.close();
  return { consoleErrors, thirdPartyRequests, mobileOverflow };
}

async function runChromeExtensionLiveTest() {
  // Start local test AI chat webpage to verify content.js inline air-gap banner in live Chromium
  const html = `<!doctype html>
  <html lang="en">
  <head><meta charset="utf-8"><title>Enterprise AI Assistant — Live Prompt Test</title>
  <style>
    body { margin:0; font-family: Inter, system-ui, sans-serif; background:#0B0E14; color:#F1F5F9; display:flex; align-items:center; justify-content:center; min-height:100vh; }
    .card { width:780px; background:#111621; border:1px solid #263042; border-radius:14px; padding:32px; box-shadow:0 24px 64px rgba(0,0,0,0.5); }
    h1 { font-size:20px; margin:0 0 8px; letter-spacing:-0.02em; }
    p { font-size:13px; color:#94A3B8; margin:0 0 18px; }
    textarea { width:100%; height:170px; background:#090C11; color:#E2E8F0; border:1px solid #334155; border-radius:10px; padding:14px; font-family: ui-monospace, monospace; font-size:13px; box-sizing:border-box; }
    .bar { display:flex; justify-content:space-between; align-items:center; margin-top:14px; }
    .pill { font-size:12px; color:#94A3B8; }
    button.send { background:#F8FAFC; color:#090B0F; border:none; border-radius:8px; padding:10px 18px; font-weight:600; cursor:pointer; }
  </style></head>
  <body>
    <div class="card">
      <h1>External Cloud AI Assistant — Prompt Composer</h1>
      <p>PhantomGlass MV3 v3.0.0 content script monitors form fields locally with 0 outbound network requests.</p>
      <textarea id="ai-prompt" placeholder="Paste deployment logs or code to debug..."></textarea>
      <div class="bar"><span class="pill">Model: External Cloud LLM</span><button class="send">Send Prompt</button></div>
    </div>
  </body></html>`;

  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
  });
  await new Promise((r) => server.listen(4173, '127.0.0.1', r));

  const userDataDir = '/tmp/pg-ext-profile-' + Date.now();
  const ctx = await chromium.launchPersistentContext(userDataDir, {
    headless: false,
    viewport: { width: 1440, height: 960 },
    args: [
      `--disable-extensions-except=${EXT_DIR}`,
      `--load-extension=${EXT_DIR}`,
      '--no-sandbox'
    ]
  });

  const page = await ctx.newPage();
  await page.goto('http://127.0.0.1:4173/', { waitUntil: 'domcontentloaded' });
  await sleep(1000);

  const secretSample = [
    'Debug why our prod deploy failed with these env keys:',
    'AWS_ACCESS_KEY_ID=' + 'AKIA' + 'IOSFODNN7EXAMPLE',
    'STRIPE_SECRET=' + 'sk_' + 'live_' + '51NxTest9xK2mP7qR4sT8vW1yZ3b',
    'GITHUB_TOKEN=' + 'ghp_' + '1234567890abcdefghijklmnopqrstuvwxyz1234'
  ].join('\n');

  await page.fill('#ai-prompt', secretSample);
  await page.dispatchEvent('#ai-prompt', 'input');
  await sleep(1200);

  const bannerVisible = await page.locator('#phantomglass-live-airgap-banner').isVisible().catch(() => false);
  await page.screenshot({ path: path.join(OUT_DIR, '04_v3_chrome_ext_inline_airgap.jpg'), type: 'jpeg', quality: 92 });

  let scrubbedText = '';
  if (bannerVisible) {
    await page.locator('#phantomglass-airgap-redact-btn').click();
    await sleep(600);
    scrubbedText = await page.inputValue('#ai-prompt');
  }

  await ctx.close();
  server.close();
  return {
    bannerVisible,
    redactedCleanly: scrubbedText.includes('[PHANTOMGLASS_REDACTED_') && !scrubbedText.includes('AKIA' + 'IOSFODNN7EXAMPLE')
  };
}

async function record1080pWalkthrough() {
  const videoDir = '/tmp/pg-v3-video';
  fs.mkdirSync(videoDir, { recursive: true });
  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({
    viewport: { width: 1920, height: 1080 },
    recordVideo: { dir: videoDir, size: { width: 1920, height: 1080 } }
  });
  const page = await ctx.newPage();
  await page.goto(LIVE_URL, { waitUntil: 'networkidle', timeout: 45000 });
  await sleep(2500);

  // Scene 1: Click Load Haunted Incident Bundle
  const loadBtn = page.getByRole('button', { name: /Load Haunted Incident Bundle/i }).first();
  await loadBtn.hover();
  await sleep(700);
  await loadBtn.click();
  await sleep(3200);

  // Smooth scroll to reveal Cross-Organ Kill-Chains & all 7 organs
  for (const y of [280, 560, 820, 420, 0]) {
    await page.evaluate((top) => window.scrollTo({ top, behavior: 'smooth' }), y);
    await sleep(2200);
  }

  // Scene 2: Click Exorcise Entire Bundle (Risk 96 -> 0 + SHA-256 Chain of Custody)
  const exorciseBtn = page.getByRole('button', { name: /Exorcise Entire Bundle/i }).first();
  await exorciseBtn.hover();
  await sleep(700);
  await exorciseBtn.click();
  await sleep(4200);
  await page.evaluate(() => window.scrollTo({ top: 320, behavior: 'smooth' }));
  await sleep(3200);
  await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'smooth' }));
  await sleep(1600);

  // Scene 3: Android & iOS 3D Topology Tab
  const mobileTab = page.getByRole('button', { name: /Android & iOS 3D/i }).first();
  if (await mobileTab.isVisible().catch(() => false)) {
    await mobileTab.click();
    await sleep(3500);
    await page.evaluate(() => window.scrollTo({ top: 300, behavior: 'smooth' }));
    await sleep(3200);
    await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'smooth' }));
    await sleep(1200);
  }

  // Scene 4: CSV Shrinker Tab
  const colTab = page.getByRole('button', { name: /CSV Shrinker/i }).first();
  if (await colTab.isVisible().catch(() => false)) {
    await colTab.click();
    await sleep(3500);
  }

  // Scene 5: Kiro Hooks & MCP Live Interceptor Tab (30s proof segment!)
  const kiroTab = page.getByRole('button', { name: /Kiro Hooks & MCP/i }).first();
  await kiroTab.click();
  await sleep(2400);
  const cleanBtn = page.getByRole('button', { name: /Load Clean Zero-Egress Patch/i }).first();
  if (await cleanBtn.isVisible().catch(() => false)) {
    await cleanBtn.click();
    await sleep(2600);
  }
  const rogueBtn = page.getByRole('button', { name: /Inject Rogue Telemetry Leak/i }).first();
  if (await rogueBtn.isVisible().catch(() => false)) {
    await rogueBtn.hover();
    await sleep(900);
    await rogueBtn.click();
    await sleep(4800);
  }
  await page.evaluate(() => window.scrollTo({ top: 380, behavior: 'smooth' }));
  await sleep(3200);

  const rawVideoPath = await page.video().path();
  await ctx.close();
  await browser.close();

  const finalMp4 = path.join(OUT_DIR, 'phantomglass_v3_live_walkthrough_1080p.mp4');
  execSync(
    `ffmpeg -y -ss 1.5 -i "${rawVideoPath}" -c:v libx264 -preset fast -crf 18 -r 30 -pix_fmt yuv420p -movflags +faststart "${finalMp4}"`,
    { stdio: 'inherit' }
  );
  return { finalMp4, bytes: fs.statSync(finalMp4).size };
}

(async () => {
  const webAudit = await runDesktopAndMobileAudit();
  const extAudit = await runChromeExtensionLiveTest();
  const recAudit = await record1080pWalkthrough();
  const summary = { webAudit, extAudit, recAudit };
  fs.writeFileSync(path.join(OUT_DIR, 'phantomglass_v3_verification.json'), JSON.stringify(summary, null, 2));
  console.log('PHANTOMGLASS_V3_VERIFICATION:', JSON.stringify(summary, null, 2));
  if (webAudit.consoleErrors.length > 0) process.exit(1);
  if (webAudit.thirdPartyRequests.length > 0) process.exit(1);
  if (webAudit.mobileOverflow) process.exit(1);
  if (!extAudit.bannerVisible || !extAudit.redactedCleanly) process.exit(1);
})();
