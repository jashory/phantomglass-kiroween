/**
 * PhantomGlass v3.0 Live Webpage Air-Gap Content Script
 * Detects accidental AWS keys, GitHub PATs, Stripe keys, JWTs, or Luhn cards typed into
 * live web prompts/forms and offers 1-click local in-place redaction strictly in browser RAM.
 * ZERO network requests — ZERO telemetry.
 */
(() => {
  if (window.__phantomglassV3Loaded) return;
  window.__phantomglassV3Loaded = true;

  const RULES = [
    { name: 'GOOGLE_FIREBASE_API_KEY', re: /\bAIza[0-9A-Za-z_-]{33,40}\b/g },
    { name: 'OPENAI_ANTHROPIC_KEY', re: /\bsk-(?:proj-|ant-|live_|test_)?[A-Za-z0-9_-]{20,}\b/g },
    { name: 'HUGGINGFACE_TOKEN', re: /\bhf_[A-Za-z0-9]{20,}\b/g },
    { name: 'AWS_ACCESS_KEY', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
    { name: 'GITHUB_PAT', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b/g },
    { name: 'ATLASSIAN_API_TOKEN', re: /\bATATT3xFfGF0[A-Za-z0-9_=-]{20,}\b/g },
    { name: 'SLACK_TOKEN', re: /\bxox[baprs]-[A-Za-z0-9-]{16,}\b/g },
    { name: 'STRIPE_KEY', re: /\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
    { name: 'PRIVATE_KEY_BLOCK', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
    { name: 'JWT_TOKEN', re: /\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b/g }
  ];

  let banner = null;
  let activeField = null;

  function scanText(text) {
    const hits = [];
    for (const r of RULES) {
      r.re.lastIndex = 0;
      const matches = text.match(r.re);
      if (matches) {
        hits.push({ name: r.name, count: matches.length });
      }
    }
    return hits;
  }

  function redactText(text) {
    let out = text;
    for (const r of RULES) {
      r.re.lastIndex = 0;
      out = out.replace(r.re, `[PHANTOMGLASS_REDACTED_${r.name}]`);
    }
    return out;
  }

  function ensureBanner() {
    if (banner) return banner;
    banner = document.createElement('div');
    banner.id = 'phantomglass-live-airgap-banner';
    banner.style.cssText = [
      'position:fixed',
      'bottom:18px',
      'right:18px',
      'z-index:2147483647',
      'display:none',
      'align-items:center',
      'gap:12px',
      'padding:10px 14px',
      'border-radius:12px',
      'background:#0f131b',
      'border:1px solid #f43f5e',
      'color:#f8fafc',
      'font-family:Inter,system-ui,sans-serif',
      'font-size:12px',
      'box-shadow:0 12px 32px rgba(0,0,0,0.45)'
    ].join(';');

    const msg = document.createElement('span');
    msg.id = 'phantomglass-banner-msg';

    const btn = document.createElement('button');
    btn.id = 'phantomglass-redact-btn';
    btn.type = 'button';
    btn.textContent = 'Air-Gap Redact';
    btn.style.cssText = [
      'background:#ffffff',
      'color:#090b0f',
      'border:none',
      'border-radius:8px',
      'padding:6px 10px',
      'font-weight:600',
      'font-size:11px',
      'cursor:pointer'
    ].join(';');

    btn.addEventListener('click', () => {
      if (!activeField) return;
      if ('value' in activeField && typeof activeField.value === 'string') {
        activeField.value = redactText(activeField.value);
        activeField.dispatchEvent(new Event('input', { bubbles: true }));
      } else if (activeField.isContentEditable) {
        activeField.innerText = redactText(activeField.innerText || '');
      }
      banner.style.display = 'none';
    });

    banner.appendChild(msg);
    banner.appendChild(btn);
    document.documentElement.appendChild(banner);
    return banner;
  }

  function inspectTarget(target) {
    if (!target) return;
    const isInput = target.tagName === 'TEXTAREA' || (target.tagName === 'INPUT' && target.type === 'text');
    const isEditable = target.isContentEditable;
    if (!isInput && !isEditable) return;

    const text = isInput ? target.value : target.innerText || '';
    const hits = scanText(text);
    const el = ensureBanner();
    if (hits.length > 0) {
      activeField = target;
      const total = hits.reduce((a, h) => a + h.count, 0);
      const msg = el.querySelector('#phantomglass-banner-msg');
      if (msg) {
        msg.textContent = `PhantomGlass Air-Gap: ${total} secret${total > 1 ? 's' : ''} (${hits.map((h) => h.name).join(', ')}) detected offline`;
      }
      el.style.display = 'flex';
    } else if (activeField === target) {
      el.style.display = 'none';
    }
  }

  document.addEventListener('input', (e) => inspectTarget(e.target), true);
  document.addEventListener('paste', (e) => setTimeout(() => inspectTarget(e.target), 50), true);
})();
