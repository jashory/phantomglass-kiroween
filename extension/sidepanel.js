function auditActiveDom() {
  const forms = Array.from(document.forms || []);
  const externalForms = forms
    .map((f) => f.getAttribute('action') || '')
    .filter((a) => a.startsWith('http') && !a.startsWith(location.origin));
  const passwordInputs = document.querySelectorAll('input[type="password"]').length;
  const hiddenIframes = Array.from(document.querySelectorAll('iframe')).filter((ifr) => {
    const r = ifr.getBoundingClientRect();
    return r.width <= 2 || r.height <= 2 || getComputedStyle(ifr).opacity === '0';
  }).length;
  const thirdPartyScripts = Array.from(document.querySelectorAll('script[src]'))
    .map((s) => {
      try {
        return new URL(s.src).hostname;
      } catch {
        return '';
      }
    })
    .filter((h) => h && h !== location.hostname);

  const uniqueThirdParty = [...new Set(thirdPartyScripts)];
  const riskScore = Math.min(
    100,
    externalForms.length * 35 + hiddenIframes * 30 + (passwordInputs > 0 && location.protocol !== 'https:' ? 45 : 0) + Math.min(25, uniqueThirdParty.length * 3)
  );

  return {
    origin: location.origin,
    https: location.protocol === 'https:',
    riskScore,
    riskLevel: riskScore >= 60 ? 'CRITICAL' : riskScore >= 30 ? 'HIGH' : 'LOW',
    passwordInputs,
    externalFormTargets: externalForms,
    hiddenIframes,
    thirdPartyScriptHosts: uniqueThirdParty.slice(0, 8),
    cloudBytesSent: 0
  };
}

function redactLocalSecrets(text) {
  let out = String(text || '');
  let count = 0;
  const patterns = [
    ['AWS_KEY', /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g],
    ['GITHUB_PAT', /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/g],
    ['JWT', /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g],
    ['EMAIL', /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g],
    ['CARD', /\b(?:\d[ -]*?){13,19}\b/g]
  ];
  for (const [label, regex] of patterns) {
    out = out.replace(regex, () => {
      count += 1;
      return `[REDACTED_${label}_${count}]`;
    });
  }
  return { count, redacted: out };
}

document.getElementById('scanTabBtn')?.addEventListener('click', async () => {
  const outEl = document.getElementById('domReport');
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) throw new Error('No active tab found.');
    const [result] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: auditActiveDom
    });
    outEl.textContent = JSON.stringify(result.result, null, 2);
  } catch (err) {
    outEl.textContent = `Local scan notice: ${err.message} (Open any regular https:// page to inspect.)`;
  }
});

document.getElementById('redactBtn')?.addEventListener('click', () => {
  const raw = document.getElementById('secretInput').value;
  const res = redactLocalSecrets(raw);
  document.getElementById('redactOut').textContent = `Blocked ${res.count} secrets (0 cloud bytes):\n\n${res.redacted}`;
});
