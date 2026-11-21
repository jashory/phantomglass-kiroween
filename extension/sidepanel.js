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

function luhnCheck(num) {
  const digits = String(num || '').replace(/\D/g, '');
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

function redactLocalSecrets(text) {
  let out = String(text || '');
  let count = 0;
  const patterns = [
    ['AWS_KEY', /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g],
    ['GITHUB_PAT', /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/g],
    ['JWT', /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g],
    ['NID_SSN', /\b(?:NID|SSN|Passport)[\s:#-]*[A-Z0-9-]{7,17}\b/gi],
    ['EMAIL', /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g]
  ];
  for (const [label, regex] of patterns) {
    out = out.replace(regex, () => {
      count += 1;
      return `[REDACTED_${label}_${count}]`;
    });
  }
  out = out.replace(/\b(?:\d[ -]*?){13,19}\b/g, (match) => {
    if (!luhnCheck(match)) return match;
    count += 1;
    return `[REDACTED_CARD_${count}]`;
  });
  return { count, redacted: out };
}

function auditMobileManifestSnippet(text) {
  const raw = String(text || '');
  const androidPerms = [...new Set([...raw.matchAll(/android\.permission\.([A-Z0-9_]+)/g)].map((m) => m[1]))];
  const iosKeys = [
    'NSPhotoLibraryUsageDescription',
    'NSMicrophoneUsageDescription',
    'NSLocationAlwaysAndWhenInUseUsageDescription',
    'NSUserTrackingUsageDescription',
    'NSAllowsArbitraryLoads',
    'NSPrivacyTracking'
  ].filter((k) => raw.includes(k));
  const risk = Math.min(100, androidPerms.length * 10 + iosKeys.length * 18);
  return {
    platformDetected: iosKeys.length > 0 ? 'iOS Info.plist / xcprivacy' : androidPerms.length > 0 ? 'Android 8-17 Manifest' : 'No mobile manifest keys detected',
    androidPermissions: androidPerms,
    iosPrivacyKeys: iosKeys,
    blastRadiusScore: risk,
    cloudBytesSent: 0
  };
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
  document.getElementById('redactOut').textContent = `Blocked ${res.count} secrets/PII (0 cloud bytes):\n\n${res.redacted}`;
});

document.getElementById('mobileBtn')?.addEventListener('click', () => {
  const raw = document.getElementById('secretInput').value;
  const res = auditMobileManifestSnippet(raw);
  document.getElementById('redactOut').textContent = JSON.stringify(res, null, 2);
});
