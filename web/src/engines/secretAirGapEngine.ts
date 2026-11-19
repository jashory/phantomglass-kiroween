/**
 * PhantomGlass Organ #4: Zero-Leak Shannon-Entropy & Luhn PII Air-Gap Redactor
 * Scrubs sensitive secrets, credentials, payment cards, and identity numbers strictly in local RAM.
 */

export interface SecretFinding {
  id: string;
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  placeholder: string;
  redactedLength: number;
  entropy?: number;
}

export interface SecretRedactionReport {
  redactedText: string;
  findings: SecretFinding[];
  totalSecretsBlocked: number;
  entropyAnomalies: number;
  cloudBytesSent: 0;
}

export function computeShannonEntropy(str: string): number {
  if (!str) return 0;
  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function validateLuhn(raw: string): boolean {
  const digits = raw.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10);
    if (shouldDouble) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

export function runAirGapRedaction(rawText: string): SecretRedactionReport {
  let redacted = rawText;
  const findings: SecretFinding[] = [];
  let seq = 0;

  const rules: Array<{ type: string; severity: SecretFinding['severity']; regex: RegExp }> = [
    {
      type: 'PRIVATE_KEY_BLOCK',
      severity: 'CRITICAL',
      regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g
    },
    { type: 'AWS_ACCESS_KEY', severity: 'CRITICAL', regex: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g },
    { type: 'GITHUB_PAT', severity: 'CRITICAL', regex: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/g },
    { type: 'BEARER_JWT', severity: 'HIGH', regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
    { type: 'IBAN_ACCOUNT', severity: 'HIGH', regex: /\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,26}\b/g },
    { type: 'NID_OR_SSN', severity: 'HIGH', regex: /\b(?:NID|SSN|Passport)[\s:#-]*[A-Z0-9-]{7,17}\b/gi },
    { type: 'EMAIL_ADDRESS', severity: 'MEDIUM', regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
    {
      type: 'PHONE_NUMBER',
      severity: 'MEDIUM',
      regex: /\b(?:\+?[0-9]{1,3}[\s-]?)?(?:\(?[0-9]{3,4}\)?[\s-]?)[0-9]{3,4}[\s-]?[0-9]{3,4}\b/g
    }
  ];

  for (const rule of rules) {
    redacted = redacted.replace(rule.regex, (match) => {
      seq += 1;
      const placeholder = `[REDACTED_${rule.type}_${seq}]`;
      findings.push({
        id: `${rule.type}-${seq}`,
        type: rule.type,
        severity: rule.severity,
        placeholder,
        redactedLength: match.length
      });
      return placeholder;
    });
  }

  // Luhn-validated payment card detection
  redacted = redacted.replace(/\b(?:\d[ -]*?){13,19}\b/g, (match) => {
    if (!validateLuhn(match)) return match;
    seq += 1;
    const placeholder = `[REDACTED_PAYMENT_CARD_${seq}]`;
    findings.push({
      id: `CARD-${seq}`,
      type: 'PAYMENT_CARD_LUHN',
      severity: 'CRITICAL',
      placeholder,
      redactedLength: match.length
    });
    return placeholder;
  });

  // High-entropy unknown credential detector
  let entropyAnomalies = 0;
  redacted = redacted.replace(/\b[A-Za-z0-9_/+=-]{24,80}\b/g, (match) => {
    if (match.includes('REDACTED_')) return match;
    const ent = computeShannonEntropy(match);
    const mixedClasses = /[a-z]/.test(match) && /[A-Z]/.test(match) && /[0-9]/.test(match);
    if (ent >= 4.2 && mixedClasses) {
      entropyAnomalies += 1;
      seq += 1;
      const placeholder = `[REDACTED_HIGH_ENTROPY_${seq}]`;
      findings.push({
        id: `ENTROPY-${seq}`,
        type: 'HIGH_ENTROPY_SECRET',
        severity: 'HIGH',
        placeholder,
        redactedLength: match.length,
        entropy: Number(ent.toFixed(2))
      });
      return placeholder;
    }
    return match;
  });

  return {
    redactedText: redacted,
    findings,
    totalSecretsBlocked: findings.length,
    entropyAnomalies,
    cloudBytesSent: 0
  };
}

export const SECRET_SCENARIOS = [
  {
    id: 'prod-env-leak',
    title: 'Production .env Config & Cloud Keys',
    content: `# Production Deployment Config (DO NOT PASTE INTO CLOUD AI)
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
GITHUB_DEPLOY_TOKEN=ghp_9xK2mP7qR4sT8vW1yZ3bC6dF9hJ2kL5nQ8rU
ADMIN_CONTACT=ops-lead@acme-corp.internal
FALLBACK_SIGNING_SECRET=Q9vX4mR8pL2kN7wT3zB6cF1hJ5dS9yG4uA8eM2qW`
  },
  {
    id: 'freelance-contract',
    title: 'Freelance NDA & Wire Transfer Details',
    content: `Contractor Agreement — Confidential Addendum
Legal Contractor: A. Rahman | NID: 4225720988123 | Phone: +880-1711-554433
Payout Account IBAN: DE89370400440532013000
Billing Email: finance-payouts@clientstudio.io
Clause 9.4: All pre-existing background IP and personal repositories created during the engagement become exclusive perpetual property of Client without additional royalty.`
  },
  {
    id: 'support-chat-card',
    title: 'Customer Support Log with Payment Card & JWT',
    content: `Customer Ticket #88412:
User reported double charge on card 4532-0151-1283-0366 for email user.billing@example.org.
Debug session header accidentally copied:
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3JfOTkyMSIsInJvbGUiOiJhZG1pbiJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`
  }
];
