import { useState } from 'react';
import { CheckCircle2, ShieldAlert, Terminal } from 'lucide-react';
import {
  KIRO_HOOK_TEST_SNIPPETS,
  runKiroZeroEgressHookCheck,
  type KiroHookCheckResult
} from '../engines/unifiedFrankensteinEngine';

export function KiroHookLivePanel() {
  const [code, setCode] = useState<string>(KIRO_HOOK_TEST_SNIPPETS.rogueTelemetry);
  const [result, setResult] = useState<KiroHookCheckResult>(() =>
    runKiroZeroEgressHookCheck(KIRO_HOOK_TEST_SNIPPETS.rogueTelemetry)
  );

  const runCheck = (src: string) => {
    setCode(src);
    setResult(runKiroZeroEgressHookCheck(src));
  };

  return (
    <div className="surface-card rounded-2xl p-5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Terminal className="h-4 w-4 text-slate-300" />
          <h3 className="text-sm font-semibold text-white">
            Live Kiro Agent Hook Guard (.kiro/hooks/zero-leak-security-audit.json)
          </h3>
        </div>
        <span
          className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 font-mono text-[11px] font-medium ${
            result.verdict === 'BLOCKED'
              ? 'border-rose-500/35 bg-rose-500/10 text-rose-300'
              : 'border-emerald-500/35 bg-emerald-500/10 text-emerald-300'
          }`}
        >
          {result.verdict === 'BLOCKED' ? (
            <ShieldAlert className="h-3.5 w-3.5" />
          ) : (
            <CheckCircle2 className="h-3.5 w-3.5" />
          )}
          {result.verdict === 'BLOCKED' ? `Save blocked (${result.violations.length} leaks)` : 'Zero-egress verified'}
        </span>
      </div>

      <p className="mt-1.5 text-xs text-slate-400">
        Test how Kiro enforces the project privacy constitution on every engine save—deterministically blocking any
        accidental outbound fetch, beacon, or socket before it reaches production.
      </p>

      <div className="mt-3 flex flex-wrap gap-2">
        <button
          type="button"
          onClick={() => runCheck(KIRO_HOOK_TEST_SNIPPETS.rogueTelemetry)}
          className="cursor-pointer rounded-lg border border-rose-500/35 bg-rose-500/10 px-3 py-1.5 text-xs font-medium text-rose-200 transition hover:bg-rose-500/20"
        >
          Inject Rogue Telemetry Leak
        </button>
        <button
          type="button"
          onClick={() => runCheck(KIRO_HOOK_TEST_SNIPPETS.cleanZeroEgress)}
          className="cursor-pointer rounded-lg border border-[#252E3E] bg-[#0C0F15] px-3 py-1.5 text-xs font-medium text-slate-200 transition hover:border-slate-500"
        >
          Load Clean Zero-Egress Patch
        </button>
      </div>

      <textarea
        value={code}
        onChange={(e) => runCheck(e.target.value)}
        rows={6}
        aria-label="Kiro hook test code snippet"
        className="mt-3 w-full rounded-xl border border-[#1E2532] bg-[#090B0F] p-3 font-mono text-xs text-slate-200 focus:border-slate-500 focus:outline-none"
      />

      {result.violations.length > 0 ? (
        <div className="mt-3 space-y-2">
          {result.violations.map((v, i) => (
            <div key={i} className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-3 text-xs">
              <div className="font-mono font-semibold text-rose-200">
                Line {v.line} · {v.rule}
              </div>
              <div className="mt-1 text-slate-300">{v.remediation}</div>
            </div>
          ))}
        </div>
      ) : (
        <div className="mt-3 rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-3 text-xs text-emerald-200">
          Hook passed: zero outbound fetch, sendBeacon, WebSocket, or XHR calls detected in {result.targetFile}.
        </div>
      )}
    </div>
  );
}
