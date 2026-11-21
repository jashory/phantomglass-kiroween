import { useRef, useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Copy,
  Download,
  FileArchive,
  Layers,
  Link2,
  Play,
  ShieldCheck,
  Upload
} from 'lucide-react';
import {
  exorciseUnifiedBundle,
  runHauntedIncidentBundle,
  runUnifiedUserFiles,
  type UnifiedExorcismPackage,
  type UnifiedPipelineReport
} from '../engines/unifiedFrankensteinEngine';

interface UnifiedPipelineViewProps {
  onJumpToTab: (tab: 'exorcist' | 'permissions' | 'airgap' | 'dataset' | 'kiro') => void;
  onSyncBundleToOrgans?: (report: UnifiedPipelineReport) => void;
}

function StatusTag({ level }: { level: string }) {
  const cls =
    level === 'CRITICAL' || level === 'THREAT_DETECTED'
      ? 'border-rose-500/35 bg-rose-500/10 text-rose-300'
      : level === 'HIGH'
        ? 'border-amber-500/35 bg-amber-500/10 text-amber-300'
        : 'border-emerald-500/35 bg-emerald-500/10 text-emerald-300';
  return (
    <span className={`inline-flex items-center rounded-md border px-2 py-0.5 font-mono text-[11px] font-medium ${cls}`}>
      {level === 'THREAT_DETECTED' ? 'Threat' : level === 'EXORCISED' ? 'Verified clean' : level}
    </span>
  );
}

export function UnifiedPipelineView({ onJumpToTab, onSyncBundleToOrgans }: UnifiedPipelineViewProps) {
  const dropInputRef = useRef<HTMLInputElement | null>(null);
  const [report, setReport] = useState<UnifiedPipelineReport | null>(null);
  const [exorcised, setExorcised] = useState<UnifiedExorcismPackage | null>(null);
  const [running, setRunning] = useState(false);
  const [exorcising, setExorcising] = useState(false);
  const [copiedSha, setCopiedSha] = useState(false);

  const handleLoadHauntedPack = async () => {
    setRunning(true);
    setExorcised(null);
    try {
      const next = await runHauntedIncidentBundle();
      setReport(next);
      onSyncBundleToOrgans?.(next);
    } finally {
      setRunning(false);
    }
  };

  const handleFilesSelected = async (fileList: FileList | null) => {
    if (!fileList || fileList.length === 0) return;
    setRunning(true);
    setExorcised(null);
    try {
      const next = await runUnifiedUserFiles(Array.from(fileList));
      setReport(next);
      onSyncBundleToOrgans?.(next);
    } finally {
      setRunning(false);
    }
  };

  const handleFullExorcism = async () => {
    if (!report) return;
    setExorcising(true);
    try {
      const pkg = await exorciseUnifiedBundle(report);
      setExorcised(pkg);
    } finally {
      setExorcising(false);
    }
  };

  const copySha = (hash: string) => {
    navigator.clipboard?.writeText(hash).catch(() => {});
    setCopiedSha(true);
    setTimeout(() => setCopiedSha(false), 1800);
  };

  const displayedRisk = exorcised ? exorcised.afterRiskScore : (report?.masterRiskScore ?? null);

  return (
    <section className="grid items-start gap-6 lg:grid-cols-12">
      {/* Left: Calm Entry Control Panel */}
      <div className="space-y-4 lg:col-span-5">
        <div className="surface-card rounded-2xl p-6">
          <div className="flex items-center gap-2 text-sm font-semibold text-white">
            <Layers className="h-4 w-4 text-slate-300" />
            <span>Unified Frankenstein Incident Pipeline</span>
          </div>
          <p className="mt-2 text-sm leading-relaxed text-slate-400">
            Drop a full incident archive (.zip) or multiple files—or run the 1-click Haunted Sample Pack—to chain all
            seven local forensic organs into a single master verdict and clean export.
          </p>

          <button
            type="button"
            onClick={handleLoadHauntedPack}
            disabled={running}
            className="mt-5 flex w-full cursor-pointer items-center justify-center gap-2 rounded-xl bg-white px-4 py-3 text-sm font-semibold text-[#090B0F] transition hover:bg-slate-200 disabled:opacity-60"
          >
            <Play className="h-4 w-4 fill-current" />
            {running ? 'Running 7-Organ Chain in RAM...' : 'Load Haunted Incident Bundle (1-Click Demo)'}
          </button>

          <input
            ref={dropInputRef}
            type="file"
            multiple
            accept=".zip,.jpg,.jpeg,.png,.pdf,.xml,.plist,.xcprivacy,.csv,.tsv,.txt,.log,.env"
            className="hidden"
            onChange={(e) => handleFilesSelected(e.target.files)}
          />

          <button
            type="button"
            onClick={() => dropInputRef.current?.click()}
            className="mt-3 flex w-full cursor-pointer flex-col items-center justify-center rounded-xl border border-dashed border-[#273142] bg-[#0C0F15] px-4 py-6 text-center transition hover:border-slate-500 hover:bg-[#10151F]"
          >
            <FileArchive className="h-6 w-6 text-slate-400" />
            <span className="mt-2 text-sm font-medium text-slate-200">
              Drop a .zip archive or select multiple local files
            </span>
            <span className="mt-1 text-xs text-slate-500">
              JPEG, PNG, PDF, AndroidManifest.xml, Info.plist, logs, or CSV · 0 bytes uploaded
            </span>
          </button>

          <div className="mt-5 border-t border-[#1E2532] pt-4">
            <div className="text-xs font-medium text-slate-400">How the 7 organs chain together</div>
            <ol className="mt-2.5 space-y-2 text-xs text-slate-400">
              <li className="flex items-start gap-2">
                <span className="font-mono text-slate-500">01</span>
                <span>Image &amp; PDF parsers extract raw GPS coordinates, device serials &amp; active script triggers.</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="font-mono text-slate-500">02</span>
                <span>Android 8–17 &amp; Apple iOS auditors cross-link gallery/location rights against Stage 1 leaks.</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="font-mono text-slate-500">03</span>
                <span>Secret Air-Gap &amp; Columnar CSV Shrinker scrub credentials and compress dumps &gt;94% offline.</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="font-mono text-slate-500">04</span>
                <span>One-click full exorcism outputs clean media, .pgcol.gz archive &amp; WebCrypto SHA-256 proof.</span>
              </li>
            </ol>
          </div>
        </div>
      </div>

      {/* Right: Unified Verdict & Cross-Organ Kill-Chain */}
      <div className="min-w-0 space-y-4 lg:col-span-7">
        {!report ? (
          <div className="surface-card flex min-h-[380px] flex-col items-center justify-center rounded-2xl p-8 text-center">
            <Upload className="h-8 w-8 text-slate-500" />
            <h3 className="mt-4 text-lg font-semibold text-white">Ready for zero-cloud bundle inspection</h3>
            <p className="mt-1.5 max-w-md text-sm text-slate-400">
              Click <span className="text-slate-200 font-medium">Load Haunted Incident Bundle</span> on the left to
              watch six hostile artifacts flow through every PhantomGlass organ in under one second—strictly in RAM.
            </p>
          </div>
        ) : (
          <>
            {/* Master Verdict Bar */}
            <div className="surface-card rounded-2xl p-6">
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div>
                  <div className="flex flex-wrap items-center gap-2.5">
                    <h3 className="text-base font-semibold text-white">{report.bundleName}</h3>
                    <StatusTag level={exorcised ? 'EXORCISED' : report.masterRiskLevel} />
                  </div>
                  <p className="mt-1 font-mono text-xs text-slate-400">
                    {report.totalFilesProcessed} artifacts analyzed in {report.elapsedMs} ms · Cloud egress: 0 B
                  </p>
                </div>

                <div className="flex items-center gap-4">
                  <div className="text-right">
                    <div className="text-xs text-slate-400">Master risk score</div>
                    <div
                      className={`font-display text-2xl font-bold tabular-nums ${
                        displayedRisk === 0 ? 'text-emerald-400' : 'text-rose-400'
                      }`}
                    >
                      {displayedRisk}/100
                    </div>
                  </div>

                  {!exorcised && (
                    <button
                      type="button"
                      onClick={handleFullExorcism}
                      disabled={exorcising}
                      className="inline-flex cursor-pointer items-center gap-2 rounded-xl bg-white px-4 py-2.5 text-xs font-semibold text-[#090B0F] transition hover:bg-slate-200 disabled:opacity-60"
                    >
                      <ShieldCheck className="h-4 w-4" />
                      {exorcising ? 'Exorcising...' : 'Exorcise Entire Bundle'}
                    </button>
                  )}
                </div>
              </div>

              {/* Exorcism Completion Banner */}
              {exorcised && (
                <div className="mt-5 rounded-xl border border-emerald-500/35 bg-emerald-500/10 p-4">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="flex items-start gap-2.5">
                      <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-emerald-400" />
                      <div>
                        <div className="text-sm font-semibold text-emerald-200">
                          Full bundle exorcised — Risk reduced {exorcised.beforeRiskScore} → {exorcised.afterRiskScore} in{' '}
                          {exorcised.elapsedMs} ms
                        </div>
                        <div className="mt-0.5 font-mono text-xs text-emerald-300/80">
                          {exorcised.totalThreatsNeutralized.toLocaleString()} threat items neutralized · Chain SHA-256:{' '}
                          {exorcised.masterChainSha256.slice(0, 20)}...
                        </div>
                      </div>
                    </div>

                    <button
                      type="button"
                      onClick={() => copySha(exorcised.masterChainSha256)}
                      className="inline-flex cursor-pointer items-center gap-1.5 rounded-lg border border-emerald-500/40 bg-[#090B0F] px-3 py-1.5 font-mono text-xs text-emerald-300 hover:bg-[#10141C]"
                    >
                      <Copy className="h-3.5 w-3.5" />
                      {copiedSha ? 'Copied SHA-256' : 'Copy SHA-256'}
                    </button>
                  </div>

                  <div className="mt-3.5 flex flex-wrap gap-2">
                    <a
                      href={exorcised.attestationUrl}
                      download={exorcised.attestationFileName}
                      className="inline-flex cursor-pointer items-center gap-1.5 rounded-lg bg-white px-3 py-1.5 text-xs font-semibold text-[#090B0F] hover:bg-slate-200"
                    >
                      <Download className="h-3.5 w-3.5" />
                      Chain-of-Custody JSON
                    </a>
                    {exorcised.photoResult && (
                      <a
                        href={exorcised.photoResult.cleanUrl}
                        download={exorcised.photoResult.cleanFileName}
                        className="inline-flex cursor-pointer items-center gap-1.5 rounded-lg border border-slate-700 bg-[#0C0F15] px-3 py-1.5 text-xs font-medium text-slate-200 hover:border-slate-500"
                      >
                        <Download className="h-3.5 w-3.5" />
                        Clean JPEG ({exorcised.photoResult.afterReport.tags.length} tags)
                      </a>
                    )}
                    {exorcised.datasetResult && (
                      <a
                        href={exorcised.datasetResult.columnarGzUrl}
                        download={exorcised.datasetResult.columnarGzFileName}
                        className="inline-flex cursor-pointer items-center gap-1.5 rounded-lg border border-slate-700 bg-[#0C0F15] px-3 py-1.5 text-xs font-medium text-slate-200 hover:border-slate-500"
                      >
                        <Download className="h-3.5 w-3.5" />
                        Shrunk .pgcol.gz (-{exorcised.datasetResult.attestation.shrinkRatioPercent}%)
                      </a>
                    )}
                  </div>
                </div>
              )}
            </div>

            {/* Cross-Organ Synergy Kill-Chains */}
            {report.correlations.length > 0 && (
              <div className="surface-card rounded-2xl p-6">
                <div className="flex items-center gap-2 text-sm font-semibold text-white">
                  <Link2 className="h-4 w-4 text-rose-400" />
                  <span>Cross-Organ Threat Correlations ({report.correlations.length} active chains)</span>
                </div>
                <p className="mt-1 text-xs text-slate-400">
                  Findings linked across organs—proving how separate leaks combine into real-world data exfiltration.
                </p>

                <div className="mt-4 space-y-2.5">
                  {report.correlations.map((c) => (
                    <div key={c.id} className="surface-inset rounded-xl p-4">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400" />
                          <span className="text-sm font-medium text-white">{c.title}</span>
                        </div>
                        <StatusTag level={exorcised ? 'EXORCISED' : c.severity} />
                      </div>
                      <p className="mt-1.5 text-xs leading-relaxed text-slate-400">{c.explanation}</p>
                      <div className="mt-2.5 flex flex-wrap items-center gap-1.5 font-mono text-[11px] text-slate-300">
                        {c.organsLinked.map((org, idx) => (
                          <span key={org} className="inline-flex items-center gap-1.5">
                            <span className="rounded border border-[#252E3E] bg-[#131823] px-2 py-0.5">{org}</span>
                            {idx < c.organsLinked.length - 1 && <ArrowRight className="h-3 w-3 text-slate-500" />}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Chained Stage-by-Stage Breakdown */}
            <div className="surface-card rounded-2xl p-6">
              <div className="text-sm font-semibold text-white">Chained Organ Execution Log</div>
              <div className="mt-3 divide-y divide-[#1A212D] rounded-xl border border-[#1E2532] bg-[#0C0F15]">
                {report.stages.map((st) => {
                  const targetTab =
                    st.id.includes('exif') || st.id.includes('pdf')
                      ? 'exorcist'
                      : st.id.includes('mobile') || st.id.includes('android') || st.id.includes('ios')
                        ? 'permissions'
                        : st.id.includes('secret')
                          ? 'airgap'
                          : 'dataset';
                  return (
                    <div key={st.id} className="flex flex-wrap items-center justify-between gap-3 px-4 py-3.5">
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-xs font-semibold text-white">{st.organ}</span>
                          <span className="font-mono text-[11px] text-slate-500">{st.fileName}</span>
                        </div>
                        <div className="mt-1 text-xs text-slate-300">{st.headlineMetric}</div>
                        <div className="mt-0.5 text-[11px] text-slate-500">{st.detail}</div>
                      </div>
                      <div className="flex items-center gap-2.5">
                        <StatusTag level={exorcised ? 'EXORCISED' : st.status} />
                        <button
                          type="button"
                          onClick={() => onJumpToTab(targetTab)}
                          className="cursor-pointer rounded-lg border border-[#252E3E] bg-[#111622] px-2.5 py-1 text-xs text-slate-300 transition hover:border-slate-500 hover:text-white"
                        >
                          Inspect
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </>
        )}
      </div>
    </section>
  );
}
