import { useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Copy,
  Cpu,
  Download,
  FileCode2,
  FileImage,
  FolderGit2,
  Lock,
  Radio,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
  Upload,
  WifiOff
} from 'lucide-react';
import {
  parseImageForensics,
  type BinaryForensicReport
} from './engines/exifBinaryParser';
import {
  exorciseImageFile,
  generateLiveForensicSpecimen,
  SPECIMEN_PRESETS,
  type ExorcismResult
} from './engines/mediaExorcist';
import {
  auditManifestPermissions,
  MANIFEST_PRESETS
} from './engines/permissionGraphEngine';
import {
  runAirGapRedaction,
  SECRET_SCENARIOS
} from './engines/secretAirGapEngine';
import { ThreatTopology3D } from './components/ThreatTopology3D';

type ActiveTab = 'exorcist' | 'permissions' | 'airgap' | 'kiro';

const KIRO_ARTIFACTS = [
  {
    path: '.kiro/specs/phantomglass-core/requirements.md',
    kind: 'EARS Spec',
    summary: '5 formal EARS requirements covering Zero-Cloud Binary Parsing, Canvas Exorcism, Android Permission Chains, Secret Air-Gap, and Local MCP.'
  },
  {
    path: '.kiro/specs/phantomglass-core/design.md',
    kind: 'Architecture Spec',
    summary: 'Frankenstein 4-Organ Chimera Mermaid topology, media re-parse self-verification sequence, and strict DataView safety guarantees.'
  },
  {
    path: '.kiro/specs/binary-exorcist-engine/design.md',
    kind: 'Binary Splicer Spec',
    summary: 'Little-Endian TIFF/EXIF+GPS APP1 binary splice architecture enabling 1-click judge evaluation with real binary tags.'
  },
  {
    path: '.kiro/steering/product-and-privacy-constitution.md',
    kind: 'Steering (always)',
    summary: 'Permanent project law enforcing 0 outbound network bytes, defensive-only security scope, and Swiss-precision dark laboratory UX.'
  },
  {
    path: '.kiro/hooks/zero-leak-security-audit.json',
    kind: 'Agent Hook (v1)',
    summary: 'PostFileSave hook auditing web/src/engines/*.ts against accidental fetch/telemetry leaks and DataView bounds safety.'
  },
  {
    path: '.kiro/settings/mcp.json',
    kind: 'MCP Server Wiring',
    summary: 'Connects Kiro directly to ./mcp-server/index.mjs exposing 4 standalone zero-dependency JSON-RPC forensic tools.'
  }
];

function SeverityPill({ level }: { level: string }) {
  const styles =
    level === 'CRITICAL'
      ? 'border-red-500/40 bg-red-500/15 text-red-300'
      : level === 'HIGH'
        ? 'border-amber-500/40 bg-amber-500/15 text-amber-300'
        : level === 'MEDIUM'
          ? 'border-sky-500/40 bg-sky-500/15 text-sky-300'
          : 'border-emerald-500/40 bg-emerald-500/15 text-emerald-300';
  return (
    <span className={`inline-flex items-center rounded border px-2 py-0.5 font-mono text-[11px] font-medium ${styles}`}>
      {level}
    </span>
  );
}

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('exorcist');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Organ 1 & 2: Binary EXIF Exorcist state
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [rawBuffer, setRawBuffer] = useState<ArrayBuffer | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [forensicReport, setForensicReport] = useState<BinaryForensicReport | null>(null);
  const [exorcismResult, setExorcismResult] = useState<ExorcismResult | null>(null);
  const [exorcising, setExorcising] = useState(false);

  // Organ 3: Android Permission Blast-Radius state
  const [manifestInput, setManifestInput] = useState<string>(MANIFEST_PRESETS[0].xml);
  const permissionReport = useMemo(() => auditManifestPermissions(manifestInput), [manifestInput]);

  // Organ 4: Secret Air-Gap Redactor state
  const [secretInput, setSecretInput] = useState<string>(SECRET_SCENARIOS[0].content);
  const secretReport = useMemo(() => runAirGapRedaction(secretInput), [secretInput]);

  // MCP interactive preview state
  const [selectedMcpTool, setSelectedMcpTool] = useState<string>('audit_android_permissions');

  const copyText = (text: string, id: string) => {
    navigator.clipboard?.writeText(text).catch(() => {});
    setCopiedId(id);
    setTimeout(() => setCopiedId((curr) => (curr === id ? null : curr)), 1800);
  };

  const handleFileUpload = async (file: File) => {
    const buffer = await file.arrayBuffer();
    const url = URL.createObjectURL(file);
    const report = parseImageForensics(buffer, file.name, file.type || 'image/jpeg');
    setRawBuffer(buffer);
    setPreviewUrl(url);
    setForensicReport(report);
    setExorcismResult(null);
  };

  const handleLoadSpecimen = async (presetIndex: number) => {
    const preset = SPECIMEN_PRESETS[presetIndex];
    const specimen = await generateLiveForensicSpecimen(preset);
    setRawBuffer(specimen.buffer);
    setPreviewUrl(specimen.previewUrl);
    setForensicReport(specimen.report);
    setExorcismResult(null);
  };

  const handleExorcise = async () => {
    if (!rawBuffer || !forensicReport) return;
    setExorcising(true);
    try {
      const res = await exorciseImageFile(rawBuffer, forensicReport.fileName, forensicReport.mimeType);
      setExorcismResult(res);
    } finally {
      setExorcising(false);
    }
  };

  const mcpPreviewPayload = useMemo(() => {
    if (selectedMcpTool === 'audit_android_permissions') {
      return JSON.stringify(
        {
          tool: 'audit_android_permissions',
          packageName: permissionReport.packageName,
          blastRadiusScore: permissionReport.blastRadiusScore,
          riskLevel: permissionReport.riskLevel,
          detectedChains: permissionReport.chains.map((c) => c.title),
          cloudBytesSent: 0
        },
        null,
        2
      );
    }
    if (selectedMcpTool === 'scan_text_secrets') {
      return JSON.stringify(
        {
          tool: 'scan_text_secrets',
          totalSecretsBlocked: secretReport.totalSecretsBlocked,
          entropyAnomalies: secretReport.entropyAnomalies,
          blockedTypes: secretReport.findings.map((f) => f.type),
          cloudBytesSent: 0
        },
        null,
        2
      );
    }
    return JSON.stringify(
      {
        tool: 'inspect_image_exif_bytes',
        fileName: forensicReport?.fileName ?? 'Load a specimen in Tab 1',
        format: forensicReport?.format ?? 'JPEG',
        tagsFound: forensicReport?.tags.length ?? 0,
        trailingBytes: forensicReport?.trailingBytes ?? 0,
        cloudBytesSent: 0
      },
      null,
      2
    );
  }, [selectedMcpTool, permissionReport, secretReport, forensicReport]);

  return (
    <div className="min-h-screen grid-lab-bg text-slate-100">
      {/* Top Telemetry Bar */}
      <header className="sticky top-0 z-30 border-b border-slate-800/90 bg-[#070B14]/90 backdrop-blur-md">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-4 py-3 sm:px-6">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-emerald-500/40 bg-emerald-500/10 text-emerald-400">
              <Shield className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="font-display text-lg font-bold tracking-tight text-white">
                  PhantomGlass
                </h1>
                <span className="rounded border border-slate-700 bg-slate-800/80 px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider text-slate-300">
                  Kiroween 2026 // Frankenstein
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Zero-Trust Permission, Binary EXIF &amp; Secret Exorcist — 100% Local RAM
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
            <div className="flex items-center gap-1.5 rounded-md border border-emerald-500/35 bg-emerald-500/10 px-2.5 py-1.5 text-emerald-300">
              <WifiOff className="h-3.5 w-3.5" />
              <span>CLOUD EGRESS: 0 BYTES</span>
            </div>
            <div className="hidden items-center gap-1.5 rounded-md border border-slate-700/80 bg-slate-900/90 px-2.5 py-1.5 text-slate-300 sm:flex">
              <Cpu className="h-3.5 w-3.5 text-sky-400" />
              <span>4-ORGAN LOCAL CHIMERA</span>
            </div>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl px-4 py-6 sm:px-6">
        {/* Hero Context Banner */}
        <section className="glass-panel mb-6 rounded-2xl p-5 sm:p-6">
          <div className="grid gap-5 lg:grid-cols-12 lg:items-center">
            <div className="lg:col-span-8">
              <div className="mb-2 inline-flex items-center gap-2 rounded-full border border-red-500/30 bg-red-500/10 px-3 py-1 font-mono text-[11px] text-red-300">
                <Radio className="h-3.5 w-3.5" />
                DEFENSIVE COUNTER-ARCHITECTURE TO SILENT GALLERY &amp; PERMISSION HARVESTING
              </div>
              <h2 className="font-display text-2xl font-bold tracking-tight text-white sm:text-3xl">
                Stop Silent Camera-Roll, Permission &amp; Secret Leaks Before a Single Byte Leaves Your Device
              </h2>
              <p className="mt-2 max-w-3xl text-sm leading-relaxed text-slate-300">
                Ordinary smartphone apps no longer need root exploits to harvest private photos, GPS coordinates,
                and credentials—a single blanket Gallery or Mic permission is enough. PhantomGlass stitches four
                independent forensic engines into one offline laboratory: raw binary EXIF/GPS parsing, cryptographic
                Canvas pixel exorcism, 3D AndroidManifest blast-radius auditing, and a local MCP security server.
              </p>
            </div>
            <div className="grid grid-cols-2 gap-3 lg:col-span-4">
              <div className="rounded-xl border border-slate-800 bg-[#080D18] p-3.5">
                <div className="font-mono text-[11px] text-slate-400">OUTBOUND DATA</div>
                <div className="mt-1 font-display text-2xl font-bold tabular-nums text-emerald-400">
                  0 B
                </div>
                <div className="mt-0.5 text-[11px] text-slate-400">100% Air-Gapped RAM</div>
              </div>
              <div className="rounded-xl border border-slate-800 bg-[#080D18] p-3.5">
                <div className="font-mono text-[11px] text-slate-400">FORENSIC ORGANS</div>
                <div className="mt-1 font-display text-2xl font-bold tabular-nums text-white">
                  4 + MCP
                </div>
                <div className="mt-0.5 text-[11px] text-slate-400">Web + Node.js stdio</div>
              </div>
            </div>
          </div>
        </section>

        {/* Module Navigation */}
        <nav
          aria-label="Forensic Workbench Modules"
          className="mb-6 grid grid-cols-2 gap-2 sm:grid-cols-4"
        >
          {[
            { id: 'exorcist', label: '1. EXIF & Photo Exorcist', icon: FileImage },
            { id: 'permissions', label: '2. Permission 3D Lab', icon: ShieldAlert },
            { id: 'airgap', label: '3. Secret Air-Gap', icon: Lock },
            { id: 'kiro', label: '4. Kiro Specs & MCP', icon: FolderGit2 }
          ].map((tab) => {
            const Icon = tab.icon;
            const active = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => setActiveTab(tab.id as ActiveTab)}
                className={`flex cursor-pointer items-center justify-center gap-2 rounded-xl border px-3 py-3 text-xs font-semibold transition-all sm:text-sm ${
                  active
                    ? 'border-emerald-500/60 bg-emerald-500/15 text-emerald-200 shadow-sm'
                    : 'border-slate-800 bg-[#0D1424] text-slate-300 hover:border-slate-700 hover:text-white'
                }`}
              >
                <Icon className="h-4 w-4 shrink-0" />
                <span className="truncate">{tab.label}</span>
              </button>
            );
          })}
        </nav>

        {/* TAB 1: BINARY EXIF & PHOTO EXORCIST */}
        {activeTab === 'exorcist' && (
          <section className="grid gap-6 lg:grid-cols-12">
            {/* Left: Upload & 1-Click Judge Specimens */}
            <div className="space-y-4 lg:col-span-5">
              <div className="glass-panel rounded-2xl p-5">
                <h3 className="flex items-center gap-2 font-display text-base font-semibold text-white">
                  <Upload className="h-4 w-4 text-emerald-400" />
                  Inspect Local Photo (JPEG / PNG)
                </h3>
                <p className="mt-1 text-xs text-slate-400">
                  Files are decoded strictly via local browser DataView. Zero network upload ever occurs.
                </p>

                <input
                  ref={fileInputRef}
                  type="file"
                  accept="image/jpeg,image/png"
                  className="hidden"
                  onChange={(e) => {
                    const f = e.target.files?.[0];
                    if (f) handleFileUpload(f);
                  }}
                />
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  className="mt-4 flex w-full cursor-pointer flex-col items-center justify-center rounded-xl border border-dashed border-slate-700 bg-[#080D18] px-4 py-7 text-center transition hover:border-emerald-500/60 hover:bg-[#0B1324]"
                >
                  <FileImage className="h-7 w-7 text-slate-400" />
                  <span className="mt-2 text-sm font-medium text-slate-200">
                    Click to select a real JPEG or PNG from disk
                  </span>
                  <span className="mt-1 font-mono text-[11px] text-slate-400">
                    Parses APP1 TIFF/EXIF, GPS Rationals, PNG Chunks &amp; Post-EOI Trailers
                  </span>
                </button>

                <div className="mt-5 border-t border-slate-800 pt-4">
                  <div className="mb-2.5 flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-wider text-emerald-400">
                    <Sparkles className="h-3.5 w-3.5" />
                    1-Click Judge Binary Specimens (Real Spliced EXIF + GPS)
                  </div>
                  <div className="space-y-2">
                    {SPECIMEN_PRESETS.map((preset, idx) => (
                      <button
                        key={preset.id}
                        type="button"
                        onClick={() => handleLoadSpecimen(idx)}
                        className="w-full cursor-pointer rounded-xl border border-slate-800 bg-[#091020] p-3 text-left transition hover:border-emerald-500/50 hover:bg-[#0D172B]"
                      >
                        <div className="text-xs font-semibold text-white">{preset.label}</div>
                        <div className="mt-0.5 text-[11px] text-slate-400">{preset.subtitle}</div>
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              {previewUrl && (
                <div className="glass-panel rounded-2xl p-4">
                  <div className="mb-2 flex items-center justify-between font-mono text-[11px] text-slate-400">
                    <span>SPECIMEN PREVIEW</span>
                    <span>{forensicReport?.byteLength.toLocaleString()} BYTES</span>
                  </div>
                  <img
                    src={previewUrl}
                    alt="Loaded forensic specimen"
                    className="max-h-56 w-full rounded-lg border border-slate-800 object-contain bg-[#060A13]"
                  />
                </div>
              )}
            </div>

            {/* Right: Binary Forensic Report & Cryptographic Exorcist */}
            <div className="space-y-4 lg:col-span-7">
              {!forensicReport ? (
                <div className="glass-panel flex min-h-80 flex-col items-center justify-center rounded-2xl p-8 text-center">
                  <ShieldCheck className="h-10 w-10 text-emerald-400/80" />
                  <h3 className="mt-3 font-display text-lg font-semibold text-white">
                    Binary Microscope Standby
                  </h3>
                  <p className="mt-1 max-w-md text-sm text-slate-400">
                    Drop any photo on the left or click a 1-Click Judge Binary Specimen to splice a genuine
                    APP1 EXIF/GPS JPEG in RAM, inspect every leaked byte, and exorcise it clean.
                  </p>
                </div>
              ) : (
                <>
                  <div className="glass-panel rounded-2xl p-5">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div>
                        <div className="flex items-center gap-2">
                          <h3 className="font-display text-base font-bold text-white">
                            {forensicReport.fileName}
                          </h3>
                          <SeverityPill level={forensicReport.riskLevel} />
                        </div>
                        <p className="mt-1 font-mono text-xs text-slate-400">
                          FORMAT: {forensicReport.format} // TAGS: {forensicReport.tags.length} // TRAILING:{' '}
                          {forensicReport.trailingBytes} B // RISK: {forensicReport.riskScore}/100
                        </p>
                      </div>

                      <button
                        type="button"
                        disabled={exorcising}
                        onClick={handleExorcise}
                        className="inline-flex cursor-pointer items-center gap-2 rounded-xl bg-emerald-500 px-4 py-2.5 text-xs font-bold text-slate-950 transition hover:bg-emerald-400 disabled:opacity-50"
                      >
                        <ShieldCheck className="h-4 w-4" />
                        {exorcising ? 'EXORCISING PIXELS...' : 'EXORCISE & VERIFY CLEAN'}
                      </button>
                    </div>

                    {forensicReport.gpsCoordinates && (
                      <div className="mt-4 flex items-start gap-3 rounded-xl border border-red-500/40 bg-red-500/10 p-3.5 text-xs text-red-200">
                        <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-red-400" />
                        <div>
                          <div className="font-semibold">CRITICAL PHYSICAL LOCATION LEAK DETECTED</div>
                          <div className="mt-0.5 font-mono">
                            GPS Coordinates: {forensicReport.gpsCoordinates.lat},{' '}
                            {forensicReport.gpsCoordinates.lon} — Any app with blanket gallery access can
                            pinpoint the exact building where this photo was taken.
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Parsed Binary Tags */}
                    <div className="mt-4 space-y-2">
                      {forensicReport.tags.length === 0 ? (
                        <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-3.5 text-xs text-emerald-300">
                          Zero EXIF, GPS, PNG text chunks, or post-EOI trailing bytes detected.
                        </div>
                      ) : (
                        forensicReport.tags.map((tag) => (
                          <div
                            key={tag.id}
                            className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-800 bg-[#080D18] px-3 py-2.5 text-xs"
                          >
                            <div className="min-w-0">
                              <span className="font-mono text-[10px] text-slate-500">[{tag.group}] </span>
                              <span className="font-semibold text-slate-200">{tag.name}</span>
                              <div className="mt-0.5 break-all font-mono text-[11px] text-slate-400">
                                {tag.value}
                              </div>
                            </div>
                            <SeverityPill level={tag.severity} />
                          </div>
                        ))
                      )}
                    </div>

                    <div className="mt-4 rounded-lg border border-slate-800 bg-[#060A13] p-3">
                      <div className="font-mono text-[10px] uppercase tracking-wider text-slate-500">
                        RAW BINARY HEADER HEX PREVIEW (FIRST 48 BYTES)
                      </div>
                      <div className="mt-1 break-all font-mono text-[11px] text-sky-300/90">
                        {forensicReport.hexPreview}
                      </div>
                    </div>
                  </div>

                  {/* Independent Verification Proof after Exorcism */}
                  {exorcismResult && (
                    <div className="rounded-2xl border border-emerald-500/40 bg-emerald-500/10 p-5">
                      <div className="flex flex-wrap items-center justify-between gap-3">
                        <div className="flex items-center gap-2.5">
                          <CheckCircle2 className="h-5 w-5 text-emerald-400" />
                          <div>
                            <h4 className="font-display text-base font-bold text-emerald-200">
                              Exorcism Complete — Independently Re-Parsed &amp; Verified Clean
                            </h4>
                            <p className="font-mono text-xs text-emerald-300/90">
                              TAGS PURGED: {exorcismResult.tagsEliminated} // BYTES REMOVED:{' '}
                              {exorcismResult.bytesPurged.toLocaleString()} B // REMAINING METADATA:{' '}
                              {exorcismResult.afterReport.tags.length} TAGS, {exorcismResult.afterReport.trailingBytes} B TRAILER
                            </p>
                          </div>
                        </div>

                        <a
                          href={exorcismResult.cleanUrl}
                          download={exorcismResult.cleanFileName}
                          className="inline-flex cursor-pointer items-center gap-2 rounded-xl border border-emerald-400/50 bg-emerald-500 px-4 py-2 text-xs font-bold text-slate-950 transition hover:bg-emerald-400"
                        >
                          <Download className="h-4 w-4" />
                          Download Clean Image
                        </a>
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>
          </section>
        )}

        {/* TAB 2: ANDROID PERMISSION BLAST-RADIUS 3D LAB */}
        {activeTab === 'permissions' && (
          <section className="grid gap-6 lg:grid-cols-12">
            <div className="space-y-4 lg:col-span-5">
              <div className="glass-panel rounded-2xl p-5">
                <h3 className="flex items-center gap-2 font-display text-base font-semibold text-white">
                  <Activity className="h-4 w-4 text-emerald-400" />
                  Select Real-World App Profile or Paste AndroidManifest.xml
                </h3>
                <div className="mt-3 grid gap-2">
                  {MANIFEST_PRESETS.map((preset) => (
                    <button
                      key={preset.id}
                      type="button"
                      onClick={() => setManifestInput(preset.xml)}
                      className="flex cursor-pointer items-center justify-between rounded-xl border border-slate-800 bg-[#080D18] px-3.5 py-2.5 text-left transition hover:border-emerald-500/50"
                    >
                      <div>
                        <div className="text-xs font-semibold text-white">{preset.name}</div>
                        <div className="font-mono text-[11px] text-slate-400">{preset.packageName}</div>
                      </div>
                      <SeverityPill level={preset.badge} />
                    </button>
                  ))}
                </div>

                <label className="mt-4 block font-mono text-[11px] uppercase tracking-wider text-slate-400">
                  AndroidManifest.xml / Permission List Input
                </label>
                <textarea
                  value={manifestInput}
                  onChange={(e) => setManifestInput(e.target.value)}
                  rows={9}
                  className="mt-1.5 w-full rounded-xl border border-slate-800 bg-[#060A13] p-3 font-mono text-xs text-slate-200 focus:border-emerald-500 focus:outline-none"
                />
              </div>
            </div>

            <div className="space-y-4 lg:col-span-7">
              <div className="glass-panel rounded-2xl p-5">
                <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <div className="font-mono text-[11px] text-slate-400">
                      PACKAGE: {permissionReport.packageName}
                    </div>
                    <h3 className="font-display text-lg font-bold text-white">
                      Silent Exfiltration Blast-Radius Score:{' '}
                      <span
                        className={
                          permissionReport.blastRadiusScore >= 70
                            ? 'text-red-400'
                            : permissionReport.blastRadiusScore >= 30
                              ? 'text-amber-400'
                              : 'text-emerald-400'
                        }
                      >
                        {permissionReport.blastRadiusScore}/100
                      </span>
                    </h3>
                  </div>
                  <SeverityPill level={permissionReport.riskLevel} />
                </div>

                <ThreatTopology3D
                  nodes={permissionReport.nodes}
                  blastRadiusScore={permissionReport.blastRadiusScore}
                />

                {/* Detected Permission Chains */}
                <div className="mt-5 space-y-3">
                  <div className="font-mono text-xs uppercase tracking-wider text-slate-400">
                    DETECTED SILENT HARVESTING CHAINS ({permissionReport.chains.length})
                  </div>
                  {permissionReport.chains.length === 0 ? (
                    <div className="rounded-xl border border-emerald-500/35 bg-emerald-500/10 p-4 text-xs text-emerald-300">
                      Zero dangerous background harvesting chains detected. This permission manifest obeys
                      least-privilege containment.
                    </div>
                  ) : (
                    permissionReport.chains.map((chain) => (
                      <div
                        key={chain.id}
                        className="rounded-xl border border-slate-800 bg-[#080D18] p-4"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <h4 className="font-display text-sm font-bold text-white">{chain.title}</h4>
                          <SeverityPill level={chain.severity} />
                        </div>
                        <p className="mt-1.5 text-xs leading-relaxed text-slate-300">{chain.mechanism}</p>
                        <div className="mt-2 rounded-lg border border-amber-500/25 bg-amber-500/5 px-3 py-2 text-[11px] text-amber-200/90">
                          <strong>Real-World Precedent:</strong> {chain.realWorldPrecedent}
                        </div>
                        <div className="mt-2.5 flex flex-wrap gap-1.5">
                          {chain.matchedPermissions.map((p) => (
                            <span
                              key={p}
                              className="rounded bg-slate-900 px-2 py-0.5 font-mono text-[10px] text-red-300 border border-red-500/25"
                            >
                              {p}
                            </span>
                          ))}
                        </div>
                        {chain.adbRevokeCommands.length > 0 && (
                          <div className="mt-3 rounded-lg border border-slate-800 bg-[#050810] p-2.5">
                            <div className="mb-1 flex items-center justify-between font-mono text-[10px] text-slate-400">
                              <span>READY-TO-RUN ADB REVOCATION COMMANDS</span>
                              <button
                                type="button"
                                onClick={() => copyText(chain.adbRevokeCommands.join('\n'), chain.id)}
                                className="inline-flex cursor-pointer items-center gap-1 text-emerald-400 hover:text-emerald-300"
                              >
                                <Copy className="h-3 w-3" />
                                {copiedId === chain.id ? 'COPIED' : 'COPY'}
                              </button>
                            </div>
                            <pre className="overflow-x-auto font-mono text-[11px] text-emerald-300">
                              {chain.adbRevokeCommands.join('\n')}
                            </pre>
                          </div>
                        )}
                      </div>
                    ))
                  )}
                </div>

                {/* Hardening Steps */}
                <div className="mt-4 rounded-xl border border-slate-800 bg-[#080D18] p-4">
                  <div className="mb-2 font-mono text-[11px] uppercase tracking-wider text-emerald-400">
                    ACTIONABLE ZERO-TRUST HARDENING CHECKLIST
                  </div>
                  <ul className="space-y-1.5 text-xs text-slate-300">
                    {permissionReport.hardeningSteps.map((step, i) => (
                      <li key={i} className="flex items-start gap-2">
                        <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-400" />
                        <span>{step}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          </section>
        )}

        {/* TAB 3: ZERO-LEAK SECRET AIR-GAP REDACTOR */}
        {activeTab === 'airgap' && (
          <section className="grid gap-6 lg:grid-cols-12">
            <div className="space-y-4 lg:col-span-6">
              <div className="glass-panel rounded-2xl p-5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <h3 className="flex items-center gap-2 font-display text-base font-semibold text-white">
                    <Lock className="h-4 w-4 text-emerald-400" />
                    Raw Sensitive Input (Never Leaves Local RAM)
                  </h3>
                  <span className="font-mono text-[11px] text-emerald-400">0 BYTES TRANSMITTED</span>
                </div>
                <div className="mt-3 flex flex-wrap gap-2">
                  {SECRET_SCENARIOS.map((sc) => (
                    <button
                      key={sc.id}
                      type="button"
                      onClick={() => setSecretInput(sc.content)}
                      className="cursor-pointer rounded-lg border border-slate-800 bg-[#080D18] px-3 py-1.5 text-xs font-medium text-slate-300 transition hover:border-emerald-500/50 hover:text-white"
                    >
                      {sc.title}
                    </button>
                  ))}
                </div>
                <textarea
                  value={secretInput}
                  onChange={(e) => setSecretInput(e.target.value)}
                  rows={12}
                  className="mt-3 w-full rounded-xl border border-slate-800 bg-[#060A13] p-3.5 font-mono text-xs text-slate-200 focus:border-emerald-500 focus:outline-none"
                />
              </div>
            </div>

            <div className="space-y-4 lg:col-span-6">
              <div className="glass-panel rounded-2xl p-5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <h3 className="font-display text-base font-semibold text-white">
                    Air-Gapped Safe Output ({secretReport.totalSecretsBlocked} Secrets Blocked)
                  </h3>
                  <button
                    type="button"
                    onClick={() => copyText(secretReport.redactedText, 'redacted-out')}
                    className="inline-flex cursor-pointer items-center gap-1.5 rounded-lg border border-emerald-500/40 bg-emerald-500/15 px-3 py-1.5 font-mono text-xs text-emerald-300 hover:bg-emerald-500/25"
                  >
                    <Copy className="h-3.5 w-3.5" />
                    {copiedId === 'redacted-out' ? 'COPIED SAFE TEXT' : 'COPY SAFE TEXT'}
                  </button>
                </div>

                <pre className="mt-3 max-h-64 overflow-auto whitespace-pre-wrap rounded-xl border border-emerald-500/25 bg-[#060A13] p-3.5 font-mono text-xs text-emerald-200">
                  {secretReport.redactedText}
                </pre>

                <div className="mt-4 space-y-2">
                  <div className="font-mono text-[11px] uppercase tracking-wider text-slate-400">
                    INTERCEPTED SECRETS &amp; SHANNON ENTROPY ANOMALIES ({secretReport.entropyAnomalies})
                  </div>
                  <div className="max-h-48 space-y-1.5 overflow-y-auto pr-1">
                    {secretReport.findings.map((f) => (
                      <div
                        key={f.id}
                        className="flex items-center justify-between rounded-lg border border-slate-800 bg-[#080D18] px-3 py-2 font-mono text-[11px]"
                      >
                        <div className="truncate text-slate-200">
                          {f.placeholder}
                          {f.entropy ? (
                            <span className="ml-2 text-amber-300">H={f.entropy} bits/char</span>
                          ) : null}
                        </div>
                        <SeverityPill level={f.severity} />
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </section>
        )}

        {/* TAB 4: KIRO SPEC-DRIVEN ARCHITECTURE & LIVE MCP INSPECTOR */}
        {activeTab === 'kiro' && (
          <section className="grid gap-6 lg:grid-cols-12">
            <div className="space-y-4 lg:col-span-6">
              <div className="glass-panel rounded-2xl p-5">
                <h3 className="flex items-center gap-2 font-display text-base font-semibold text-white">
                  <FileCode2 className="h-4 w-4 text-emerald-400" />
                  Tracked .kiro/ Spec-Driven Development Architecture
                </h3>
                <p className="mt-1 text-xs text-slate-400">
                  Every requirement, design diagram, hook, steering rule, and MCP configuration is committed
                  directly in the repository root under .kiro/ for full judge verification.
                </p>

                <div className="mt-4 space-y-2.5">
                  {KIRO_ARTIFACTS.map((item) => (
                    <div
                      key={item.path}
                      className="rounded-xl border border-slate-800 bg-[#080D18] p-3.5"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="font-mono text-xs font-semibold text-emerald-300">
                          {item.path}
                        </span>
                        <span className="rounded border border-slate-700 bg-slate-900 px-2 py-0.5 font-mono text-[10px] text-slate-300">
                          {item.kind}
                        </span>
                      </div>
                      <p className="mt-1.5 text-xs text-slate-400">{item.summary}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="space-y-4 lg:col-span-6">
              <div className="glass-panel rounded-2xl p-5">
                <h3 className="flex items-center gap-2 font-display text-base font-semibold text-white">
                  <Terminal className="h-4 w-4 text-emerald-400" />
                  Live Standalone MCP Server Inspector (./mcp-server/index.mjs)
                </h3>
                <p className="mt-1 text-xs text-slate-400">
                  Zero-dependency Node.js stdio JSON-RPC 2.0 MCP server wired via .kiro/settings/mcp.json.
                  Preview live structured output from the active workbench engines below:
                </p>

                <div className="mt-3 flex flex-wrap gap-2">
                  {[
                    'audit_android_permissions',
                    'scan_text_secrets',
                    'inspect_image_exif_bytes'
                  ].map((tool) => (
                    <button
                      key={tool}
                      type="button"
                      onClick={() => setSelectedMcpTool(tool)}
                      className={`cursor-pointer rounded-lg border px-3 py-1.5 font-mono text-[11px] transition ${
                        selectedMcpTool === tool
                          ? 'border-emerald-500/60 bg-emerald-500/15 text-emerald-200'
                          : 'border-slate-800 bg-[#080D18] text-slate-300 hover:border-slate-700'
                      }`}
                    >
                      {tool}
                    </button>
                  ))}
                </div>

                <pre className="mt-3 overflow-x-auto rounded-xl border border-slate-800 bg-[#060A13] p-4 font-mono text-xs text-sky-300">
                  {mcpPreviewPayload}
                </pre>

                <div className="mt-4 rounded-xl border border-slate-800 bg-[#080D18] p-3.5">
                  <div className="font-mono text-[11px] uppercase tracking-wider text-slate-400">
                    KIRO CLI / IDE QUICK LAUNCH
                  </div>
                  <pre className="mt-1.5 overflow-x-auto font-mono text-xs text-emerald-300">
{`# Run automated MCP & forensic engine test suite
node --test tests/forensic-engines.test.mjs

# Connect directly as a local Kiro MCP server
node ./mcp-server/index.mjs`}
                  </pre>
                </div>
              </div>
            </div>
          </section>
        )}
      </main>

      <footer className="mt-10 border-t border-slate-800/80 py-6 text-center text-xs text-slate-400">
        <div className="mx-auto max-w-7xl px-4">
          PhantomGlass // Built by HM Shihabuddin Jashory (@jashory) for Kiroween 2026 (Frankenstein Track) — 100% Zero-Cloud Defensive Security Architecture
        </div>
      </footer>
    </div>
  );
}
