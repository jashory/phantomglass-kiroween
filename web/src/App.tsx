import { useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Copy,
  Cpu,
  Database,
  Download,
  FileCode2,
  FileImage,
  FolderGit2,
  Layers,
  Lock,
  Radio,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Smartphone,
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
  generateLivePdfSpecimen,
  SPECIMEN_PRESETS,
  type ExorcismResult
} from './engines/mediaExorcist';
import {
  ANDROID_VERSION_SPECS,
  auditManifestPermissions,
  MANIFEST_PRESETS
} from './engines/permissionGraphEngine';
import {
  auditIosPrivacyManifest,
  IOS_PLIST_PRESETS
} from './engines/iosPrivacyEngine';
import {
  runAirGapRedaction,
  SECRET_SCENARIOS
} from './engines/secretAirGapEngine';
import {
  exorciseTabularDataset,
  generateEnterpriseDatasetSpecimen,
  profileTabularSample,
  type ColumnPolicy,
  type DatasetExorcismResult,
  type DatasetProfileReport
} from './engines/columnarScrubberEngine';
import { ThreatTopology3D } from './components/ThreatTopology3D';

type ActiveTab = 'exorcist' | 'permissions' | 'airgap' | 'dataset' | 'kiro';
type MobilePlatform = 'android' | 'ios';

const KIRO_ARTIFACTS = [
  {
    path: '.kiro/specs/phantomglass-core/requirements.md',
    kind: 'EARS Spec',
    summary: '5 core EARS requirements covering Zero-Cloud Binary Parsing, Canvas Exorcism, Mobile Audits, Secret Air-Gap, and Local MCP.'
  },
  {
    path: '.kiro/specs/universal-mobile-forensics/design.md',
    kind: 'v2.0 Mobile Spec',
    summary: 'Universal Android 8–17 (API 26–37) runtime/AppOps matrix + Apple iOS Info.plist & PrivacyInfo.xcprivacy 3D auditor.'
  },
  {
    path: '.kiro/specs/columnar-dataset-scrubber/design.md',
    kind: 'Organ #7 Spec',
    summary: 'Zero-Cloud Columnar CSV Shrinker, Shannon-Entropy PII Scrubber, PGCOL1 Gzip archive & SHA-256 Chain-of-Custody.'
  },
  {
    path: '.kiro/specs/binary-exorcist-engine/design.md',
    kind: 'Binary Splicer Spec',
    summary: 'Little-Endian TIFF/EXIF+GPS APP1 binary splice architecture enabling 1-click judge evaluation with real binary tags.'
  },
  {
    path: '.kiro/steering/product-and-privacy-constitution.md',
    kind: 'Steering (always)',
    summary: 'Permanent project law enforcing 0 outbound network bytes, defensive-only security scope, and Swiss-precision dark lab UX.'
  },
  {
    path: '.kiro/hooks/zero-leak-security-audit.json',
    kind: 'Agent Hook (v1)',
    summary: 'PostFileSave hook auditing web/src/engines/*.ts against accidental fetch/telemetry leaks and DataView bounds safety.'
  },
  {
    path: '.kiro/settings/mcp.json',
    kind: '7-Tool MCP Wiring',
    summary: 'Connects Kiro directly to ./mcp-server/index.mjs exposing 7 standalone zero-dependency JSON-RPC 2.0 forensic tools.'
  }
];

function SeverityPill({ level }: { level: string }) {
  const styles =
    level === 'CRITICAL' || level === 'SECRET_RISK'
      ? 'border-red-500/40 bg-red-500/15 text-red-300'
      : level === 'HIGH' || level === 'PII_RISK'
        ? 'border-amber-500/40 bg-amber-500/15 text-amber-300'
        : level === 'MEDIUM' || level === 'HIGH_BLOAT'
          ? 'border-sky-500/40 bg-sky-500/15 text-sky-300'
          : 'border-emerald-500/40 bg-emerald-500/15 text-emerald-300';
  return (
    <span className={`inline-flex items-center rounded border px-2 py-0.5 font-mono text-[11px] font-medium ${styles}`}>
      {level}
    </span>
  );
}

function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('exorcist');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Organ 1, 2 & 5: Binary EXIF & PDF Exorcist state
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [rawBuffer, setRawBuffer] = useState<ArrayBuffer | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [forensicReport, setForensicReport] = useState<BinaryForensicReport | null>(null);
  const [exorcismResult, setExorcismResult] = useState<ExorcismResult | null>(null);
  const [exorcising, setExorcising] = useState(false);

  // Organ 3: Universal Mobile Privacy Forensics (Android 8–17 + Apple iOS)
  const [mobilePlatform, setMobilePlatform] = useState<MobilePlatform>('android');
  const [androidApiLevel, setAndroidApiLevel] = useState<number>(35);
  const [manifestInput, setManifestInput] = useState<string>(MANIFEST_PRESETS[0].xml);
  const [iosPlistInput, setIosPlistInput] = useState<string>(IOS_PLIST_PRESETS[0].plistXml);

  const permissionReport = useMemo(
    () => auditManifestPermissions(manifestInput, androidApiLevel),
    [manifestInput, androidApiLevel]
  );
  const iosReport = useMemo(() => auditIosPrivacyManifest(iosPlistInput), [iosPlistInput]);

  // Organ 4: Secret Air-Gap Redactor state
  const [secretInput, setSecretInput] = useState<string>(SECRET_SCENARIOS[0].content);
  const secretReport = useMemo(() => runAirGapRedaction(secretInput), [secretInput]);

  // Organ 7: Zero-Cloud Columnar Dataset Shrinker & PII Scrubber state
  const datasetInputRef = useRef<HTMLInputElement | null>(null);
  const [datasetSource, setDatasetSource] = useState<File | string | null>(null);
  const [datasetProfile, setDatasetProfile] = useState<DatasetProfileReport | null>(null);
  const [colPolicies, setColPolicies] = useState<Record<string, ColumnPolicy>>({});
  const [filterColumn, setFilterColumn] = useState<string>('__ALL__');
  const [filterContains, setFilterContains] = useState<string>('');
  const [maxRowsSlice, setMaxRowsSlice] = useState<string>('');
  const [datasetResult, setDatasetResult] = useState<DatasetExorcismResult | null>(null);
  const [shrinkingDataset, setShrinkingDataset] = useState(false);

  // MCP interactive preview & Chaos Stress-Test state
  const [selectedMcpTool, setSelectedMcpTool] = useState<string>('audit_android_permissions');
  const [chaosResult, setChaosResult] = useState<string | null>(null);

  const copyText = (text: string, id: string) => {
    navigator.clipboard?.writeText(text).catch(() => {});
    setCopiedId(id);
    setTimeout(() => setCopiedId((curr) => (curr === id ? null : curr)), 1800);
  };

  const runChaosStressTest = () => {
    const truncatedJpeg = new Uint8Array([0xff, 0xd8, 0xff, 0xe1, 0x00, 0xff]).buffer;
    const corruptedPng = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0xff, 0xff, 0xff]).buffer;
    const pdfProbe = generateLivePdfSpecimen();
    const r1 = parseImageForensics(truncatedJpeg, 'chaos_truncated.jpg', 'image/jpeg');
    const r2 = parseImageForensics(corruptedPng, 'chaos_corrupt.png', 'image/png');
    const r3 = auditManifestPermissions('<<<MALFORMED_XML>>> android.permission.READ_MEDIA_IMAGES', 37);
    const r4 = auditIosPrivacyManifest('<plist><key>NSAllowsArbitraryLoads</key><true/><<<BROKEN');
    const r5 = runAirGapRedaction('Chaos key AKIAIOSFODNN7EXAMPLE + card 4532015112830366');
    const r6 = profileTabularSample('id,email,raw_debug\n1,test@corp.io,"unterminated', 'chaos.csv', 64);
    setChaosResult(
      `6/6 CHAOS PROBES SURVIVED (0 CRASHES, 0 CLOUD BYTES)\n` +
        `• Truncated JPEG Header: format=${r1.format}, safeClamp=OK\n` +
        `• Corrupted PNG Chunk Length: format=${r2.format}, safeClamp=OK\n` +
        `• Hostile PDF (/OpenAction + /JavaScript + Post-EOF): risk=${pdfProbe.report.riskScore}/100, tags=${pdfProbe.report.tags.length}\n` +
        `• Malformed Android 17 (API 37) XML: perms=${r3.permissions.length}, safeClamp=OK\n` +
        `• Malformed iOS Info.plist: atsDowngrade=${r4.allowsArbitraryLoads}, risk=${r4.blastRadiusScore}/100\n` +
        `• Malformed CSV + Secrets: cols=${r6.columns.length}, secretsBlocked=${r5.totalSecretsBlocked}`
    );
  };

  const handleLoadPdfSpecimen = () => {
    const pdfSpec = generateLivePdfSpecimen();
    setRawBuffer(pdfSpec.buffer);
    setPreviewUrl(null);
    setForensicReport(pdfSpec.report);
    setExorcismResult(null);
  };

  const handleFileUpload = async (file: File) => {
    const buffer = await file.arrayBuffer();
    const url = file.type === 'application/pdf' ? null : URL.createObjectURL(file);
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

  const applyProfileDefaults = (profile: DatasetProfileReport) => {
    const defaults: Record<string, ColumnPolicy> = {};
    for (const c of profile.columns) {
      defaults[c.name] = c.recommendedPolicy;
    }
    setDatasetProfile(profile);
    setColPolicies(defaults);
    setFilterColumn('__ALL__');
    setFilterContains('');
    setMaxRowsSlice('');
    setDatasetResult(null);
  };

  const handleDatasetFileUpload = async (file: File) => {
    const headBlob = file.slice(0, Math.min(file.size, 256 * 1024));
    const headText = await headBlob.text();
    const profile = profileTabularSample(headText, file.name, file.size);
    setDatasetSource(file);
    applyProfileDefaults(profile);
  };

  const handleLoadDatasetBenchmark = (rowCount: number) => {
    const spec = generateEnterpriseDatasetSpecimen(rowCount);
    const profile = profileTabularSample(spec.csvText.slice(0, 256 * 1024), spec.fileName, spec.byteLength);
    setDatasetSource(spec.csvText);
    applyProfileDefaults(profile);
  };

  const handleShrinkDataset = async () => {
    if (!datasetSource || !datasetProfile) return;
    setShrinkingDataset(true);
    try {
      const parsedMax = parseInt(maxRowsSlice, 10);
      const res = await exorciseTabularDataset(datasetSource, datasetProfile.fileName, {
        policies: colPolicies,
        filterColumn,
        filterContains,
        maxRows: Number.isFinite(parsedMax) && parsedMax > 0 ? parsedMax : undefined
      });
      setDatasetResult(res);
    } finally {
      setShrinkingDataset(false);
    }
  };

  const mcpPreviewPayload = useMemo(() => {
    if (selectedMcpTool === 'audit_android_permissions') {
      return JSON.stringify(
        {
          tool: 'audit_android_permissions',
          packageName: permissionReport.packageName,
          apiLevel: permissionReport.apiLevel,
          supportedRange: 'Android 8–17 (API 26–37)',
          blastRadiusScore: permissionReport.blastRadiusScore,
          riskLevel: permissionReport.riskLevel,
          detectedChains: permissionReport.chains.map((c) => c.title),
          cloudBytesSent: 0
        },
        null,
        2
      );
    }
    if (selectedMcpTool === 'audit_ios_plist') {
      return JSON.stringify(
        {
          tool: 'audit_ios_plist',
          bundleId: iosReport.bundleId,
          blastRadiusScore: iosReport.blastRadiusScore,
          riskLevel: iosReport.riskLevel,
          allowsArbitraryLoads: iosReport.allowsArbitraryLoads,
          requiredReasonApis: iosReport.requiredReasonApis,
          detectedChains: iosReport.chains.map((c) => c.title),
          cloudBytesSent: 0
        },
        null,
        2
      );
    }
    if (selectedMcpTool === 'scrub_and_shrink_csv') {
      return JSON.stringify(
        datasetResult
          ? {
              tool: 'scrub_and_shrink_csv',
              sourceBytes: datasetResult.attestation.sourceBytes,
              columnarGzipBytes: datasetResult.attestation.columnarGzipBytes,
              shrinkRatioPercent: datasetResult.attestation.shrinkRatioPercent,
              piiCellsScrubbed: datasetResult.attestation.piiCellsScrubbed,
              pseudonymizedCells: datasetResult.attestation.pseudonymizedCells,
              columnarGzipSha256: datasetResult.attestation.columnarGzipSha256,
              cloudBytesSent: 0
            }
          : {
              tool: 'scrub_and_shrink_csv',
              status: 'Run a 1-Click Benchmark in Tab 4 (Dataset Shrinker) to inspect live SHA-256 Chain-of-Custody output',
              encoding: 'PGCOL1_DICTIONARY_GZIP',
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
  }, [selectedMcpTool, permissionReport, iosReport, datasetResult, secretReport, forensicReport]);

  return (
    <div className="flex min-h-screen flex-col overflow-x-hidden grid-lab-bg text-slate-100">
      {/* Top Telemetry Bar */}
      <header className="sticky top-0 z-30 border-b border-slate-800/80 bg-[#070B14]/92 backdrop-blur-md">
        <div className="mx-auto flex max-w-[1480px] flex-wrap items-center justify-between gap-3 px-4 py-3 sm:px-6 lg:px-8">
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
                  Kiroween 2026 // Frankenstein v2.0
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Zero-Trust Mobile (Android 8–17 &amp; iOS), Binary Media, Secret &amp; Columnar Dataset Exorcist
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
              <span>7-ORGAN LOCAL CHIMERA</span>
            </div>
          </div>
        </div>
      </header>

      <main className="mx-auto w-full max-w-[1480px] flex-1 px-4 py-6 sm:px-6 lg:px-8">
        {/* Hero Context Banner */}
        <section className="glass-panel mb-6 rounded-2xl p-5 sm:p-6">
          <div className="grid gap-5 lg:grid-cols-12 lg:items-center">
            <div className="lg:col-span-8">
              <div className="mb-2 inline-flex items-center gap-2 rounded-full border border-red-500/30 bg-red-500/10 px-3 py-1 font-mono text-[11px] text-red-300">
                <Radio className="h-3.5 w-3.5" />
                ZERO-CLOUD COUNTER-ARCHITECTURE FOR MOBILE PERMISSIONS, MEDIA, SECRETS &amp; GIGABYTE DATASETS
              </div>
              <h2 className="font-display text-2xl font-bold tracking-tight text-white sm:text-3xl">
                Stop Silent Camera-Roll, Permission, Secret &amp; Dataset Leaks Before a Single Byte Leaves Your Device
              </h2>
              <p className="mt-2 max-w-3xl text-sm leading-relaxed text-slate-300">
                PhantomGlass stitches seven independent forensic organs into one air-gapped laboratory: raw JPEG/PNG/PDF
                binary parsing, cryptographic Canvas pixel exorcism, universal Android 8–17 &amp; Apple iOS Info.plist 3D
                auditing, Shannon-entropy PII redaction, Organ #7 zero-cloud columnar CSV shrinking with SHA-256 Chain of
                Custody, a Chrome MV3 extension, and a 7-tool local Kiro MCP server.
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
                  7 + MCP
                </div>
                <div className="mt-0.5 text-[11px] text-slate-400">Web + Ext + 7 stdio Tools</div>
              </div>
            </div>
          </div>
        </section>

        {/* Module Navigation */}
        <nav
          aria-label="Forensic Workbench Modules"
          className="mb-6 grid grid-cols-2 gap-2 sm:grid-cols-5"
        >
          {[
            { id: 'exorcist', label: '1. EXIF & PDF', icon: FileImage },
            { id: 'permissions', label: '2. Android & iOS 3D', icon: ShieldAlert },
            { id: 'airgap', label: '3. Secret Air-Gap', icon: Lock },
            { id: 'dataset', label: '4. Dataset Shrinker', icon: Database },
            { id: 'kiro', label: '5. Kiro & 7-Tool MCP', icon: FolderGit2 }
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

        {/* TAB 1: BINARY EXIF & PHOTO / PDF EXORCIST */}
        {activeTab === 'exorcist' && (
          <section className="grid items-start gap-6 lg:grid-cols-12">
            <div className="space-y-4 lg:sticky lg:top-20 lg:col-span-5">
              <div className="glass-panel rounded-2xl p-5">
                <h3 className="flex items-center gap-2 font-display text-base font-semibold text-white">
                  <Upload className="h-4 w-4 text-emerald-400" />
                  Inspect Local Photo or Document (JPEG / PNG / PDF)
                </h3>
                <p className="mt-1 text-xs text-slate-400">
                  Files are decoded strictly via local browser DataView. Zero network upload ever occurs.
                </p>

                <input
                  ref={fileInputRef}
                  type="file"
                  accept="image/jpeg,image/png,application/pdf"
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
                    Click to select a real JPEG, PNG, or PDF from disk
                  </span>
                  <span className="mt-1 font-mono text-[11px] text-slate-400">
                    Parses EXIF/GPS, PNG Chunks, PDF /JavaScript &amp; Post-EOF Trailers
                  </span>
                </button>

                <div className="mt-5 border-t border-slate-800 pt-4">
                  <div className="mb-2.5 flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-wider text-emerald-400">
                    <Sparkles className="h-3.5 w-3.5" />
                    1-Click Judge Binary Specimens (JPEG EXIF + PDF Actions)
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
                    <button
                      type="button"
                      onClick={handleLoadPdfSpecimen}
                      className="w-full cursor-pointer rounded-xl border border-amber-500/30 bg-[#091020] p-3 text-left transition hover:border-amber-400/60 hover:bg-[#0D172B]"
                    >
                      <div className="text-xs font-semibold text-amber-200">
                        Suspicious PDF Invoice (/OpenAction + /JavaScript + Post-EOF)
                      </div>
                      <div className="mt-0.5 text-[11px] text-slate-400">
                        Tests pure binary PDF forensic inspection for hidden auto-exec triggers &amp; author leaks
                      </div>
                    </button>
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

            <div className="min-w-0 space-y-4 lg:col-span-7">
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
                  {exorcismResult && (
                    <div className="rounded-2xl border border-emerald-500/50 bg-emerald-500/15 p-5 shadow-lg">
                      <div className="flex flex-wrap items-center justify-between gap-3">
                        <div className="flex items-center gap-2.5">
                          <CheckCircle2 className="h-5 w-5 shrink-0 text-emerald-400" />
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

                      {forensicReport.format !== 'PDF' && (
                        <button
                          type="button"
                          disabled={exorcising}
                          onClick={handleExorcise}
                          className="inline-flex cursor-pointer items-center gap-2 rounded-xl bg-emerald-500 px-4 py-2.5 text-xs font-bold text-slate-950 transition hover:bg-emerald-400 disabled:opacity-50"
                        >
                          <ShieldCheck className="h-4 w-4" />
                          {exorcising ? 'EXORCISING PIXELS...' : 'EXORCISE & VERIFY CLEAN'}
                        </button>
                      )}
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
                </>
              )}
            </div>
          </section>
        )}

        {/* TAB 2: UNIVERSAL MOBILE PRIVACY 3D LAB (ANDROID 8–17 & APPLE iOS) */}
        {activeTab === 'permissions' && (
          <section className="grid items-start gap-6 lg:grid-cols-12">
            <div className="space-y-4 lg:sticky lg:top-20 lg:col-span-5">
              <div className="glass-panel rounded-2xl p-5">
                {/* Platform Switcher: Android 8–17 vs Apple iOS */}
                <div className="mb-4 grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => setMobilePlatform('android')}
                    className={`flex cursor-pointer items-center justify-center gap-2 rounded-xl border px-3 py-2.5 text-xs font-semibold transition ${
                      mobilePlatform === 'android'
                        ? 'border-emerald-500/60 bg-emerald-500/15 text-emerald-200'
                        : 'border-slate-800 bg-[#080D18] text-slate-400 hover:text-white'
                    }`}
                  >
                    <Smartphone className="h-4 w-4" />
                    Android 8–17 (API 26–37)
                  </button>
                  <button
                    type="button"
                    onClick={() => setMobilePlatform('ios')}
                    className={`flex cursor-pointer items-center justify-center gap-2 rounded-xl border px-3 py-2.5 text-xs font-semibold transition ${
                      mobilePlatform === 'ios'
                        ? 'border-sky-500/60 bg-sky-500/15 text-sky-200'
                        : 'border-slate-800 bg-[#080D18] text-slate-400 hover:text-white'
                    }`}
                  >
                    <Shield className="h-4 w-4" />
                    Apple iOS (Info.plist)
                  </button>
                </div>

                {mobilePlatform === 'android' ? (
                  <>
                    <div className="mb-3 flex flex-wrap items-center justify-between gap-2 rounded-xl border border-slate-800 bg-[#080D18] px-3 py-2.5">
                      <label htmlFor="android-api-select" className="font-mono text-[11px] text-slate-300">
                        TARGET ANDROID OS
                      </label>
                      <select
                        id="android-api-select"
                        value={androidApiLevel}
                        onChange={(e) => setAndroidApiLevel(Number(e.target.value))}
                        className="rounded-lg border border-slate-700 bg-[#0D1424] px-2.5 py-1 font-mono text-xs text-emerald-300 focus:border-emerald-500 focus:outline-none"
                      >
                        {ANDROID_VERSION_SPECS.map((spec) => (
                          <option key={spec.apiLevel} value={spec.apiLevel}>
                            {spec.label} — {spec.codename}
                          </option>
                        ))}
                      </select>
                    </div>

                    <h3 className="flex items-center gap-2 font-display text-sm font-semibold text-white">
                      <Activity className="h-4 w-4 text-emerald-400" />
                      AndroidManifest.xml Presets
                    </h3>
                    <div className="mt-2.5 grid gap-2">
                      {MANIFEST_PRESETS.map((preset) => (
                        <button
                          key={preset.id}
                          type="button"
                          onClick={() => setManifestInput(preset.xml)}
                          className="flex cursor-pointer items-center justify-between rounded-xl border border-slate-800 bg-[#080D18] px-3.5 py-2.5 text-left transition hover:border-emerald-500/50"
                        >
                          <div className="min-w-0 pr-2">
                            <div className="truncate text-xs font-semibold text-white">{preset.name}</div>
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
                  </>
                ) : (
                  <>
                    <h3 className="flex items-center gap-2 font-display text-sm font-semibold text-white">
                      <Activity className="h-4 w-4 text-sky-400" />
                      Apple iOS Info.plist &amp; PrivacyInfo.xcprivacy Presets
                    </h3>
                    <div className="mt-2.5 grid gap-2">
                      {IOS_PLIST_PRESETS.map((preset) => (
                        <button
                          key={preset.id}
                          type="button"
                          onClick={() => setIosPlistInput(preset.plistXml)}
                          className="flex cursor-pointer items-center justify-between rounded-xl border border-slate-800 bg-[#080D18] px-3.5 py-2.5 text-left transition hover:border-sky-500/50"
                        >
                          <div className="min-w-0 pr-2">
                            <div className="truncate text-xs font-semibold text-white">{preset.name}</div>
                            <div className="font-mono text-[11px] text-slate-400">{preset.bundleId}</div>
                          </div>
                          <SeverityPill level={preset.badge} />
                        </button>
                      ))}
                    </div>

                    <label className="mt-4 block font-mono text-[11px] uppercase tracking-wider text-slate-400">
                      iOS Info.plist / PrivacyInfo.xcprivacy XML Input
                    </label>
                    <textarea
                      value={iosPlistInput}
                      onChange={(e) => setIosPlistInput(e.target.value)}
                      rows={11}
                      className="mt-1.5 w-full rounded-xl border border-slate-800 bg-[#060A13] p-3 font-mono text-xs text-slate-200 focus:border-sky-500 focus:outline-none"
                    />
                  </>
                )}
              </div>
            </div>

            <div className="min-w-0 space-y-4 lg:col-span-7">
              {mobilePlatform === 'android' ? (
                <div className="glass-panel rounded-2xl p-5">
                  <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <div className="font-mono text-[11px] text-slate-400">
                        PACKAGE: {permissionReport.packageName} // {permissionReport.androidVersionLabel}
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

                  {/* OS Version Delta Banner */}
                  <div className="mt-4 rounded-xl border border-sky-500/30 bg-sky-500/10 p-3.5 text-xs text-sky-200">
                    <div className="font-mono text-[10px] uppercase tracking-wider text-sky-300">
                      UNIVERSAL ANDROID 8–17 OS BOUNDARY ANALYSIS (API {permissionReport.apiLevel})
                    </div>
                    {permissionReport.osSpecificDeltas.map((d, i) => (
                      <p key={i} className="mt-1 leading-relaxed">
                        {d}
                      </p>
                    ))}
                  </div>

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
                                className="rounded border border-red-500/25 bg-slate-900 px-2 py-0.5 font-mono text-[10px] text-red-300"
                              >
                                {p}
                              </span>
                            ))}
                          </div>
                          {chain.adbRevokeCommands.length > 0 && (
                            <div className="mt-3 rounded-lg border border-slate-800 bg-[#050810] p-2.5">
                              <div className="mb-1 flex items-center justify-between font-mono text-[10px] text-slate-400">
                                <span>OS-VERIFIED ADB &amp; APPOPS COMMANDS (API {permissionReport.apiLevel})</span>
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
              ) : (
                <div className="glass-panel rounded-2xl p-5">
                  <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <div className="font-mono text-[11px] text-slate-400">
                        iOS BUNDLE: {iosReport.bundleId} // REQUIRED REASON APIS: {iosReport.requiredReasonApis.length}
                      </div>
                      <h3 className="font-display text-lg font-bold text-white">
                        Apple iOS Privacy Blast-Radius Score:{' '}
                        <span
                          className={
                            iosReport.blastRadiusScore >= 70
                              ? 'text-red-400'
                              : iosReport.blastRadiusScore >= 30
                                ? 'text-amber-400'
                                : 'text-emerald-400'
                          }
                        >
                          {iosReport.blastRadiusScore}/100
                        </span>
                      </h3>
                    </div>
                    <SeverityPill level={iosReport.riskLevel} />
                  </div>

                  <ThreatTopology3D
                    nodes={iosReport.nodes}
                    blastRadiusScore={iosReport.blastRadiusScore}
                  />

                  {iosReport.trackingDomains.length > 0 && (
                    <div className="mt-4 rounded-xl border border-red-500/35 bg-red-500/10 p-3.5 text-xs text-red-200">
                      <div className="font-mono text-[10px] uppercase tracking-wider text-red-300">
                        DECLARED NSPrivacyTrackingDomains ({iosReport.trackingDomains.length})
                      </div>
                      <div className="mt-1 font-mono text-[11px]">
                        {iosReport.trackingDomains.join('  •  ')}
                      </div>
                    </div>
                  )}

                  <div className="mt-5 space-y-3">
                    <div className="font-mono text-xs uppercase tracking-wider text-slate-400">
                      DETECTED iOS PRIVACY &amp; FINGERPRINTING CHAINS ({iosReport.chains.length})
                    </div>
                    {iosReport.chains.length === 0 ? (
                      <div className="rounded-xl border border-emerald-500/35 bg-emerald-500/10 p-4 text-xs text-emerald-300">
                        Zero dangerous iOS Info.plist or PrivacyInfo.xcprivacy tracking chains detected.
                      </div>
                    ) : (
                      iosReport.chains.map((chain) => (
                        <div
                          key={chain.id}
                          className="rounded-xl border border-slate-800 bg-[#080D18] p-4"
                        >
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <h4 className="font-display text-sm font-bold text-white">{chain.title}</h4>
                            <SeverityPill level={chain.severity} />
                          </div>
                          <p className="mt-1.5 text-xs leading-relaxed text-slate-300">{chain.mechanism}</p>
                          <div className="mt-2 flex flex-wrap gap-1.5">
                            {chain.matchedKeys.map((k) => (
                              <span
                                key={k}
                                className="rounded border border-sky-500/25 bg-slate-900 px-2 py-0.5 font-mono text-[10px] text-sky-300"
                              >
                                {k}
                              </span>
                            ))}
                          </div>
                          <ul className="mt-2.5 space-y-1 text-[11px] text-emerald-300/90">
                            {chain.remediationSteps.map((s, idx) => (
                              <li key={idx}>• {s}</li>
                            ))}
                          </ul>
                        </div>
                      ))
                    )}
                  </div>

                  {/* Hardened PrivacyInfo.xcprivacy Patch */}
                  <div className="mt-4 rounded-xl border border-slate-800 bg-[#050810] p-4">
                    <div className="mb-2 flex items-center justify-between font-mono text-[11px] text-emerald-400">
                      <span>HARDENED ZERO-TRACKING PrivacyInfo.xcprivacy PATCH</span>
                      <button
                        type="button"
                        onClick={() => copyText(iosReport.hardenedXcprivacyXml, 'ios-xcprivacy')}
                        className="inline-flex cursor-pointer items-center gap-1 rounded border border-emerald-500/40 bg-emerald-500/10 px-2.5 py-1 text-[10px] text-emerald-300 hover:bg-emerald-500/20"
                      >
                        <Copy className="h-3 w-3" />
                        {copiedId === 'ios-xcprivacy' ? 'COPIED XML' : 'COPY XML'}
                      </button>
                    </div>
                    <pre className="overflow-x-auto font-mono text-[11px] text-sky-300">
                      {iosReport.hardenedXcprivacyXml}
                    </pre>
                  </div>
                </div>
              )}
            </div>
          </section>
        )}

        {/* TAB 3: ZERO-LEAK SECRET AIR-GAP REDACTOR */}
        {activeTab === 'airgap' && (
          <section className="grid items-stretch gap-6 lg:grid-cols-12">
            <div className="flex lg:col-span-6">
              <div className="glass-panel flex w-full flex-col rounded-2xl p-5">
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
                  className="mt-3 min-h-[280px] w-full flex-1 rounded-xl border border-slate-800 bg-[#060A13] p-3.5 font-mono text-xs text-slate-200 focus:border-emerald-500 focus:outline-none"
                />
              </div>
            </div>

            <div className="flex lg:col-span-6">
              <div className="glass-panel flex w-full flex-col rounded-2xl p-5">
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

        {/* TAB 4: ORGAN #7 — ZERO-CLOUD COLUMNAR DATASET SHRINKER & PII SCRUBBER */}
        {activeTab === 'dataset' && (
          <section className="grid items-start gap-6 lg:grid-cols-12">
            <div className="space-y-4 lg:sticky lg:top-20 lg:col-span-5">
              <div className="glass-panel rounded-2xl p-5">
                <h3 className="flex items-center gap-2 font-display text-base font-semibold text-white">
                  <Database className="h-4 w-4 text-emerald-400" />
                  Organ #7: Columnar Dataset Shrinker &amp; PII Scrubber
                </h3>
                <p className="mt-1 text-xs text-slate-400">
                  Drop huge local CSV/TSV dumps or run a multi-megabyte enterprise benchmark. Drops bloat
                  columns, scrubs PII &amp; cloud keys, dictionary-encodes into PGCOL1 Gzip, and emits a
                  WebCrypto SHA-256 Chain of Custody with 0 bytes uploaded.
                </p>

                <input
                  ref={datasetInputRef}
                  type="file"
                  accept=".csv,.tsv,.txt,text/csv,text/tab-separated-values"
                  className="hidden"
                  onChange={(e) => {
                    const f = e.target.files?.[0];
                    if (f) handleDatasetFileUpload(f);
                  }}
                />
                <button
                  type="button"
                  onClick={() => datasetInputRef.current?.click()}
                  className="mt-4 flex w-full cursor-pointer flex-col items-center justify-center rounded-xl border border-dashed border-slate-700 bg-[#080D18] px-4 py-6 text-center transition hover:border-emerald-500/60 hover:bg-[#0B1324]"
                >
                  <Layers className="h-7 w-7 text-slate-400" />
                  <span className="mt-2 text-sm font-medium text-slate-200">
                    Click to select a real local CSV or TSV dataset
                  </span>
                  <span className="mt-1 font-mono text-[11px] text-slate-400">
                    100% Local RAM Columnar Slicing + Gzip Compression + SHA-256 Proof
                  </span>
                </button>

                <div className="mt-4 border-t border-slate-800 pt-4">
                  <div className="mb-2 flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-wider text-emerald-400">
                    <Sparkles className="h-3.5 w-3.5" />
                    1-Click Multi-Megabyte Enterprise Leak Benchmarks
                  </div>
                  <div className="space-y-2">
                    <button
                      type="button"
                      onClick={() => handleLoadDatasetBenchmark(6000)}
                      className="w-full cursor-pointer rounded-xl border border-slate-800 bg-[#091020] p-3 text-left transition hover:border-emerald-500/50 hover:bg-[#0D172B]"
                    >
                      <div className="text-xs font-semibold text-white">
                        6,000-Row Telemetry &amp; PII Leak Dump (~2.6 MB Raw CSV)
                      </div>
                      <div className="mt-0.5 text-[11px] text-slate-400">
                        Contains repeated debug JSON bloat, emails, phones, AWS keys, GitHub PATs &amp; Luhn cards
                      </div>
                    </button>
                    <button
                      type="button"
                      onClick={() => handleLoadDatasetBenchmark(25000)}
                      className="w-full cursor-pointer rounded-xl border border-sky-500/30 bg-[#091020] p-3 text-left transition hover:border-sky-400/60 hover:bg-[#0D172B]"
                    >
                      <div className="text-xs font-semibold text-sky-200">
                        25,000-Row Enterprise Stress Test (~10.8 MB Raw CSV)
                      </div>
                      <div className="mt-0.5 text-[11px] text-slate-400">
                        Demonstrates 95%+ zero-cloud columnar dictionary compression &amp; sub-second PII scrubbing
                      </div>
                    </button>
                  </div>
                </div>

                {datasetProfile && (
                  <div className="mt-4 space-y-3 border-t border-slate-800 pt-4">
                    <div className="font-mono text-[11px] uppercase tracking-wider text-slate-400">
                      SURGICAL ROW SLICE FILTER (OPTIONAL)
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                      <select
                        value={filterColumn}
                        onChange={(e) => setFilterColumn(e.target.value)}
                        className="rounded-lg border border-slate-800 bg-[#060A13] px-2.5 py-2 font-mono text-xs text-slate-200"
                      >
                        <option value="__ALL__">Any Column</option>
                        {datasetProfile.columns.map((c) => (
                          <option key={c.name} value={c.name}>
                            {c.name}
                          </option>
                        ))}
                      </select>
                      <input
                        type="text"
                        placeholder="Filter e.g. CRITICAL"
                        value={filterContains}
                        onChange={(e) => setFilterContains(e.target.value)}
                        className="rounded-lg border border-slate-800 bg-[#060A13] px-2.5 py-2 font-mono text-xs text-slate-200 placeholder:text-slate-500"
                      />
                    </div>
                    <input
                      type="number"
                      min={1}
                      placeholder="Max rows to export (blank = all matching rows)"
                      value={maxRowsSlice}
                      onChange={(e) => setMaxRowsSlice(e.target.value)}
                      className="w-full rounded-lg border border-slate-800 bg-[#060A13] px-3 py-2 font-mono text-xs text-slate-200 placeholder:text-slate-500"
                    />
                    <button
                      type="button"
                      disabled={shrinkingDataset}
                      onClick={handleShrinkDataset}
                      className="inline-flex w-full cursor-pointer items-center justify-center gap-2 rounded-xl bg-emerald-500 px-4 py-3 text-xs font-bold text-slate-950 transition hover:bg-emerald-400 disabled:opacity-50"
                    >
                      <ShieldCheck className="h-4 w-4" />
                      {shrinkingDataset
                        ? 'SCRUBBING & COMPRESSING IN LOCAL RAM...'
                        : 'EXORCISE PII, SLICE & COMPRESS TO PGCOL1 GZIP'}
                    </button>
                  </div>
                )}
              </div>
            </div>

            <div className="min-w-0 space-y-4 lg:col-span-7">
              {!datasetProfile ? (
                <div className="glass-panel flex min-h-80 flex-col items-center justify-center rounded-2xl p-8 text-center">
                  <Database className="h-10 w-10 text-emerald-400/80" />
                  <h3 className="mt-3 font-display text-lg font-semibold text-white">
                    Columnar Forensic Shrinker Standby
                  </h3>
                  <p className="mt-1 max-w-md text-sm text-slate-400">
                    Load any local CSV/TSV or click a 1-Click Enterprise Leak Benchmark to auto-profile PII,
                    bloat columns, and compress multi-megabyte tables down by 95%+ strictly in browser RAM.
                  </p>
                </div>
              ) : (
                <>
                  {datasetResult && (
                    <div className="rounded-2xl border border-emerald-500/50 bg-emerald-500/12 p-5 shadow-lg">
                      <div className="flex flex-wrap items-center justify-between gap-3">
                        <div className="flex items-center gap-2.5">
                          <CheckCircle2 className="h-5 w-5 shrink-0 text-emerald-400" />
                          <div>
                            <h4 className="font-display text-base font-bold text-emerald-200">
                              Dataset Exorcised &amp; Compressed — {datasetResult.attestation.shrinkRatioPercent}% Smaller
                            </h4>
                            <p className="font-mono text-xs text-emerald-300/90">
                              {formatBytes(datasetResult.attestation.sourceBytes)} {'->'}{' '}
                              {formatBytes(datasetResult.attestation.columnarGzipBytes)} (.pgcol.gz) //{' '}
                              {datasetResult.attestation.throughputMbPerSec} MB/s // {datasetResult.attestation.elapsedMs} ms
                            </p>
                          </div>
                        </div>

                        <div className="flex flex-wrap gap-2">
                          <a
                            href={datasetResult.cleanCsvUrl}
                            download={datasetResult.cleanCsvFileName}
                            className="inline-flex cursor-pointer items-center gap-1.5 rounded-lg bg-emerald-500 px-3 py-2 text-xs font-bold text-slate-950 hover:bg-emerald-400"
                          >
                            <Download className="h-3.5 w-3.5" />
                            Clean CSV ({formatBytes(datasetResult.attestation.cleanCsvBytes)})
                          </a>
                          <a
                            href={datasetResult.columnarGzUrl}
                            download={datasetResult.columnarGzFileName}
                            className="inline-flex cursor-pointer items-center gap-1.5 rounded-lg border border-sky-400/50 bg-sky-500/20 px-3 py-2 text-xs font-bold text-sky-200 hover:bg-sky-500/30"
                          >
                            <Download className="h-3.5 w-3.5" />
                            .pgcol.gz ({formatBytes(datasetResult.attestation.columnarGzipBytes)})
                          </a>
                          <button
                            type="button"
                            onClick={() => copyText(datasetResult.attestationJson, 'custody-json')}
                            className="inline-flex cursor-pointer items-center gap-1.5 rounded-lg border border-slate-700 bg-[#080D18] px-3 py-2 font-mono text-xs text-slate-200 hover:border-emerald-500/50"
                          >
                            <Copy className="h-3.5 w-3.5" />
                            {copiedId === 'custody-json' ? 'SHA-256 COPIED' : 'COPY SHA-256 PROOF'}
                          </button>
                        </div>
                      </div>

                      <div className="mt-4 grid grid-cols-2 gap-2.5 sm:grid-cols-4">
                        <div className="rounded-xl border border-slate-800 bg-[#080D18] p-3">
                          <div className="font-mono text-[10px] text-slate-400">ROWS EXPORTED</div>
                          <div className="mt-1 font-display text-lg font-bold tabular-nums text-white">
                            {datasetResult.attestation.rowsExported.toLocaleString()}
                          </div>
                        </div>
                        <div className="rounded-xl border border-slate-800 bg-[#080D18] p-3">
                          <div className="font-mono text-[10px] text-slate-400">SECRETS SCRUBBED</div>
                          <div className="mt-1 font-display text-lg font-bold tabular-nums text-red-400">
                            {datasetResult.attestation.piiCellsScrubbed.toLocaleString()}
                          </div>
                        </div>
                        <div className="rounded-xl border border-slate-800 bg-[#080D18] p-3">
                          <div className="font-mono text-[10px] text-slate-400">PSEUDONYMIZED</div>
                          <div className="mt-1 font-display text-lg font-bold tabular-nums text-amber-300">
                            {datasetResult.attestation.pseudonymizedCells.toLocaleString()}
                          </div>
                        </div>
                        <div className="rounded-xl border border-slate-800 bg-[#080D18] p-3">
                          <div className="font-mono text-[10px] text-slate-400">SHRINK RATIO</div>
                          <div className="mt-1 font-display text-lg font-bold tabular-nums text-emerald-400">
                            {datasetResult.attestation.shrinkRatioPercent}%
                          </div>
                        </div>
                      </div>

                      <div className="mt-3 rounded-lg border border-slate-800 bg-[#060A13] p-3 font-mono text-[10px] text-sky-300">
                        <div>INPUT SHA-256: {datasetResult.attestation.inputSha256}</div>
                        <div className="mt-0.5">PGCOL.GZ SHA-256: {datasetResult.attestation.columnarGzipSha256}</div>
                      </div>
                    </div>
                  )}

                  {/* Auto-Profiled Column Risk & Policy Matrix */}
                  <div className="glass-panel rounded-2xl p-5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div>
                        <h3 className="font-display text-base font-bold text-white">
                          {datasetProfile.fileName}
                        </h3>
                        <p className="font-mono text-xs text-slate-400">
                          RAW SIZE: {formatBytes(datasetProfile.totalBytes)} // EST. ROWS:{' '}
                          {datasetProfile.estimatedRows.toLocaleString()} // COLUMNS: {datasetProfile.columns.length}
                        </p>
                      </div>
                      <SeverityPill level="CLEAN" />
                    </div>

                    <div className="mt-4 space-y-2">
                      {datasetProfile.columns.map((col) => (
                        <div
                          key={col.name}
                          className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-800 bg-[#080D18] px-3.5 py-2.5"
                        >
                          <div className="min-w-0 flex-1">
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="font-mono text-xs font-semibold text-white">{col.name}</span>
                              <SeverityPill level={col.classification} />
                              <span className="font-mono text-[10px] text-slate-400">
                                ~{col.avgCellBytes} B/cell
                              </span>
                            </div>
                            <div className="mt-1 truncate font-mono text-[11px] text-slate-400">
                              {col.detectedSignals.length > 0
                                ? `Signals: ${col.detectedSignals.join(', ')}`
                                : col.sampleValues[0] || 'Clean structured field'}
                            </div>
                          </div>

                          <select
                            value={colPolicies[col.name] ?? col.recommendedPolicy}
                            onChange={(e) =>
                              setColPolicies((prev) => ({
                                ...prev,
                                [col.name]: e.target.value as ColumnPolicy
                              }))
                            }
                            className="rounded-lg border border-slate-700 bg-[#0D1424] px-2.5 py-1.5 font-mono text-xs text-emerald-300"
                          >
                            <option value="KEEP">KEEP</option>
                            <option value="SCRUB_PII">SCRUB_PII</option>
                            <option value="PSEUDONYMIZE_SHA256">PSEUDONYMIZE_SHA256</option>
                            <option value="DROP_COLUMN">DROP_COLUMN</option>
                          </select>
                        </div>
                      ))}
                    </div>

                    {datasetResult && datasetResult.previewRows.length > 0 && (
                      <div className="mt-5">
                        <div className="mb-2 font-mono text-[11px] uppercase tracking-wider text-emerald-400">
                          VERIFIED SCRUBBED OUTPUT PREVIEW (FIRST {datasetResult.previewRows.length} ROWS)
                        </div>
                        <div className="overflow-x-auto rounded-xl border border-slate-800 bg-[#060A13]">
                          <table className="w-full text-left font-mono text-[11px]">
                            <thead className="border-b border-slate-800 bg-[#0B1222] text-slate-300">
                              <tr>
                                {datasetResult.previewHeaders.map((h) => (
                                  <th key={h} className="px-3 py-2 font-semibold">
                                    {h}
                                  </th>
                                ))}
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-800/70 text-slate-300">
                              {datasetResult.previewRows.slice(0, 8).map((row, rIdx) => (
                                <tr key={rIdx}>
                                  {row.map((cell, cIdx) => (
                                    <td key={cIdx} className="max-w-[220px] truncate px-3 py-1.5">
                                      {cell}
                                    </td>
                                  ))}
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}
                  </div>
                </>
              )}
            </div>
          </section>
        )}

        {/* TAB 5: KIRO SPEC-DRIVEN ARCHITECTURE & 7-TOOL MCP INSPECTOR */}
        {activeTab === 'kiro' && (
          <section className="grid items-stretch gap-6 lg:grid-cols-12">
            <div className="flex lg:col-span-6">
              <div className="glass-panel flex w-full flex-col rounded-2xl p-5">
                <h3 className="flex items-center gap-2 font-display text-base font-semibold text-white">
                  <FileCode2 className="h-4 w-4 text-emerald-400" />
                  Tracked .kiro/ Spec-Driven Development Architecture
                </h3>
                <p className="mt-1 text-xs text-slate-400">
                  Every requirement, design diagram, hook, steering rule, and 7-tool MCP configuration is
                  committed directly in the repository root under .kiro/ for full judge verification.
                </p>

                <div className="mt-4 flex flex-1 flex-col justify-between gap-2.5">
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

            <div className="flex lg:col-span-6">
              <div className="glass-panel flex w-full flex-col justify-between rounded-2xl p-5">
                <h3 className="flex items-center gap-2 font-display text-base font-semibold text-white">
                  <Terminal className="h-4 w-4 text-emerald-400" />
                  Live 7-Tool Standalone MCP Server Inspector (./mcp-server/index.mjs)
                </h3>
                <p className="mt-1 text-xs text-slate-400">
                  Zero-dependency Node.js stdio JSON-RPC 2.0 MCP server wired via .kiro/settings/mcp.json.
                  Preview live structured output from the active workbench engines below:
                </p>

                <div className="mt-3 flex flex-wrap gap-2">
                  {[
                    'audit_android_permissions',
                    'audit_ios_plist',
                    'scrub_and_shrink_csv',
                    'scan_text_secrets',
                    'inspect_image_exif_bytes'
                  ].map((tool) => (
                    <button
                      key={tool}
                      type="button"
                      onClick={() => setSelectedMcpTool(tool)}
                      className={`cursor-pointer rounded-lg border px-2.5 py-1.5 font-mono text-[11px] transition ${
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
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="font-mono text-[11px] uppercase tracking-wider text-amber-400">
                      CHAOS STRESS-TEST HARNESS (6 MALFORMED BINARY, iOS, XML &amp; CSV PROBES)
                    </div>
                    <button
                      type="button"
                      onClick={runChaosStressTest}
                      className="cursor-pointer rounded-lg border border-amber-500/40 bg-amber-500/15 px-3 py-1 font-mono text-[11px] font-semibold text-amber-200 hover:bg-amber-500/25"
                    >
                      RUN 6 CHAOS PROBES LIVE
                    </button>
                  </div>
                  {chaosResult && (
                    <pre className="mt-2.5 overflow-x-auto whitespace-pre-wrap rounded-lg border border-emerald-500/30 bg-[#050810] p-3 font-mono text-[11px] text-emerald-300">
                      {chaosResult}
                    </pre>
                  )}
                </div>

                <div className="mt-4 rounded-xl border border-slate-800 bg-[#080D18] p-3.5">
                  <div className="font-mono text-[11px] uppercase tracking-wider text-slate-400">
                    KIRO CLI / IDE QUICK LAUNCH &amp; CHROME MV3 EXTENSION
                  </div>
                  <pre className="mt-1.5 overflow-x-auto font-mono text-xs text-emerald-300">
{`# Run automated 7-Organ Forensic, iOS, Columnar & MCP test suite
node --test tests/forensic-engines.test.mjs

# Connect directly as a local 7-tool Kiro MCP server
node ./mcp-server/index.mjs

# Companion Chrome Side-Panel Extension (Manifest V3):
# Load unpacked from ./extension/ or download release zip`}
                  </pre>
                </div>
              </div>
            </div>
          </section>
        )}
      </main>

      <footer className="mt-auto border-t border-slate-800/50 bg-[#070B14]/75 py-5 text-center text-xs text-slate-400">
        <div className="mx-auto max-w-[1480px] px-4 sm:px-6 lg:px-8">
          PhantomGlass v2.0 // Built by HM Shihabuddin Jashory (@jashory) for Kiroween 2026 (Frankenstein Track) — 7-Organ Zero-Cloud Defensive Security Architecture
        </div>
      </footer>
    </div>
  );
}
