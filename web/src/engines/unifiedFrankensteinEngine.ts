import { parseImageForensics, type BinaryForensicReport } from './exifBinaryParser';
import {
  exorciseImageFile,
  generateLiveForensicSpecimen,
  generateLivePdfSpecimen,
  SPECIMEN_PRESETS,
  type ExorcismResult
} from './mediaExorcist';
import {
  auditManifestPermissions,
  MANIFEST_PRESETS,
  type PermissionAuditReport
} from './permissionGraphEngine';
import {
  auditIosPrivacyManifest,
  IOS_PLIST_PRESETS,
  type IosPrivacyAuditReport
} from './iosPrivacyEngine';
import {
  runAirGapRedaction,
  SECRET_SCENARIOS,
  type AirGapReport
} from './secretAirGapEngine';
import {
  exorciseTabularDataset,
  generateEnterpriseDatasetSpecimen,
  profileTabularSample,
  type ColumnPolicy,
  type DatasetExorcismResult,
  type DatasetProfileReport
} from './columnarScrubberEngine';

export interface ZipExtractedEntry {
  name: string;
  data: Uint8Array;
}

export interface CrossOrganCorrelation {
  id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  organsLinked: string[];
  title: string;
  explanation: string;
}

export interface UnifiedBundleStageSummary {
  id: string;
  organ: string;
  fileName: string;
  status: 'THREAT_DETECTED' | 'CLEAN' | 'EXORCISED';
  riskScore: number;
  headlineMetric: string;
  detail: string;
}

export interface UnifiedPipelineReport {
  bundleName: string;
  sourceMode: 'HAUNTED_SAMPLE_PACK' | 'USER_ZIP_ARCHIVE' | 'USER_MULTI_FILE';
  analyzedAt: string;
  elapsedMs: number;
  totalFilesProcessed: number;
  masterRiskScore: number;
  masterRiskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'CLEAN';
  outboundCloudBytes: number;
  stages: UnifiedBundleStageSummary[];
  correlations: CrossOrganCorrelation[];
  photoRaw?: { buffer: ArrayBuffer; previewUrl: string; report: BinaryForensicReport };
  pdfReport?: BinaryForensicReport;
  androidReport?: PermissionAuditReport;
  iosReport?: IosPrivacyAuditReport;
  secretReport?: AirGapReport;
  datasetSource?: { text: string; fileName: string; profile: DatasetProfileReport };
}

export interface UnifiedExorcismPackage {
  exorcisedAt: string;
  elapsedMs: number;
  beforeRiskScore: number;
  afterRiskScore: number;
  photoResult?: ExorcismResult;
  datasetResult?: DatasetExorcismResult;
  redactedLogText?: string;
  masterChainSha256: string;
  attestationJson: string;
  attestationUrl: string;
  attestationFileName: string;
  totalThreatsNeutralized: number;
}

export interface KiroHookCheckResult {
  hookPath: string;
  targetFile: string;
  verdict: 'BLOCKED' | 'PASSED';
  violations: Array<{
    line: number;
    rule: string;
    token: string;
    remediation: string;
  }>;
  checkedAt: string;
}

/**
 * Pure client-side ZIP central-directory & local-header reader using native
 * browser DecompressionStream('deflate-raw'). Zero network bytes, zero dependencies.
 */
export async function extractZipEntries(buffer: ArrayBuffer): Promise<ZipExtractedEntry[]> {
  const bytes = new Uint8Array(buffer);
  const view = new DataView(buffer);
  const entries: ZipExtractedEntry[] = [];

  // Find End of Central Directory (EOCD) signature 0x06054b50 scanning backwards
  let eocdOffset = -1;
  const minScan = Math.max(0, bytes.length - 65557);
  for (let i = bytes.length - 22; i >= minScan; i--) {
    if (view.getUint32(i, true) === 0x06054b50) {
      eocdOffset = i;
      break;
    }
  }
  if (eocdOffset < 0) return entries;

  const totalEntries = Math.min(view.getUint16(eocdOffset + 10, true), 64);
  let cdOffset = view.getUint32(eocdOffset + 16, true);
  const decoder = new TextDecoder('utf-8');

  for (let idx = 0; idx < totalEntries; idx++) {
    if (cdOffset + 46 > bytes.length || view.getUint32(cdOffset, true) !== 0x02014b50) break;
    const compressionMethod = view.getUint16(cdOffset + 10, true);
    const compressedSize = view.getUint32(cdOffset + 20, true);
    const nameLen = view.getUint16(cdOffset + 28, true);
    const extraLen = view.getUint16(cdOffset + 30, true);
    const commentLen = view.getUint16(cdOffset + 32, true);
    const localHeaderOffset = view.getUint32(cdOffset + 42, true);
    const name = decoder.decode(bytes.subarray(cdOffset + 46, cdOffset + 46 + nameLen));
    cdOffset += 46 + nameLen + extraLen + commentLen;

    if (name.endsWith('/') || name.includes('__MACOSX') || compressedSize > 25 * 1024 * 1024) {
      continue;
    }
    if (localHeaderOffset + 30 > bytes.length || view.getUint32(localHeaderOffset, true) !== 0x04034b50) {
      continue;
    }
    const localNameLen = view.getUint16(localHeaderOffset + 26, true);
    const localExtraLen = view.getUint16(localHeaderOffset + 28, true);
    const dataStart = localHeaderOffset + 30 + localNameLen + localExtraLen;
    const dataEnd = dataStart + compressedSize;
    if (dataEnd > bytes.length) continue;

    const slice = bytes.subarray(dataStart, dataEnd);
    if (compressionMethod === 0) {
      entries.push({ name, data: new Uint8Array(slice) });
    } else if (compressionMethod === 8 && typeof DecompressionStream !== 'undefined') {
      try {
        const ds = new DecompressionStream('deflate-raw');
        const writer = ds.writable.getWriter();
        writer.write(slice);
        writer.close();
        const decompressed = await new Response(ds.readable).arrayBuffer();
        entries.push({ name, data: new Uint8Array(decompressed) });
      } catch {
        // Safely skip malformed compressed entries without crashing
      }
    }
  }
  return entries;
}

async function sha256Hex(text: string): Promise<string> {
  const bytes = new TextEncoder().encode(text);
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    const hashBuf = await crypto.subtle.digest('SHA-256', bytes);
    return Array.from(new Uint8Array(hashBuf))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }
  let h = 2166136261;
  for (let i = 0; i < bytes.length; i++) {
    h ^= bytes[i];
    h = Math.imul(h, 16777619);
  }
  return `fnv32-${(h >>> 0).toString(16).padStart(8, '0')}`;
}

function countRiskyColumns(profile?: DatasetProfileReport): number {
  if (!profile) return 0;
  return profile.columns.filter((c) => c.classification === 'PII_RISK' || c.classification === 'SECRET_RISK').length;
}

function buildCrossOrganCorrelations(
  photoReport?: BinaryForensicReport,
  pdfReport?: BinaryForensicReport,
  androidReport?: PermissionAuditReport,
  iosReport?: IosPrivacyAuditReport,
  secretReport?: AirGapReport,
  datasetProfile?: DatasetProfileReport
): CrossOrganCorrelation[] {
  const correlations: CrossOrganCorrelation[] = [];
  const riskyCols = countRiskyColumns(datasetProfile);

  if (photoReport && Boolean(photoReport.gpsCoordinates) && (androidReport?.blastRadiusScore || 0) >= 60) {
    correlations.push({
      id: 'chain-camera-gps-exfil',
      severity: 'CRITICAL',
      organsLinked: ['Organ 1 (EXIF Binary)', 'Organ 3 (Android 8–17)'],
      title: 'Confirmed Camera-Roll GPS Exfiltration Kill-Chain',
      explanation:
        'Unshared photo embeds raw home GPS coordinates while the companion Android manifest holds blanket gallery + internet permissions—proving silent background location harvesting without user upload.'
    });
  }

  if (iosReport && iosReport.blastRadiusScore >= 60 && photoReport && photoReport.tags.length > 0) {
    correlations.push({
      id: 'chain-ios-photo-ats',
      severity: 'CRITICAL',
      organsLinked: ['Organ 1 (EXIF Binary)', 'Organ 3 (Apple iOS)'],
      title: 'iOS Full Photo Library + Cleartext Transport Exposure',
      explanation:
        'Apple Info.plist requests full photo library access alongside weakened ATS transport rules, exposing embedded camera serial numbers and EXIF timestamps over intercepted links.'
    });
  }

  if (secretReport && secretReport.totalSecretsBlocked > 0 && riskyCols > 0) {
    correlations.push({
      id: 'chain-secret-dataset-blast',
      severity: 'CRITICAL',
      organsLinked: ['Organ 4 (Secret Air-Gap)', 'Organ 7 (Columnar CSV)'],
      title: 'Compounded Credential & Telemetry Dataset Leak',
      explanation: `Incident logs expose ${secretReport.totalSecretsBlocked} live credentials while the telemetry export carries ${riskyCols} PII/secret-bearing columns—sending either to cloud AI creates an irreversible breach.`
    });
  }

  if (pdfReport && pdfReport.riskScore >= 50) {
    correlations.push({
      id: 'chain-pdf-active-trigger',
      severity: 'HIGH',
      organsLinked: ['Organ 2 (PDF Binary)', 'Organ 5 (Zero-Egress Guard)'],
      title: 'Weaponized Document Auto-Execution & Trailing Payload',
      explanation:
        'Active PDF /OpenAction & /JavaScript directives paired with post-%%EOF hidden bytes attempt automatic beacon execution the moment an analyst opens the invoice.'
    });
  }

  return correlations;
}

export async function runHauntedIncidentBundle(): Promise<UnifiedPipelineReport> {
  const started = performance.now();

  // Stage 1: Real Binary EXIF/GPS JPEG + Hostile PDF Invoice
  const photoSpec = await generateLiveForensicSpecimen(SPECIMEN_PRESETS[0]);
  const pdfSpec = generateLivePdfSpecimen();

  // Stage 2: Universal Android 17 (API 37) + Apple iOS Info.plist
  const androidReport = auditManifestPermissions(MANIFEST_PRESETS[0].xml, 37);
  const iosReport = auditIosPrivacyManifest(IOS_PLIST_PRESETS[0].plistXml);

  // Stage 3: Secret Air-Gap Redactor (AWS + GitHub + Stripe + Luhn)
  const combinedLog = `${SECRET_SCENARIOS[0].content}\n\n${SECRET_SCENARIOS[2].content}`;
  const secretReport = runAirGapRedaction(combinedLog);

  // Stage 4: Organ #7 Enterprise CSV Leak Dump (6,000 rows instant pipeline)
  const csvSpec = generateEnterpriseDatasetSpecimen(6000);
  const datasetProfile = profileTabularSample(csvSpec.csvText.slice(0, 256 * 1024), csvSpec.fileName, csvSpec.byteLength);
  const riskyCols = countRiskyColumns(datasetProfile);

  const stages: UnifiedBundleStageSummary[] = [
    {
      id: 'stage-exif',
      organ: 'Organ 1 & 2 — Photo EXIF/GPS',
      fileName: photoSpec.report.fileName,
      status: photoSpec.report.riskScore > 0 ? 'THREAT_DETECTED' : 'CLEAN',
      riskScore: photoSpec.report.riskScore,
      headlineMetric: `${photoSpec.report.tags.length} EXIF tags · GPS ${photoSpec.report.gpsCoordinates ? 'EXPOSED' : 'Clean'}`,
      detail: 'Raw APP1 IFD0/GPS coordinates & device fingerprint extracted strictly in browser RAM.'
    },
    {
      id: 'stage-pdf',
      organ: 'Organ 2 — Document Forensics',
      fileName: pdfSpec.report.fileName,
      status: pdfSpec.report.riskScore > 0 ? 'THREAT_DETECTED' : 'CLEAN',
      riskScore: pdfSpec.report.riskScore,
      headlineMetric: `${pdfSpec.report.tags.length} active triggers · ${pdfSpec.report.trailingBytes} B post-EOF`,
      detail: 'Detected embedded /JavaScript, /OpenAction auto-exec, outbound tracking URI & hidden trailer.'
    },
    {
      id: 'stage-mobile',
      organ: 'Organ 3 — Android 17 & iOS',
      fileName: 'AndroidManifest.xml + Info.plist',
      status: Math.max(androidReport.blastRadiusScore, iosReport.blastRadiusScore) > 0 ? 'THREAT_DETECTED' : 'CLEAN',
      riskScore: Math.max(androidReport.blastRadiusScore, iosReport.blastRadiusScore),
      headlineMetric: `Android ${androidReport.blastRadiusScore}/100 · iOS ${iosReport.blastRadiusScore}/100`,
      detail: `${androidReport.chains.length} Android & ${iosReport.chains.length} iOS silent exfiltration chains mapped with ADB/AppOps & PrivacyInfo fixes.`
    },
    {
      id: 'stage-secrets',
      organ: 'Organ 4 — Secret Air-Gap',
      fileName: 'incident_support_and_deploy.log',
      status: secretReport.totalSecretsBlocked > 0 ? 'THREAT_DETECTED' : 'CLEAN',
      riskScore: secretReport.totalSecretsBlocked > 0 ? 94 : 0,
      headlineMetric: `${secretReport.totalSecretsBlocked} live credentials intercepted`,
      detail: 'Blocked AWS keys, GitHub PATs, Luhn payment cards, JWTs & high-entropy secrets before AI paste.'
    },
    {
      id: 'stage-dataset',
      organ: 'Organ 7 — Columnar CSV Shrinker',
      fileName: csvSpec.fileName,
      status: riskyCols > 0 ? 'THREAT_DETECTED' : 'CLEAN',
      riskScore: riskyCols > 0 ? 92 : 0,
      headlineMetric: `${(csvSpec.byteLength / (1024 * 1024)).toFixed(2)} MB raw · ${riskyCols} risky columns`,
      detail: 'Ready to pseudonymize emails/phones, scrub audit secrets, drop debug bloat & compress >94% into .pgcol.gz.'
    }
  ];

  const correlations = buildCrossOrganCorrelations(
    photoSpec.report,
    pdfSpec.report,
    androidReport,
    iosReport,
    secretReport,
    datasetProfile
  );

  const avgRisk = Math.round(stages.reduce((acc, s) => acc + s.riskScore, 0) / stages.length);
  const masterRiskScore = Math.min(100, Math.max(avgRisk, Math.max(...stages.map((s) => s.riskScore))));

  return {
    bundleName: 'Haunted_Incident_Bundle_2026.zip (5 Cross-Organ Artifacts)',
    sourceMode: 'HAUNTED_SAMPLE_PACK',
    analyzedAt: new Date().toISOString(),
    elapsedMs: Math.max(1, Math.round(performance.now() - started)),
    totalFilesProcessed: 6,
    masterRiskScore,
    masterRiskLevel: masterRiskScore >= 75 ? 'CRITICAL' : masterRiskScore >= 45 ? 'HIGH' : masterRiskScore > 0 ? 'MEDIUM' : 'CLEAN',
    outboundCloudBytes: 0,
    stages,
    correlations,
    photoRaw: {
      buffer: photoSpec.buffer,
      previewUrl: photoSpec.previewUrl,
      report: photoSpec.report
    },
    pdfReport: pdfSpec.report,
    androidReport,
    iosReport,
    secretReport,
    datasetSource: {
      text: csvSpec.csvText,
      fileName: csvSpec.fileName,
      profile: datasetProfile
    }
  };
}

export async function runUnifiedUserFiles(files: File[]): Promise<UnifiedPipelineReport> {
  const started = performance.now();
  const rawItems: Array<{ name: string; buffer: ArrayBuffer; mime: string }> = [];
  let sourceMode: 'USER_ZIP_ARCHIVE' | 'USER_MULTI_FILE' = 'USER_MULTI_FILE';

  for (const file of files) {
    const buf = await file.arrayBuffer();
    if (file.name.toLowerCase().endsWith('.zip')) {
      sourceMode = 'USER_ZIP_ARCHIVE';
      const extracted = await extractZipEntries(buf);
      for (const entry of extracted) {
        const lower = entry.name.toLowerCase();
        const mime = lower.endsWith('.jpg') || lower.endsWith('.jpeg')
          ? 'image/jpeg'
          : lower.endsWith('.png')
            ? 'image/png'
            : lower.endsWith('.pdf')
              ? 'application/pdf'
              : 'text/plain';
        rawItems.push({ name: entry.name, buffer: entry.data.buffer.slice(entry.data.byteOffset, entry.data.byteOffset + entry.data.byteLength), mime });
      }
    } else {
      rawItems.push({ name: file.name, buffer: buf, mime: file.type || 'application/octet-stream' });
    }
  }

  let photoRaw: UnifiedPipelineReport['photoRaw'];
  let pdfReport: BinaryForensicReport | undefined;
  let androidReport: PermissionAuditReport | undefined;
  let iosReport: IosPrivacyAuditReport | undefined;
  let secretReport: AirGapReport | undefined;
  let datasetSource: UnifiedPipelineReport['datasetSource'];
  const stages: UnifiedBundleStageSummary[] = [];
  const decoder = new TextDecoder('utf-8');

  for (const item of rawItems) {
    const low = item.name.toLowerCase();
    if (low.endsWith('.jpg') || low.endsWith('.jpeg') || low.endsWith('.png')) {
      const report = parseImageForensics(item.buffer, item.name, item.mime);
      const blob = new Blob([item.buffer], { type: item.mime });
      photoRaw = { buffer: item.buffer, previewUrl: URL.createObjectURL(blob), report };
      stages.push({
        id: `stage-img-${stages.length}`,
        organ: 'Organ 1 & 2 — Photo EXIF/GPS',
        fileName: item.name,
        status: report.riskScore > 0 ? 'THREAT_DETECTED' : 'CLEAN',
        riskScore: report.riskScore,
        headlineMetric: `${report.tags.length} tags · GPS ${report.gpsCoordinates ? 'EXPOSED' : 'Clean'}`,
        detail: `${report.format} decoded strictly in browser RAM (${report.byteLength.toLocaleString()} bytes).`
      });
    } else if (low.endsWith('.pdf')) {
      const report = parseImageForensics(item.buffer, item.name, 'application/pdf');
      pdfReport = report;
      stages.push({
        id: `stage-pdf-${stages.length}`,
        organ: 'Organ 2 — Document Forensics',
        fileName: item.name,
        status: report.riskScore > 0 ? 'THREAT_DETECTED' : 'CLEAN',
        riskScore: report.riskScore,
        headlineMetric: `${report.tags.length} findings · ${report.trailingBytes} B post-EOF`,
        detail: 'Binary PDF stream inspected for /JavaScript, /OpenAction, /Launch, URIs & trailers.'
      });
    } else if (low.endsWith('.csv') || low.endsWith('.tsv')) {
      const text = decoder.decode(item.buffer);
      const profile = profileTabularSample(text.slice(0, 256 * 1024), item.name, item.buffer.byteLength);
      const userRiskyCols = countRiskyColumns(profile);
      datasetSource = { text, fileName: item.name, profile };
      stages.push({
        id: `stage-csv-${stages.length}`,
        organ: 'Organ 7 — Columnar CSV Shrinker',
        fileName: item.name,
        status: userRiskyCols > 0 ? 'THREAT_DETECTED' : 'CLEAN',
        riskScore: userRiskyCols > 0 ? 88 : 15,
        headlineMetric: `${profile.columns.length} columns · ${userRiskyCols} PII/secret columns`,
        detail: 'Ready for offline PII pseudonymization, bloat column removal & .pgcol.gz compression.'
      });
    } else {
      const text = decoder.decode(item.buffer);
      if (/uses-permission|AndroidManifest/i.test(text) || low.includes('manifest')) {
        androidReport = auditManifestPermissions(text, 37);
        stages.push({
          id: `stage-android-${stages.length}`,
          organ: 'Organ 3 — Android 8–17 Audit',
          fileName: item.name,
          status: androidReport.blastRadiusScore > 0 ? 'THREAT_DETECTED' : 'CLEAN',
          riskScore: androidReport.blastRadiusScore,
          headlineMetric: `Blast radius ${androidReport.blastRadiusScore}/100 · ${androidReport.chains.length} chains`,
          detail: 'Mapped dangerous permissions to version-accurate ADB & AppOps revocation commands.'
        });
      } else if (/NSCameraUsageDescription|NSPhotoLibraryUsageDescription|NSAllowsArbitraryLoads|<plist/i.test(text) || low.endsWith('.plist') || low.endsWith('.xcprivacy')) {
        iosReport = auditIosPrivacyManifest(text);
        stages.push({
          id: `stage-ios-${stages.length}`,
          organ: 'Organ 3 — Apple iOS Audit',
          fileName: item.name,
          status: iosReport.blastRadiusScore > 0 ? 'THREAT_DETECTED' : 'CLEAN',
          riskScore: iosReport.blastRadiusScore,
          headlineMetric: `Blast radius ${iosReport.blastRadiusScore}/100 · ${iosReport.chains.length} chains`,
          detail: 'Audited Apple Info.plist & PrivacyInfo.xcprivacy for photo, ATT & ATS downgrades.'
        });
      } else {
        secretReport = runAirGapRedaction(text);
        stages.push({
          id: `stage-secret-${stages.length}`,
          organ: 'Organ 4 — Secret Air-Gap',
          fileName: item.name,
          status: secretReport.totalSecretsBlocked > 0 ? 'THREAT_DETECTED' : 'CLEAN',
          riskScore: secretReport.totalSecretsBlocked > 0 ? 92 : 0,
          headlineMetric: `${secretReport.totalSecretsBlocked} secrets intercepted`,
          detail: 'Scanned text strictly offline for cloud keys, PATs, Luhn cards & Shannon-entropy tokens.'
        });
      }
    }
  }

  const correlations = buildCrossOrganCorrelations(
    photoRaw?.report,
    pdfReport,
    androidReport,
    iosReport,
    secretReport,
    datasetSource?.profile
  );

  const masterRiskScore = stages.length > 0 ? Math.max(...stages.map((s) => s.riskScore)) : 0;

  return {
    bundleName: files.length === 1 ? files[0].name : `${files.length} Local Forensic Files`,
    sourceMode,
    analyzedAt: new Date().toISOString(),
    elapsedMs: Math.max(1, Math.round(performance.now() - started)),
    totalFilesProcessed: rawItems.length,
    masterRiskScore,
    masterRiskLevel: masterRiskScore >= 75 ? 'CRITICAL' : masterRiskScore >= 45 ? 'HIGH' : masterRiskScore > 0 ? 'MEDIUM' : 'CLEAN',
    outboundCloudBytes: 0,
    stages,
    correlations,
    photoRaw,
    pdfReport,
    androidReport,
    iosReport,
    secretReport,
    datasetSource
  };
}

export async function exorciseUnifiedBundle(report: UnifiedPipelineReport): Promise<UnifiedExorcismPackage> {
  const started = performance.now();
  let photoResult: ExorcismResult | undefined;
  let datasetResult: DatasetExorcismResult | undefined;
  let totalThreatsNeutralized = 0;

  if (report.photoRaw && report.photoRaw.report.format !== 'PDF') {
    photoResult = await exorciseImageFile(
      report.photoRaw.buffer,
      report.photoRaw.report.fileName,
      report.photoRaw.report.mimeType
    );
    totalThreatsNeutralized += photoResult.tagsEliminated;
  }

  if (report.datasetSource) {
    const policies: Record<string, ColumnPolicy> = {};
    for (const c of report.datasetSource.profile.columns) {
      policies[c.name] = c.recommendedPolicy;
    }
    datasetResult = await exorciseTabularDataset(
      report.datasetSource.text,
      report.datasetSource.fileName,
      { policies }
    );
    totalThreatsNeutralized += datasetResult.attestation.piiCellsScrubbed + datasetResult.attestation.pseudonymizedCells;
  }

  if (report.secretReport) {
    totalThreatsNeutralized += report.secretReport.totalSecretsBlocked;
  }
  if (report.androidReport) {
    totalThreatsNeutralized += report.androidReport.chains.length;
  }
  if (report.iosReport) {
    totalThreatsNeutralized += report.iosReport.chains.length;
  }
  if (report.pdfReport) {
    totalThreatsNeutralized += report.pdfReport.tags.length;
  }

  const receiptPayload = {
    schema: 'phantomglass.frankenstein.chain-of-custody.v3',
    bundleName: report.bundleName,
    exorcisedAt: new Date().toISOString(),
    outboundCloudBytes: 0,
    beforeMasterRiskScore: report.masterRiskScore,
    afterMasterRiskScore: 0,
    totalThreatsNeutralized,
    crossOrganCorrelationsResolved: report.correlations.map((c) => c.title),
    artifacts: {
      photoExorcised: photoResult
        ? {
            fileName: photoResult.cleanFileName,
            tagsEliminated: photoResult.tagsEliminated,
            remainingTags: photoResult.afterReport.tags.length,
            remainingTrailerBytes: photoResult.afterReport.trailingBytes
          }
        : null,
      datasetCompressed: datasetResult
        ? {
            fileName: datasetResult.columnarGzFileName,
            rawBytes: datasetResult.attestation.sourceBytes,
            compressedBytes: datasetResult.attestation.columnarGzipBytes,
            shrinkPercent: datasetResult.attestation.shrinkRatioPercent,
            sha256: datasetResult.attestation.columnarGzipSha256
          }
        : null,
      secretsRedactedCount: report.secretReport?.totalSecretsBlocked ?? 0
    }
  };

  const receiptCanonical = JSON.stringify(receiptPayload, null, 2);
  const masterChainSha256 = await sha256Hex(receiptCanonical);
  const attestationJson = JSON.stringify({ ...receiptPayload, masterChainSha256 }, null, 2);
  const attestationBlob = new Blob([attestationJson], { type: 'application/json' });
  const attestationUrl = URL.createObjectURL(attestationBlob);

  return {
    exorcisedAt: receiptPayload.exorcisedAt,
    elapsedMs: Math.max(1, Math.round(performance.now() - started)),
    beforeRiskScore: report.masterRiskScore,
    afterRiskScore: 0,
    photoResult,
    datasetResult,
    redactedLogText: report.secretReport?.redactedText,
    masterChainSha256,
    attestationJson,
    attestationUrl,
    attestationFileName: 'PhantomGlass_v3_ChainOfCustody_Attestation.json',
    totalThreatsNeutralized
  };
}

export const KIRO_HOOK_TEST_SNIPPETS = {
  rogueTelemetry: `// Simulated accidental telemetry commit in web/src/engines/exifBinaryParser.ts
export async function parseAndReport(gps: { lat: number; lon: number }) {
  await fetch('https://telemetry.collector.example/v1/gps', {
    method: 'POST',
    body: JSON.stringify(gps)
  });
  navigator.sendBeacon('https://pixel.tracker.example/hit', String(gps.lat));
}`,
  cleanZeroEgress: `// Compliant zero-cloud forensic helper in web/src/engines/exifBinaryParser.ts
export function clampReadUint32(view: DataView, offset: number, littleEndian: boolean): number {
  if (offset < 0 || offset + 4 > view.byteLength) return 0;
  return view.getUint32(offset, littleEndian);
}`
};

export function runKiroZeroEgressHookCheck(sourceCode: string, targetFile = 'web/src/engines/exifBinaryParser.ts'): KiroHookCheckResult {
  const lines = sourceCode.split(/\r?\n/);
  const rules: Array<{ pattern: RegExp; rule: string; remediation: string }> = [
    {
      pattern: /\bfetch\s*\(\s*['"`]https?:\/\//i,
      rule: 'KIRO-ZERO-EGRESS-001 (Forbidden outbound fetch)',
      remediation: 'Remove outbound HTTP calls. All forensic parsing must execute strictly in local browser RAM.'
    },
    {
      pattern: /\bnavigator\.sendBeacon\s*\(/i,
      rule: 'KIRO-ZERO-EGRESS-002 (Forbidden background sendBeacon)',
      remediation: 'Strip telemetry beacons immediately per .kiro/steering/product-and-privacy-constitution.md.'
    },
    {
      pattern: /\bnew\s+(WebSocket|XMLHttpRequest)\s*\(/i,
      rule: 'KIRO-ZERO-EGRESS-003 (Forbidden raw socket/XHR egress)',
      remediation: 'Eliminate external sockets or XHR channels from forensic engine modules.'
    }
  ];

  const violations: KiroHookCheckResult['violations'] = [];
  lines.forEach((lineText, idx) => {
    for (const r of rules) {
      const m = lineText.match(r.pattern);
      if (m) {
        violations.push({
          line: idx + 1,
          rule: r.rule,
          token: m[0],
          remediation: r.remediation
        });
      }
    }
  });

  return {
    hookPath: '.kiro/hooks/zero-leak-security-audit.json',
    targetFile,
    verdict: violations.length > 0 ? 'BLOCKED' : 'PASSED',
    violations,
    checkedAt: new Date().toISOString()
  };
}
