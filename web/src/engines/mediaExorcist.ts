/**
 * PhantomGlass Organ #2: Cryptographic Pixel Re-Encoding & Metadata Exorcist
 * Strips 100% of binary EXIF/GPS/XMP/IPTC/PNG chunks & trailing payloads in local RAM,
 * then independently re-parses the clean output buffer to prove 0 metadata survives.
 */

import {
  parseImageForensics,
  spliceSyntheticExifAndTrailer,
  type BinaryForensicReport
} from './exifBinaryParser';

export interface ExorcismResult {
  cleanBlob: Blob;
  cleanUrl: string;
  cleanFileName: string;
  beforeReport: BinaryForensicReport;
  afterReport: BinaryForensicReport;
  bytesPurged: number;
  tagsEliminated: number;
  verifiedClean: boolean;
}

export async function exorciseImageFile(
  buffer: ArrayBuffer,
  fileName: string,
  mimeType: string
): Promise<ExorcismResult> {
  const beforeReport = parseImageForensics(buffer, fileName, mimeType);
  const sourceBlob = new Blob([buffer], { type: mimeType || 'image/jpeg' });
  const bitmapUrl = URL.createObjectURL(sourceBlob);

  try {
    const img = await new Promise<HTMLImageElement>((resolve, reject) => {
      const el = new Image();
      el.onload = () => resolve(el);
      el.onerror = () => reject(new Error('Unable to decode image pixels cleanly.'));
      el.src = bitmapUrl;
    });

    const canvas = document.createElement('canvas');
    canvas.width = img.naturalWidth || 800;
    canvas.height = img.naturalHeight || 500;
    const ctx = canvas.getContext('2d');
    if (!ctx) throw new Error('Canvas 2D context unavailable.');
    ctx.drawImage(img, 0, 0);

    const outMime = mimeType === 'image/png' ? 'image/png' : 'image/jpeg';
    const cleanBlob = await new Promise<Blob>((resolve, reject) => {
      canvas.toBlob(
        (b) => (b ? resolve(b) : reject(new Error('Canvas re-encoding failed.'))),
        outMime,
        0.92
      );
    });

    const cleanBuffer = await cleanBlob.arrayBuffer();
    const baseName = fileName.replace(/\.[^.]+$/, '');
    const ext = outMime === 'image/png' ? 'png' : 'jpg';
    const cleanFileName = `${baseName}_EXORCISED_CLEAN.${ext}`;

    // Independent second-pass binary verification
    const afterReport = parseImageForensics(cleanBuffer, cleanFileName, outMime);
    const cleanUrl = URL.createObjectURL(cleanBlob);

    return {
      cleanBlob,
      cleanUrl,
      cleanFileName,
      beforeReport,
      afterReport,
      bytesPurged: Math.max(0, beforeReport.byteLength - afterReport.byteLength),
      tagsEliminated: beforeReport.tags.length - afterReport.tags.length,
      verifiedClean: afterReport.tags.length === 0 && afterReport.trailingBytes === 0
    };
  } finally {
    URL.revokeObjectURL(bitmapUrl);
  }
}

export interface SpecimenPreset {
  id: string;
  label: string;
  subtitle: string;
  fileName: string;
  spec: Parameters<typeof spliceSyntheticExifAndTrailer>[1];
}

export const SPECIMEN_PRESETS: SpecimenPreset[] = [
  {
    id: 'home-gallery-photo',
    label: 'Unshared Camera-Roll Photo (Home GPS + Device Fingerprint)',
    subtitle: 'Simulates a private gallery photo silently scraped via blanket Android media permission',
    fileName: 'IMG_20261119_HOME_PRIVATE.jpg',
    spec: {
      make: 'Samsung Electronics',
      model: 'Galaxy S25 Ultra (SM-S938B)',
      software: 'Android 16 / OneUI 8.1 Build S938BXXU2',
      dateTime: '2026:11:19 09:42:17',
      artist: 'Private Household Camera Roll',
      userComment: 'CLOUD_INDEX_QUEUE=PENDING;FACE_CLUSTER=HOME_FAMILY',
      latDeg: [23, 10, 4.8],
      latRef: 'N',
      lonDeg: [89, 12, 51.4],
      lonRef: 'E',
      trailerText: 'PHANTOM_APP_TELEMETRY_TRAILER::DEVICE_HASH=9F4A2C88::UNSHARED_ROLL=TRUE'
    }
  },
  {
    id: 'wire-receipt-screenshot',
    label: 'Bank Wire Receipt Photo (Office GPS + Hidden Trailing Bytes)',
    subtitle: 'Contains exact branch GPS coordinates + serial metadata + appended post-EOI bytes',
    fileName: 'WIRE_RECEIPT_CONFIDENTIAL.jpg',
    spec: {
      make: 'Apple',
      model: 'iPhone 17 Pro Max',
      software: 'iOS 20.1.2 (24B109)',
      dateTime: '2026:11:18 14:15:03',
      artist: 'Finance Operations Lead',
      userComment: 'SWIFT_COPY_INTERNAL_DO_NOT_UPLOAD',
      latDeg: [37, 25, 19.2],
      latRef: 'N',
      lonDeg: [122, 5, 6.0],
      lonRef: 'W',
      trailerText: 'HIDDEN_POST_EOI_STEG_BLOCK::SESSION_TRACKER=4419283710'
    }
  }
];

export async function generateLiveForensicSpecimen(
  preset: SpecimenPreset
): Promise<{ buffer: ArrayBuffer; previewUrl: string; report: BinaryForensicReport }> {
  const canvas = document.createElement('canvas');
  canvas.width = 720;
  canvas.height = 420;
  const ctx = canvas.getContext('2d')!;

  // Draw crisp Swiss-forensic synthetic evidence graphic
  const grad = ctx.createLinearGradient(0, 0, 720, 420);
  grad.addColorStop(0, '#091121');
  grad.addColorStop(1, '#111C33');
  ctx.fillStyle = grad;
  ctx.fillRect(0, 0, 720, 420);

  // Precision laboratory grid
  ctx.strokeStyle = 'rgba(148, 163, 184, 0.12)';
  ctx.lineWidth = 1;
  for (let x = 0; x < 720; x += 36) {
    ctx.beginPath();
    ctx.moveTo(x, 0);
    ctx.lineTo(x, 420);
    ctx.stroke();
  }
  for (let y = 0; y < 420; y += 36) {
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(720, y);
    ctx.stroke();
  }

  // Containment frame
  ctx.strokeStyle = '#EF4444';
  ctx.lineWidth = 2;
  ctx.strokeRect(28, 28, 664, 364);

  ctx.fillStyle = '#EF4444';
  ctx.font = 'bold 14px monospace';
  ctx.fillText('SYNTHETIC BINARY SPECIMEN // GENUINE APP1 EXIF + GPS + EOI TRAILER', 48, 66);

  ctx.fillStyle = '#F8FAFC';
  ctx.font = 'bold 26px sans-serif';
  ctx.fillText(preset.fileName, 48, 114);

  ctx.fillStyle = '#94A3B8';
  ctx.font = '15px monospace';
  ctx.fillText(`DEVICE:   ${preset.spec.make} — ${preset.spec.model}`, 48, 168);
  ctx.fillText(`OS BUILD: ${preset.spec.software}`, 48, 198);
  ctx.fillText(`CAPTURED: ${preset.spec.dateTime}`, 48, 228);
  ctx.fillStyle = '#FCA5A5';
  ctx.fillText(
    `GPS EXIF: ${preset.spec.latDeg[0]}°${preset.spec.latDeg[1]}'${preset.spec.latDeg[2]}" ${preset.spec.latRef}, ${preset.spec.lonDeg[0]}°${preset.spec.lonDeg[1]}'${preset.spec.lonDeg[2]}" ${preset.spec.lonRef}`,
    48,
    264
  );
  ctx.fillStyle = '#FCD34D';
  ctx.fillText(`TRAILER:  +${preset.spec.trailerText?.length ?? 0} hidden bytes appended past 0xFFD9 EOI`, 48, 298);

  ctx.fillStyle = '#22C55E';
  ctx.font = '13px monospace';
  ctx.fillText('ZERO-CLOUD LOCAL SPECIMEN — CLICK "EXORCISE & VERIFY" TO PURGE ALL BINARY LEAKS', 48, 358);

  const rawBlob = await new Promise<Blob>((resolve, reject) => {
    canvas.toBlob((b) => (b ? resolve(b) : reject(new Error('Specimen encode error'))), 'image/jpeg', 0.92);
  });
  const baseBuf = await rawBlob.arrayBuffer();
  const splicedBuf = spliceSyntheticExifAndTrailer(baseBuf, preset.spec);
  const splicedBlob = new Blob([splicedBuf], { type: 'image/jpeg' });
  const previewUrl = URL.createObjectURL(splicedBlob);
  const report = parseImageForensics(splicedBuf, preset.fileName, 'image/jpeg');

  return { buffer: splicedBuf, previewUrl, report };
}

export function generateLivePdfSpecimen(): {
  buffer: ArrayBuffer;
  report: BinaryForensicReport;
} {
  const rawPdf = `%PDF-1.7
1 0 obj
<< /Type /Catalog /OpenAction 2 0 R >>
endobj
2 0 obj
<< /Type /Action /S /JavaScript /JS (app.alert('Synthetic_Forensic_Probe')) /URI (https://verify-payroll-login.invalid/collect) >>
endobj
3 0 obj
<< /Author (Finance Dept Workstation #14) /Creator (Adobe Acrobat Pro 2026) /Producer (macOS Quartz PDFContext) /CreationDate (D:20261119101500+06'00') >>
endobj
%%EOF
PHANTOM_HIDDEN_POST_EOF_TRAILER_PAYLOAD_2026`;
  const encoded = new TextEncoder().encode(rawPdf);
  const buffer = encoded.buffer.slice(encoded.byteOffset, encoded.byteOffset + encoded.byteLength);
  const report = parseImageForensics(buffer, 'SUSPICIOUS_INVOICE_TRAP.pdf', 'application/pdf');
  return { buffer, report };
}
