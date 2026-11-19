/**
 * PhantomGlass Organ #1: Pure Zero-Cloud Binary JPEG/EXIF/GPS & PNG Forensic Parser
 * Strictly bounds-checked DataView parsing — runs 100% in local RAM (0 cloud bytes).
 */

export interface ExifTagEntry {
  id: string;
  group: 'IFD0' | 'ExifIFD' | 'GPS' | 'PNG_CHUNK' | 'PDF_META' | 'PDF_ACTION' | 'TRAILER';
  name: string;
  value: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
}

export interface BinaryForensicReport {
  fileName: string;
  mimeType: string;
  byteLength: number;
  format: 'JPEG' | 'PNG' | 'PDF' | 'UNKNOWN';
  tags: ExifTagEntry[];
  gpsCoordinates: { lat: number; lon: number } | null;
  trailingBytes: number;
  riskScore: number;
  riskLevel: 'CLEAN' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  hexPreview: string;
  cloudBytesSent: 0;
}

const IFD0_TAGS: Record<number, { name: string; severity: ExifTagEntry['severity'] }> = {
  0x010f: { name: 'Camera Make', severity: 'HIGH' },
  0x0110: { name: 'Device Model', severity: 'HIGH' },
  0x0112: { name: 'Orientation', severity: 'LOW' },
  0x0131: { name: 'Software / OS Build', severity: 'MEDIUM' },
  0x0132: { name: 'Modify DateTime', severity: 'HIGH' },
  0x013b: { name: 'Artist / Owner', severity: 'CRITICAL' },
  0x8298: { name: 'Copyright', severity: 'MEDIUM' }
};

const EXIF_SUB_TAGS: Record<number, { name: string; severity: ExifTagEntry['severity'] }> = {
  0x9003: { name: 'DateTime Original', severity: 'HIGH' },
  0x9004: { name: 'DateTime Digitized', severity: 'MEDIUM' },
  0x9286: { name: 'UserComment / App Payload', severity: 'HIGH' },
  0xa431: { name: 'Body Serial Number', severity: 'CRITICAL' },
  0xa434: { name: 'Lens Model', severity: 'MEDIUM' }
};

function readAscii(bytes: Uint8Array, start: number, count: number): string {
  if (start < 0 || start >= bytes.length || count <= 0) return '';
  const end = Math.min(bytes.length, start + count);
  let out = '';
  for (let i = start; i < end; i++) {
    const ch = bytes[i];
    if (ch === 0) break;
    if (ch >= 32 && ch <= 126) out += String.fromCharCode(ch);
  }
  return out.trim();
}

function readRational(view: DataView, offset: number, littleEndian: boolean): number {
  if (offset < 0 || offset + 8 > view.byteLength) return 0;
  const num = view.getUint32(offset, littleEndian);
  const den = view.getUint32(offset + 4, littleEndian);
  return den === 0 ? 0 : num / den;
}

function toHexPreview(bytes: Uint8Array, maxBytes = 64): string {
  const slice = bytes.slice(0, Math.min(bytes.length, maxBytes));
  return Array.from(slice)
    .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
    .join(' ');
}

function parseIfd(
  bytes: Uint8Array,
  view: DataView,
  tiffStart: number,
  ifdRelOffset: number,
  littleEndian: boolean,
  tagMap: Record<number, { name: string; severity: ExifTagEntry['severity'] }>,
  group: ExifTagEntry['group'],
  tags: ExifTagEntry[]
): { exifOffset: number | null; gpsOffset: number | null } {
  let exifOffset: number | null = null;
  let gpsOffset: number | null = null;
  const absOffset = tiffStart + ifdRelOffset;
  if (absOffset < tiffStart || absOffset + 2 > view.byteLength) {
    return { exifOffset, gpsOffset };
  }

  const entryCount = view.getUint16(absOffset, littleEndian);
  for (let i = 0; i < entryCount; i++) {
    const entryPos = absOffset + 2 + i * 12;
    if (entryPos + 12 > view.byteLength) break;

    const tagId = view.getUint16(entryPos, littleEndian);
    const type = view.getUint16(entryPos + 2, littleEndian);
    const count = view.getUint32(entryPos + 4, littleEndian);
    const valueOrOffset = view.getUint32(entryPos + 8, littleEndian);

    if (tagId === 0x8769) {
      exifOffset = valueOrOffset;
      continue;
    }
    if (tagId === 0x8825) {
      gpsOffset = valueOrOffset;
      continue;
    }

    const meta = tagMap[tagId];
    if (!meta) continue;

    let displayVal = '';
    if (type === 2) {
      // ASCII string
      const strOffset = count <= 4 ? entryPos + 8 : tiffStart + valueOrOffset;
      displayVal = readAscii(bytes, strOffset, count);
    } else if (type === 7) {
      // UNDEFINED (e.g. UserComment)
      const strOffset = count <= 4 ? entryPos + 8 : tiffStart + valueOrOffset;
      displayVal = readAscii(bytes, strOffset, Math.min(count, 160));
    } else if (type === 3) {
      displayVal = String(view.getUint16(entryPos + 8, littleEndian));
    } else if (type === 4) {
      displayVal = String(valueOrOffset);
    }

    if (displayVal) {
      tags.push({
        id: `${group}-${tagId.toString(16)}`,
        group,
        name: meta.name,
        value: displayVal,
        severity: meta.severity
      });
    }
  }
  return { exifOffset, gpsOffset };
}

function parseGpsIfd(
  bytes: Uint8Array,
  view: DataView,
  tiffStart: number,
  gpsRelOffset: number,
  littleEndian: boolean,
  tags: ExifTagEntry[]
): { lat: number; lon: number } | null {
  const absOffset = tiffStart + gpsRelOffset;
  if (absOffset < tiffStart || absOffset + 2 > view.byteLength) return null;

  let latRef = 'N';
  let lonRef = 'E';
  let latDms: [number, number, number] | null = null;
  let lonDms: [number, number, number] | null = null;

  const entryCount = view.getUint16(absOffset, littleEndian);
  for (let i = 0; i < entryCount; i++) {
    const entryPos = absOffset + 2 + i * 12;
    if (entryPos + 12 > view.byteLength) break;
    const tagId = view.getUint16(entryPos, littleEndian);
    const count = view.getUint32(entryPos + 4, littleEndian);
    const valueOrOffset = view.getUint32(entryPos + 8, littleEndian);

    if (tagId === 0x0001) {
      latRef = readAscii(bytes, entryPos + 8, Math.min(count, 4)) || 'N';
    } else if (tagId === 0x0003) {
      lonRef = readAscii(bytes, entryPos + 8, Math.min(count, 4)) || 'E';
    } else if (tagId === 0x0002 && count === 3) {
      const base = tiffStart + valueOrOffset;
      latDms = [
        readRational(view, base, littleEndian),
        readRational(view, base + 8, littleEndian),
        readRational(view, base + 16, littleEndian)
      ];
    } else if (tagId === 0x0004 && count === 3) {
      const base = tiffStart + valueOrOffset;
      lonDms = [
        readRational(view, base, littleEndian),
        readRational(view, base + 8, littleEndian),
        readRational(view, base + 16, littleEndian)
      ];
    }
  }

  if (latDms && lonDms) {
    let lat = latDms[0] + latDms[1] / 60 + latDms[2] / 3600;
    let lon = lonDms[0] + lonDms[1] / 60 + lonDms[2] / 3600;
    if (latRef.toUpperCase() === 'S') lat = -lat;
    if (lonRef.toUpperCase() === 'W') lon = -lon;
    const roundedLat = Number(lat.toFixed(6));
    const roundedLon = Number(lon.toFixed(6));

    tags.push({
      id: 'GPS-COORDS',
      group: 'GPS',
      name: 'Exact Physical GPS Coordinates',
      value: `${roundedLat}, ${roundedLon} (${latRef}/${lonRef})`,
      severity: 'CRITICAL'
    });
    return { lat: roundedLat, lon: roundedLon };
  }
  return null;
}

export function parseImageForensics(
  buffer: ArrayBuffer,
  fileName = 'specimen.jpg',
  mimeType = 'image/jpeg'
): BinaryForensicReport {
  const bytes = new Uint8Array(buffer);
  const view = new DataView(buffer);
  const tags: ExifTagEntry[] = [];
  let format: BinaryForensicReport['format'] = 'UNKNOWN';
  let gpsCoordinates: { lat: number; lon: number } | null = null;
  let trailingBytes = 0;

  if (bytes.length >= 4 && bytes[0] === 0xff && bytes[1] === 0xd8) {
    format = 'JPEG';
    let offset = 2;
    let eoiEnd = -1;

    while (offset + 4 <= bytes.length) {
      if (bytes[offset] !== 0xff) break;
      const marker = bytes[offset + 1];
      if (marker === 0xd9) {
        eoiEnd = offset + 2;
        break;
      }
      if (marker === 0xda) {
        // Scan backwards for final EOI (0xFFD9)
        for (let i = bytes.length - 2; i >= offset; i--) {
          if (bytes[i] === 0xff && bytes[i + 1] === 0xd9) {
            eoiEnd = i + 2;
            break;
          }
        }
        break;
      }
      const segLen = view.getUint16(offset + 2, false);
      if (segLen < 2 || offset + 2 + segLen > bytes.length) break;

      if (marker === 0xe1 && segLen > 14) {
        const exifHeader = readAscii(bytes, offset + 4, 6);
        if (exifHeader === 'Exif') {
          const tiffStart = offset + 10;
          if (tiffStart + 8 <= bytes.length) {
            const byteOrder = view.getUint16(tiffStart, false);
            const littleEndian = byteOrder === 0x4949;
            const firstIfdOffset = view.getUint32(tiffStart + 4, littleEndian);
            const { exifOffset, gpsOffset } = parseIfd(
              bytes,
              view,
              tiffStart,
              firstIfdOffset,
              littleEndian,
              IFD0_TAGS,
              'IFD0',
              tags
            );
            if (exifOffset !== null) {
              parseIfd(bytes, view, tiffStart, exifOffset, littleEndian, EXIF_SUB_TAGS, 'ExifIFD', tags);
            }
            if (gpsOffset !== null) {
              gpsCoordinates = parseGpsIfd(bytes, view, tiffStart, gpsOffset, littleEndian, tags);
            }
          }
        }
      }
      offset += 2 + segLen;
    }

    if (eoiEnd > 0 && eoiEnd < bytes.length) {
      trailingBytes = bytes.length - eoiEnd;
      const preview = readAscii(bytes, eoiEnd, Math.min(trailingBytes, 80));
      tags.push({
        id: 'TRAILER-EOI',
        group: 'TRAILER',
        name: 'Hidden Post-EOI Trailing Payload',
        value: `${trailingBytes} bytes${preview ? ` — "${preview}"` : ''}`,
        severity: 'CRITICAL'
      });
    }
  } else if (
    bytes.length >= 8 &&
    bytes[0] === 0x89 &&
    bytes[1] === 0x50 &&
    bytes[2] === 0x4e &&
    bytes[3] === 0x47
  ) {
    format = 'PNG';
    let offset = 8;
    while (offset + 12 <= bytes.length) {
      const length = view.getUint32(offset, false);
      const chunkType = readAscii(bytes, offset + 4, 4);
      const dataStart = offset + 8;
      if (dataStart + length + 4 > bytes.length) break;

      if (['tEXt', 'iTXt', 'zTXt', 'eXIf'].includes(chunkType)) {
        const snippet = readAscii(bytes, dataStart, Math.min(length, 100));
        tags.push({
          id: `PNG-${chunkType}-${offset}`,
          group: 'PNG_CHUNK',
          name: `PNG ${chunkType} Metadata Chunk`,
          value: snippet || `${length} binary bytes`,
          severity: chunkType === 'eXIf' ? 'CRITICAL' : 'HIGH'
        });
      }

      offset = dataStart + length + 4;
      if (chunkType === 'IEND') {
        if (offset < bytes.length) {
          trailingBytes = bytes.length - offset;
          tags.push({
            id: 'TRAILER-IEND',
            group: 'TRAILER',
            name: 'Hidden Post-IEND Trailing Payload',
            value: `${trailingBytes} appended bytes`,
            severity: 'CRITICAL'
          });
        }
        break;
      }
    }
  } else if (
    bytes.length >= 5 &&
    bytes[0] === 0x25 &&
    bytes[1] === 0x50 &&
    bytes[2] === 0x44 &&
    bytes[3] === 0x46 &&
    bytes[4] === 0x2d
  ) {
    format = 'PDF';
    const rawLatin = new TextDecoder('latin1').decode(bytes.slice(0, Math.min(bytes.length, 512_000)));
    const pdfActions: Array<{ key: string; regex: RegExp; label: string; severity: ExifTagEntry['severity'] }> = [
      { key: 'JS', regex: /\/(?:JavaScript|JS)\b/g, label: 'Embedded PDF JavaScript Trigger', severity: 'CRITICAL' },
      { key: 'OPENACTION', regex: /\/(?:OpenAction|AA)\b/g, label: 'Auto-Execute OpenAction / Additional Action', severity: 'CRITICAL' },
      { key: 'LAUNCH', regex: /\/Launch\b/g, label: 'External System Command /Launch Action', severity: 'CRITICAL' },
      { key: 'URI', regex: /\/URI\s*\(([^)]{1,120})\)/g, label: 'Embedded Outbound Phishing/Tracking URI', severity: 'HIGH' }
    ];
    for (const act of pdfActions) {
      const matches = [...rawLatin.matchAll(act.regex)];
      if (matches.length > 0) {
        const detail = act.key === 'URI' ? matches.map((m) => m[1]).slice(0, 3).join(', ') : `${matches.length} occurrence(s) in PDF object stream`;
        tags.push({
          id: `PDF-${act.key}`,
          group: 'PDF_ACTION',
          name: act.label,
          value: detail,
          severity: act.severity
        });
      }
    }
    const metaFields: Array<{ field: string; label: string; severity: ExifTagEntry['severity'] }> = [
      { field: 'Author', label: 'PDF Author Identity', severity: 'HIGH' },
      { field: 'Creator', label: 'Originating Software / OS', severity: 'MEDIUM' },
      { field: 'Producer', label: 'PDF Producer Pipeline', severity: 'MEDIUM' },
      { field: 'CreationDate', label: 'Document Creation Timestamp', severity: 'HIGH' }
    ];
    for (const mf of metaFields) {
      const m = rawLatin.match(new RegExp(`\\/${mf.field}\\s*\\(([^)]{1,140})\\)`));
      if (m && m[1].trim()) {
        tags.push({
          id: `PDF-META-${mf.field}`,
          group: 'PDF_META',
          name: mf.label,
          value: m[1].trim(),
          severity: mf.severity
        });
      }
    }
    const eofIdx = rawLatin.lastIndexOf('%%EOF');
    if (eofIdx > 0 && eofIdx + 6 < bytes.length) {
      trailingBytes = Math.max(0, bytes.length - (eofIdx + 6));
      if (trailingBytes > 4) {
        tags.push({
          id: 'TRAILER-PDF',
          group: 'TRAILER',
          name: 'Hidden Post-%%EOF Appended Bytes',
          value: `${trailingBytes} trailing bytes after %%EOF`,
          severity: 'CRITICAL'
        });
      }
    }
  }

  let riskScore = 0;
  for (const t of tags) {
    if (t.severity === 'CRITICAL') riskScore += 35;
    else if (t.severity === 'HIGH') riskScore += 16;
    else if (t.severity === 'MEDIUM') riskScore += 9;
    else riskScore += 4;
  }
  riskScore = Math.min(100, riskScore);

  const riskLevel: BinaryForensicReport['riskLevel'] =
    riskScore === 0
      ? 'CLEAN'
      : riskScore >= 75
        ? 'CRITICAL'
        : riskScore >= 45
          ? 'HIGH'
          : riskScore >= 20
            ? 'MEDIUM'
            : 'LOW';

  return {
    fileName,
    mimeType,
    byteLength: bytes.length,
    format,
    tags,
    gpsCoordinates,
    trailingBytes,
    riskScore,
    riskLevel,
    hexPreview: toHexPreview(bytes, 48),
    cloudBytesSent: 0
  };
}

/**
 * Splices a genuine Little-Endian TIFF/EXIF+GPS APP1 segment & optional post-EOI payload
 * into a standard JPEG ArrayBuffer so judges can test real binary parsing & exorcism in 1 click.
 */
export function spliceSyntheticExifAndTrailer(
  cleanJpegBuffer: ArrayBuffer,
  spec: {
    make: string;
    model: string;
    software: string;
    dateTime: string;
    artist: string;
    userComment: string;
    latDeg: [number, number, number];
    latRef: 'N' | 'S';
    lonDeg: [number, number, number];
    lonRef: 'E' | 'W';
    trailerText?: string;
  }
): ArrayBuffer {
  const src = new Uint8Array(cleanJpegBuffer);
  if (src.length < 4 || src[0] !== 0xff || src[1] !== 0xd8) return cleanJpegBuffer;

  const encoder = new TextEncoder();
  const makeB = encoder.encode(spec.make + '\0');
  const modelB = encoder.encode(spec.model + '\0');
  const softB = encoder.encode(spec.software + '\0');
  const dtB = encoder.encode(spec.dateTime + '\0');
  const artistB = encoder.encode(spec.artist + '\0');
  const commentB = encoder.encode(spec.userComment + '\0');

  // Build compact little-endian TIFF buffer (512 bytes is plenty)
  const tiff = new Uint8Array(512);
  const tv = new DataView(tiff.buffer);

  // TIFF Header: "II", 42, IFD0 at offset 8
  tv.setUint16(0, 0x4949, false);
  tv.setUint16(2, 42, true);
  tv.setUint32(4, 8, true);

  // IFD0: 7 entries -> 2 + 7*12 + 4 = 90 bytes (8..98)
  const ifd0Offset = 8;
  tv.setUint16(ifd0Offset, 7, true);

  // ExifIFD at 104: 2 entries -> 2 + 2*12 + 4 = 30 bytes (104..134)
  const exifIfdOffset = 104;
  // GPSIFD at 140: 4 entries -> 2 + 4*12 + 4 = 54 bytes (140..194)
  const gpsIfdOffset = 140;

  // Data area starts at 200
  let cursor = 200;
  const writeBytes = (arr: Uint8Array) => {
    const start = cursor;
    tiff.set(arr, cursor);
    cursor += arr.length + (arr.length % 2);
    return start;
  };
  const writeRationals = (dms: [number, number, number]) => {
    const start = cursor;
    for (const v of dms) {
      tv.setUint32(cursor, Math.round(v * 100), true);
      tv.setUint32(cursor + 4, 100, true);
      cursor += 8;
    }
    return start;
  };

  const makePos = writeBytes(makeB);
  const modelPos = writeBytes(modelB);
  const softPos = writeBytes(softB);
  const dtPos = writeBytes(dtB);
  const artistPos = writeBytes(artistB);
  const commentPos = writeBytes(commentB);
  const latPos = writeRationals(spec.latDeg);
  const lonPos = writeRationals(spec.lonDeg);

  const writeEntry = (base: number, idx: number, tag: number, type: number, count: number, val: number) => {
    const p = base + 2 + idx * 12;
    tv.setUint16(p, tag, true);
    tv.setUint16(p + 2, type, true);
    tv.setUint32(p + 4, count, true);
    tv.setUint32(p + 8, val, true);
  };

  writeEntry(ifd0Offset, 0, 0x010f, 2, makeB.length, makePos);
  writeEntry(ifd0Offset, 1, 0x0110, 2, modelB.length, modelPos);
  writeEntry(ifd0Offset, 2, 0x0131, 2, softB.length, softPos);
  writeEntry(ifd0Offset, 3, 0x0132, 2, dtB.length, dtPos);
  writeEntry(ifd0Offset, 4, 0x013b, 2, artistB.length, artistPos);
  writeEntry(ifd0Offset, 5, 0x8769, 4, 1, exifIfdOffset);
  writeEntry(ifd0Offset, 6, 0x8825, 4, 1, gpsIfdOffset);

  tv.setUint16(exifIfdOffset, 2, true);
  writeEntry(exifIfdOffset, 0, 0x9003, 2, dtB.length, dtPos);
  writeEntry(exifIfdOffset, 1, 0x9286, 7, commentB.length, commentPos);

  tv.setUint16(gpsIfdOffset, 4, true);
  const latRefCode = spec.latRef.charCodeAt(0);
  const lonRefCode = spec.lonRef.charCodeAt(0);
  writeEntry(gpsIfdOffset, 0, 0x0001, 2, 2, latRefCode);
  writeEntry(gpsIfdOffset, 1, 0x0002, 5, 3, latPos);
  writeEntry(gpsIfdOffset, 2, 0x0003, 2, 2, lonRefCode);
  writeEntry(gpsIfdOffset, 3, 0x0004, 5, 3, lonPos);

  const tiffTrimmed = tiff.slice(0, cursor);
  const exifPrefix = new Uint8Array([0x45, 0x78, 0x69, 0x66, 0x00, 0x00]); // Exif\0\0
  const app1Len = 2 + exifPrefix.length + tiffTrimmed.length;
  const app1 = new Uint8Array(2 + app1Len);
  app1[0] = 0xff;
  app1[1] = 0xe1;
  new DataView(app1.buffer).setUint16(2, app1Len, false);
  app1.set(exifPrefix, 4);
  app1.set(tiffTrimmed, 10);

  const trailerBytes = spec.trailerText ? encoder.encode(spec.trailerText) : new Uint8Array(0);
  const out = new Uint8Array(2 + app1.length + (src.length - 2) + trailerBytes.length);
  out[0] = 0xff;
  out[1] = 0xd8;
  out.set(app1, 2);
  out.set(src.slice(2), 2 + app1.length);
  if (trailerBytes.length > 0) {
    out.set(trailerBytes, 2 + app1.length + (src.length - 2));
  }
  return out.buffer;
}
