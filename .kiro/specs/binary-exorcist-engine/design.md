# Technical Design — Binary Exorcist & Synthetic Specimen Engine

## JPEG APP1 Exif Binary Splice Structure
1. Start with standard JPEG SOI (`0xFF 0xD8`) from Canvas `toBlob('image/jpeg', 0.92)`.
2. Construct a valid Little-Endian (`II`, `0x49 0x49`, magic `0x002A`) TIFF structure containing:
   - `IFD0`: `Make (0x010F)`, `Model (0x0110)`, `Software (0x0131)`, `DateTime (0x0132)`, `ExifIFDPointer (0x8769)`, `GPSInfoIFDPointer (0x8825)`
   - `ExifIFD`: `DateTimeOriginal (0x9003)`, `UserComment (0x9286)`
   - `GPSIFD`: `GPSLatitudeRef (0x0001)`, `GPSLatitude (0x0002)`, `GPSLongitudeRef (0x0003)`, `GPSLongitude (0x0004)`
3. Wrap TIFF inside `0xFF 0xE1 [2-byte big-endian length] "Exif\0\0" [TIFF bytes]` immediately after `0xFF 0xD8`.
4. Optionally append a realistic trailing marker payload after `0xFF 0xD9` to demonstrate hidden post-EOI data detection.
5. Re-encode cleanly via Canvas during Exorcism so the browser's native JPEG/PNG encoder discards every non-pixel segment and trailing byte, then independently verify `tags.length === 0 && trailingBytes === 0`.
