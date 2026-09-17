import { ALLOWED_EXTENSIONS, MAX_UPLOAD_BYTES } from "@/lib/types";

const DENY_MAGIC: number[][] = [
  [0x89, 0x50, 0x4e, 0x47], // PNG
  [0xff, 0xd8, 0xff], // JPEG
  [0x25, 0x50, 0x44, 0x46], // PDF
  [0x50, 0x4b, 0x03, 0x04], // ZIP
  [0x1f, 0x8b], // gzip
  [0x7f, 0x45, 0x4c, 0x46], // ELF
];

export type UploadValidation =
  | { ok: true; filename: string; bytes: Buffer }
  | { ok: false; error: string };

export async function validateUpload(file: File): Promise<UploadValidation> {
  const filename = sanitizeFilename(file.name);

  if (!hasAllowedExtension(filename)) {
    return {
      ok: false,
      error: `File extension not allowed. Use ${ALLOWED_EXTENSIONS.join(" or ")}.`,
    };
  }

  if (file.size <= 0) {
    return { ok: false, error: "File is empty." };
  }

  if (file.size > MAX_UPLOAD_BYTES) {
    return {
      ok: false,
      error: `File exceeds the ${MAX_UPLOAD_BYTES / (1024 * 1024)}MB size cap.`,
    };
  }

  const declared = (file.type || "").toLowerCase();
  if (
    declared &&
    declared !== "text/plain" &&
    declared !== "application/octet-stream"
  ) {
    return {
      ok: false,
      error: `Unexpected Content-Type "${file.type}". Expected text/plain.`,
    };
  }

  const bytes = Buffer.from(await file.arrayBuffer());
  if (!looksLikeTextLog(bytes)) {
    return {
      ok: false,
      error: "File does not look like a text log (binary/magic-byte check failed).",
    };
  }

  return { ok: true, filename, bytes };
}

export function looksLikeTextLog(bytes: Buffer): boolean {
  if (bytes.length === 0) return false;
  if (bytes.includes(0)) return false;

  for (const sig of DENY_MAGIC) {
    if (sig.every((b, i) => bytes[i] === b)) return false;
  }

  const sample = bytes.subarray(0, Math.min(bytes.length, 8192));
  let printable = 0;
  for (let i = 0; i < sample.length; i += 1) {
    const byte = sample[i];
    if (
      byte === 9 ||
      byte === 10 ||
      byte === 13 ||
      (byte >= 32 && byte < 127) ||
      byte >= 128
    ) {
      printable += 1;
    }
  }
  if (printable / sample.length < 0.85) return false;

  try {
    new TextDecoder("utf-8", { fatal: false }).decode(sample);
  } catch {
    return false;
  }

  return true;
}

function hasAllowedExtension(filename: string): boolean {
  const lower = filename.toLowerCase();
  return ALLOWED_EXTENSIONS.some((ext) => lower.endsWith(ext));
}

function sanitizeFilename(name: string): string {
  const base = name.replace(/\\/g, "/").split("/").pop() ?? "upload.log";
  const cleaned = base.replace(/[^a-zA-Z0-9._-]/g, "_");
  return cleaned.length > 0 ? cleaned.slice(0, 180) : "upload.log";
}
