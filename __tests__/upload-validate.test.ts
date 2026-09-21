import { describe, expect, it } from "vitest";
import { looksLikeTextLog, validateUpload } from "@/lib/upload/validate";
import { MAX_UPLOAD_BYTES } from "@/lib/types";

function makeFile(
  name: string,
  content: string | Uint8Array,
  type = "text/plain",
): File {
  const parts =
    typeof content === "string" ? [content] : [new Uint8Array(content)];
  return new File(parts, name, { type });
}

describe("looksLikeTextLog", () => {
  it("accepts UTF-8 text with tabs and CRLF line endings", () => {
    const bytes = Buffer.from("col1\tcol2\r\nnext\tline\r\n", "utf8");
    expect(looksLikeTextLog(bytes)).toBe(true);
  });

  it("rejects NUL bytes anywhere in the file", () => {
    const bytes = Buffer.concat([
      Buffer.alloc(100, 0x61),
      Buffer.from([0]),
      Buffer.alloc(100, 0x61),
    ]);
    expect(looksLikeTextLog(bytes)).toBe(false);
  });

  it("rejects PNG and PDF magic-byte headers", () => {
    expect(looksLikeTextLog(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d]))).toBe(
      false,
    );
    expect(looksLikeTextLog(Buffer.from([0x25, 0x50, 0x44, 0x46, 0x2d]))).toBe(
      false,
    );
  });

  it("accepts printable first 8KB followed by non-NUL binary (printable check is chunked)", () => {
    const head = Buffer.alloc(8192, 0x61);
    const tail = Buffer.alloc(200, 0x01);
    expect(looksLikeTextLog(Buffer.concat([head, tail]))).toBe(true);
  });

  it("rejects a file that is printable in the first 8KB then contains a NUL", () => {
    const head = Buffer.alloc(8192, 0x61);
    const tail = Buffer.from([0x00, 0x61]);
    expect(looksLikeTextLog(Buffer.concat([head, tail]))).toBe(false);
  });
});

describe("validateUpload", () => {
  it("accepts a valid .log and a valid .txt with text content", async () => {
    const log = await validateUpload(
      makeFile("session.log", "Mon Oct 16 22:55:48 2023\tGMT\t10.1.2.3\n"),
    );
    const txt = await validateUpload(
      makeFile("session.txt", "hello world\n"),
    );
    expect(log.ok).toBe(true);
    expect(txt.ok).toBe(true);
  });

  it("rejects wrong extensions including a double extension", async () => {
    for (const name of ["notes.pdf", "photo.png", "setup.exe", "a.log.exe"]) {
      const result = await validateUpload(makeFile(name, "not a log"));
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toMatch(/extension/i);
      }
    }
  });

  it("rejects files over the size cap and accepts exactly at the cap", async () => {
    const atCap = await validateUpload(
      makeFile("ok.log", Buffer.alloc(MAX_UPLOAD_BYTES, 0x61)),
    );
    expect(atCap.ok).toBe(true);

    const over = await validateUpload(
      makeFile("big.log", Buffer.alloc(MAX_UPLOAD_BYTES + 1, 0x61)),
    );
    expect(over.ok).toBe(false);
    if (!over.ok) {
      expect(over.error).toMatch(/size cap/i);
    }
  });

  it("rejects an empty file", async () => {
    const result = await validateUpload(makeFile("empty.log", ""));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe("File is empty.");
    }
  });

  it("rejects a disallowed declared Content-Type", async () => {
    const result = await validateUpload(
      makeFile("ok.log", "hello\n", "application/pdf"),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toMatch(/Content-Type/i);
    }
  });

  it("rejects binary content renamed to .log (NUL bytes and PNG/PDF magic)", async () => {
    const withNul = await validateUpload(
      makeFile("payload.log", Buffer.from("hello\0world")),
    );
    expect(withNul.ok).toBe(false);

    const png = Buffer.from([
      0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
    ]);
    const pngRenamed = await validateUpload(makeFile("photo.log", png));
    expect(pngRenamed.ok).toBe(false);

    const pdf = Buffer.from("%PDF-1.4\n1 0 obj\n", "binary");
    const pdfRenamed = await validateUpload(makeFile("doc.log", pdf));
    expect(pdfRenamed.ok).toBe(false);
  });

  it("accepts UTF-8 text with tabs and CRLF through validateUpload", async () => {
    const result = await validateUpload(
      makeFile("ua.log", "user\tagent\r\nsecond\tline\r\n"),
    );
    expect(result.ok).toBe(true);
  });
});
