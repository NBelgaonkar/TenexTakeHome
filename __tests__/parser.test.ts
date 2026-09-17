import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { parseLogFile, parseLogLine } from "@/lib/parser/zscaler";

const SAMPLE = `Mon Oct 16 22:55:48 2023\tGMT\t10.1.2.3\tjdoe@corp.com\thttps://www.office.com/\tAllowed\t1234\t56780\tMozilla/5.0 (Windows NT 10.0; Win64; x64)`;

describe("parseLogLine", () => {
  it("extracts NSS web fields into LogEntry", () => {
    const entry = parseLogLine(SAMPLE);
    expect(entry).not.toBeNull();
    expect(entry?.sourceIp).toBe("10.1.2.3");
    expect(entry?.destUrl).toBe("https://www.office.com/");
    expect(entry?.action).toBe("allowed");
    expect(entry?.bytesSent).toBe(1234);
    expect(entry?.bytesReceived).toBe(56780);
    expect(entry?.userAgent).toContain("Mozilla/5.0");
    expect(entry?.timestamp).toBe("2023-10-16T22:55:48.000Z");
    expect(entry?.rawLine).toBe(SAMPLE);
  });

  it("returns null for a malformed line (too few fields)", () => {
    const malformed = "Mon Oct 16 22:55:48 2023 this is not an NSS row";
    expect(parseLogLine(malformed)).toBeNull();
  });

  it("returns null for an invalid timestamp", () => {
    const bad = `not-a-date\tGMT\t10.1.2.3\tuser\thttps://example.com/\tAllowed\t1\t2\tUA`;
    expect(parseLogLine(bad)).toBeNull();
  });

  it("returns null for a non-IP client field", () => {
    const bad = `Mon Oct 16 22:55:48 2023\tGMT\tnot-an-ip\tuser\thttps://example.com/\tAllowed\t1\t2\tUA`;
    expect(parseLogLine(bad)).toBeNull();
  });
});

describe("parseLogFile", () => {
  it("skips empty lines and counts malformed rows", () => {
    const content = `${SAMPLE}\n\nnot-valid\n${SAMPLE}\n`;
    const result = parseLogFile(content);
    expect(result.entries).toHaveLength(2);
    expect(result.skipped).toBe(1);
  });

  it("parses the committed normal.log fixture", () => {
    const file = readFileSync(
      path.join(process.cwd(), "sample-logs", "normal.log"),
      "utf8",
    );
    const result = parseLogFile(file);
    expect(result.skipped).toBe(0);
    expect(result.entries.length).toBeGreaterThanOrEqual(150);
    expect(result.entries.length).toBeLessThanOrEqual(200);
  });
});
