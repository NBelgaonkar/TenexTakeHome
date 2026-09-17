import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  DEFAULT_RULE_CONFIG,
  detectAnomalies,
  detectHighRequestRate,
  detectLargeTransfer,
  detectOffHours,
  detectRareDomain,
} from "@/lib/anomaly/rules";
import { parseLogFile } from "@/lib/parser/zscaler";
import type { LogEntry } from "@/lib/types";

function entry(overrides: Partial<LogEntry>): LogEntry {
  return {
    timestamp: "2024-03-11T15:00:00.000Z",
    sourceIp: "10.0.0.1",
    destUrl: "https://www.google.com/",
    action: "allowed",
    bytesSent: 500,
    bytesReceived: 1500,
    userAgent: "Mozilla/5.0",
    rawLine: "raw",
    ...overrides,
  };
}

describe("high_request_rate", () => {
  it("flags every event in a window that exceeds the threshold", () => {
    const entries = Array.from({ length: 20 }, (_, i) =>
      entry({
        sourceIp: "10.9.9.9",
        timestamp: new Date(Date.UTC(2024, 2, 11, 16, 0, i)).toISOString(),
      }),
    );
    const hits = detectHighRequestRate(entries, DEFAULT_RULE_CONFIG);
    expect(hits).toHaveLength(20);
    expect(hits.every((h) => h.rule === "high_request_rate")).toBe(true);
  });
});

describe("off_hours", () => {
  it("flags activity outside weekday business hours in America/New_York", () => {
    const entries = [
      entry({ timestamp: "2024-03-12T07:15:00.000Z" }), // 03:15 EDT Tuesday
    ];
    const hits = detectOffHours(entries, DEFAULT_RULE_CONFIG);
    expect(hits).toEqual([{ entryIndex: 0, rule: "off_hours" }]);
  });

  it("does not flag weekday business-hours traffic", () => {
    const entries = [entry({ timestamp: "2024-03-11T15:00:00.000Z" })];
    expect(detectOffHours(entries, DEFAULT_RULE_CONFIG)).toEqual([]);
  });
});

describe("large_transfer", () => {
  it("flags transfers at or above max(10x median, 5MB)", () => {
    const entries = [
      ...Array.from({ length: 10 }, () =>
        entry({ bytesSent: 400, bytesReceived: 600 }),
      ),
      entry({ bytesSent: 1024, bytesReceived: 8 * 1024 * 1024 }),
    ];
    const hits = detectLargeTransfer(entries, DEFAULT_RULE_CONFIG);
    expect(hits).toEqual([{ entryIndex: 10, rule: "large_transfer" }]);
  });
});

describe("rare_domain", () => {
  it("flags a first-seen domain and a denylisted TLD", () => {
    const entries = [
      entry({ destUrl: "https://www.google.com/" }),
      entry({ destUrl: "https://www.google.com/search" }),
      entry({ destUrl: "https://steal-session.xyz/login" }),
    ];
    const hits = detectRareDomain(entries, DEFAULT_RULE_CONFIG);
    expect(hits).toEqual([{ entryIndex: 2, rule: "rare_domain" }]);
  });
});

describe("normal traffic fixture", () => {
  it("does not false-positive on sample-logs/normal.log", () => {
    const file = readFileSync(
      path.join(process.cwd(), "sample-logs", "normal.log"),
      "utf8",
    );
    const { entries } = parseLogFile(file);
    expect(entries.length).toBeGreaterThan(0);
    expect(detectAnomalies(entries, DEFAULT_RULE_CONFIG)).toEqual([]);
  });
});
