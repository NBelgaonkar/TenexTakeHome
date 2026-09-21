import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { fallbackExplanation, selectHitsForLlm } from "@/lib/anomaly/llm";
import { runAnomalyPipeline } from "@/lib/anomaly/pipeline";
import {
  DEFAULT_RULE_CONFIG,
  detectAnomalies,
  detectHighRequestRate,
  detectLargeTransfer,
  detectOffHours,
  detectRareDomain,
} from "@/lib/anomaly/rules";
import { parseLogFile } from "@/lib/parser/zscaler";
import type { LogEntry, RuleHit } from "@/lib/types";
import { LLM_ANOMALY_CAP } from "@/lib/types";

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
  it("collapses a violating window into one grouped hit", () => {
    const entries = Array.from({ length: 20 }, (_, i) =>
      entry({
        sourceIp: "10.9.9.9",
        destUrl: "https://www.office.com/",
        timestamp: new Date(Date.UTC(2024, 2, 11, 16, 0, i)).toISOString(),
      }),
    );
    const hits = detectHighRequestRate(entries, DEFAULT_RULE_CONFIG);
    expect(hits).toHaveLength(1);
    expect(hits[0]).toEqual({
      entryIndex: 0,
      rule: "high_request_rate",
      entryCount: 20,
      relatedEntryIndexes: Array.from({ length: 20 }, (_, i) => i),
    });
    const copy = fallbackExplanation("high_request_rate", entries[0], {
      entryCount: 20,
      rateWindowSeconds: DEFAULT_RULE_CONFIG.rateWindowSeconds,
    });
    expect(copy.explanation).toBe(
      "IP 10.9.9.9 made 20 requests to https://www.office.com/ in under 60 seconds.",
    );
  });

  it("emits one grouped hit per contiguous violating window", () => {
    const burst = (startSec: number) =>
      Array.from({ length: 20 }, (_, i) =>
        entry({
          sourceIp: "10.9.9.9",
          timestamp: new Date(
            Date.UTC(2024, 2, 11, 16, 0, startSec + i),
          ).toISOString(),
        }),
      );
    const entries = [...burst(0), ...burst(120)];
    const hits = detectHighRequestRate(entries, DEFAULT_RULE_CONFIG);
    expect(hits).toHaveLength(2);
    expect(hits[0].entryIndex).toBe(0);
    expect(hits[0].entryCount).toBe(20);
    expect(hits[1].entryIndex).toBe(20);
    expect(hits[1].entryCount).toBe(20);
  });

  it("does not flag a window below the threshold", () => {
    const entries = Array.from({ length: 19 }, (_, i) =>
      entry({
        sourceIp: "10.9.9.9",
        timestamp: new Date(Date.UTC(2024, 2, 11, 16, 0, i)).toISOString(),
      }),
    );
    expect(detectHighRequestRate(entries, DEFAULT_RULE_CONFIG)).toEqual([]);
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

describe("anomalous traffic fixture", () => {
  const file = readFileSync(
    path.join(process.cwd(), "sample-logs", "anomalous.log"),
    "utf8",
  );
  const { entries } = parseLogFile(file);

  it("groups two distinct high_request_rate bursts", () => {
    const rateHits = detectHighRequestRate(entries, DEFAULT_RULE_CONFIG);
    expect(rateHits).toHaveLength(2);
    const bursts = rateHits.map((hit) => ({
      ip: entries[hit.entryIndex].sourceIp,
      dest: entries[hit.entryIndex].destUrl,
      count: hit.entryCount,
    }));
    expect(bursts).toEqual(
      expect.arrayContaining([
        {
          ip: "10.9.9.9",
          dest: "https://www.office.com/",
          count: 25,
        },
        {
          ip: "10.4.4.20",
          dest: "https://login.salesforce.com/",
          count: 28,
        },
      ]),
    );
  });

  it("still flags the original off-hours GitHub access", () => {
    const hits = detectOffHours(entries, DEFAULT_RULE_CONFIG);
    const urls = hits.map((hit) => entries[hit.entryIndex].destUrl);
    expect(hits.length).toBeGreaterThanOrEqual(4);
    expect(urls.every((url) => url.includes("github.com"))).toBe(true);
  });

  it("flags original and additional rare domains, including a non-xyz denylist TLD", () => {
    const hits = detectRareDomain(entries, DEFAULT_RULE_CONFIG);
    const urls = hits.map((hit) => entries[hit.entryIndex].destUrl);
    expect(urls).toEqual(
      expect.arrayContaining([
        "https://steal-session.xyz/login",
        "https://portal.docusign.net/signing",
        "https://status.pagerduty.com/",
        "https://payload-cdn.click/beacon",
      ]),
    );
    expect(urls.some((url) => url.includes(".xyz"))).toBe(true);
    expect(urls.some((url) => url.includes(".click"))).toBe(true);
  });

  it("flags the ~50MB export and not the Zoom recording below the 5MB floor", () => {
    const hits = detectLargeTransfer(entries, DEFAULT_RULE_CONFIG);
    const flaggedUrls = hits.map((hit) => entries[hit.entryIndex].destUrl);
    expect(flaggedUrls).toContain("https://www.office.com/share/export");
    expect(flaggedUrls.some((url) => url.includes("zoom.us"))).toBe(false);

    const zoom = entries.find((e) =>
      e.destUrl.includes("zoom.us/recording/download"),
    );
    expect(zoom).toBeDefined();
    const total = (zoom?.bytesSent ?? 0) + (zoom?.bytesReceived ?? 0);
    // Typical session rows are ~10KB, so max(10×median, 5MB) is the 5MB floor.
    // This ~4.2MB Zoom recording must stay unflagged; 15–20MB would not.
    expect(total).toBeGreaterThan(3 * 1024 * 1024);
    expect(total).toBeLessThan(DEFAULT_RULE_CONFIG.transferFloorBytes);
  });

  it("yields all four rule types", () => {
    const rules = new Set(
      detectAnomalies(entries, DEFAULT_RULE_CONFIG).map((hit) => hit.rule),
    );
    expect(rules.has("high_request_rate")).toBe(true);
    expect(rules.has("off_hours")).toBe(true);
    expect(rules.has("large_transfer")).toBe(true);
    expect(rules.has("rare_domain")).toBe(true);
  });
});

describe("LLM cap", () => {
  it("persists every Stage 1 hit, including large_transfer and rare_domain past 25 off_hours", async () => {
    const previousKey = process.env.ANTHROPIC_API_KEY;
    delete process.env.ANTHROPIC_API_KEY;

    try {
      const weekend = Array.from({ length: 26 }, (_, i) =>
        entry({
          timestamp: new Date(Date.UTC(2024, 2, 16, 12, i * 2, 0)).toISOString(),
          destUrl: "https://www.google.com/",
        }),
      );
      const large = entry({
        timestamp: "2024-03-11T15:00:00.000Z",
        destUrl: "https://www.google.com/",
        bytesSent: 1024,
        bytesReceived: 50 * 1024 * 1024,
      });
      const rare = entry({
        timestamp: "2024-03-11T15:05:00.000Z",
        destUrl: "https://steal-session.xyz/login",
      });
      const entries = [...weekend, large, rare];
      const hits = detectAnomalies(entries, DEFAULT_RULE_CONFIG);
      expect(hits.length).toBeGreaterThan(25);
      expect(hits.some((hit) => hit.rule === "off_hours")).toBe(true);
      expect(hits.some((hit) => hit.rule === "large_transfer")).toBe(true);
      expect(hits.some((hit) => hit.rule === "rare_domain")).toBe(true);

      const withIds = entries.map((row, index) => ({ ...row, id: index + 1 }));
      const rows = await runAnomalyPipeline("test-session", withIds);
      expect(rows).toHaveLength(hits.length);
      expect(rows.some((row) => row.rule_triggered === "large_transfer")).toBe(
        true,
      );
      expect(rows.some((row) => row.rule_triggered === "rare_domain")).toBe(
        true,
      );
    } finally {
      if (previousKey === undefined) {
        delete process.env.ANTHROPIC_API_KEY;
      } else {
        process.env.ANTHROPIC_API_KEY = previousKey;
      }
    }
  });

  it("selectHitsForLlm never exceeds the cap and ranks large_transfer ahead of off_hours", () => {
    const hits: RuleHit[] = [
      ...Array.from({ length: 30 }, (_, i) => ({
        entryIndex: i,
        rule: "off_hours" as const,
      })),
      { entryIndex: 30, rule: "large_transfer" },
    ];
    const selected = selectHitsForLlm(hits, LLM_ANOMALY_CAP);
    expect(selected.length).toBeLessThanOrEqual(LLM_ANOMALY_CAP);
    expect(selected).toHaveLength(LLM_ANOMALY_CAP);
    expect(selected[0].rule).toBe("large_transfer");
    expect(selected.slice(1).every((hit) => hit.rule === "off_hours")).toBe(
      true,
    );
  });
});
