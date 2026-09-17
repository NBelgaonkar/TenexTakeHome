import { parse as parseDomain } from "tldts";
import type { LogEntry, RuleHit } from "@/lib/types";

export interface RuleConfig {
  rateThreshold: number;
  rateWindowSeconds: number;
  timezone: string;
  businessStartHour: number;
  businessEndHour: number;
  transferMedianMultiplier: number;
  transferFloorBytes: number;
  suspiciousTlds: string[];
}

export const DEFAULT_RULE_CONFIG: RuleConfig = {
  rateThreshold: 20,
  rateWindowSeconds: 60,
  timezone: "America/New_York",
  businessStartHour: 8,
  businessEndHour: 18,
  transferMedianMultiplier: 10,
  transferFloorBytes: 5 * 1024 * 1024,
  suspiciousTlds: ["xyz", "tk", "top", "click", "gq", "ml", "cf", "zip"],
};

export function loadRuleConfigFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): RuleConfig {
  return {
    ...DEFAULT_RULE_CONFIG,
    timezone: env.ANOMALY_OFF_HOURS_TZ || DEFAULT_RULE_CONFIG.timezone,
    businessStartHour: readInt(
      env.ANOMALY_BUSINESS_START_HOUR,
      DEFAULT_RULE_CONFIG.businessStartHour,
    ),
    businessEndHour: readInt(
      env.ANOMALY_BUSINESS_END_HOUR,
      DEFAULT_RULE_CONFIG.businessEndHour,
    ),
    rateThreshold: readInt(
      env.ANOMALY_RATE_THRESHOLD,
      DEFAULT_RULE_CONFIG.rateThreshold,
    ),
    rateWindowSeconds: readInt(
      env.ANOMALY_RATE_WINDOW_SECONDS,
      DEFAULT_RULE_CONFIG.rateWindowSeconds,
    ),
    transferMedianMultiplier: readInt(
      env.ANOMALY_TRANSFER_MEDIAN_MULTIPLIER,
      DEFAULT_RULE_CONFIG.transferMedianMultiplier,
    ),
    transferFloorBytes: readInt(
      env.ANOMALY_TRANSFER_FLOOR_BYTES,
      DEFAULT_RULE_CONFIG.transferFloorBytes,
    ),
  };
}

export function detectAnomalies(
  entries: LogEntry[],
  config: RuleConfig = DEFAULT_RULE_CONFIG,
): RuleHit[] {
  const hits: RuleHit[] = [];
  hits.push(...detectHighRequestRate(entries, config));
  hits.push(...detectOffHours(entries, config));
  hits.push(...detectLargeTransfer(entries, config));
  hits.push(...detectRareDomain(entries, config));
  return hits.sort((a, b) => a.entryIndex - b.entryIndex || a.rule.localeCompare(b.rule));
}

export function detectHighRequestRate(
  entries: LogEntry[],
  config: RuleConfig = DEFAULT_RULE_CONFIG,
): RuleHit[] {
  const byIp = new Map<string, number[]>();
  entries.forEach((entry, index) => {
    const list = byIp.get(entry.sourceIp) ?? [];
    list.push(index);
    byIp.set(entry.sourceIp, list);
  });

  const flagged = new Set<number>();
  const windowMs = config.rateWindowSeconds * 1000;

  byIp.forEach((indexes) => {
    const sorted = indexes.slice().sort(
      (a, b) =>
        new Date(entries[a].timestamp).getTime() -
        new Date(entries[b].timestamp).getTime(),
    );
    let left = 0;
    for (let right = 0; right < sorted.length; right += 1) {
      const rightTs = new Date(entries[sorted[right]].timestamp).getTime();
      while (
        rightTs - new Date(entries[sorted[left]].timestamp).getTime() >
        windowMs
      ) {
        left += 1;
      }
      if (right - left + 1 >= config.rateThreshold) {
        for (let i = left; i <= right; i += 1) {
          flagged.add(sorted[i]);
        }
      }
    }
  });

  return Array.from(flagged)
    .sort((a, b) => a - b)
    .map((entryIndex) => ({ entryIndex, rule: "high_request_rate" as const }));
}

export function detectOffHours(
  entries: LogEntry[],
  config: RuleConfig = DEFAULT_RULE_CONFIG,
): RuleHit[] {
  const hits: RuleHit[] = [];
  entries.forEach((entry, entryIndex) => {
    if (isOffHours(entry.timestamp, config)) {
      hits.push({ entryIndex, rule: "off_hours" });
    }
  });
  return hits;
}

export function detectLargeTransfer(
  entries: LogEntry[],
  config: RuleConfig = DEFAULT_RULE_CONFIG,
): RuleHit[] {
  if (entries.length === 0) return [];
  const totals = entries.map((e) => e.bytesSent + e.bytesReceived);
  const median = medianOf(totals);
  const threshold = Math.max(
    median * config.transferMedianMultiplier,
    config.transferFloorBytes,
  );
  const hits: RuleHit[] = [];
  totals.forEach((total, entryIndex) => {
    if (total >= threshold) {
      hits.push({ entryIndex, rule: "large_transfer" });
    }
  });
  return hits;
}

export function detectRareDomain(
  entries: LogEntry[],
  config: RuleConfig = DEFAULT_RULE_CONFIG,
): RuleHit[] {
  const denylist = new Set(config.suspiciousTlds.map((t) => t.toLowerCase()));
  const counts = new Map<string, number>();
  const domains = entries.map((entry) => registrableDomain(entry.destUrl));

  for (const domain of domains) {
    if (!domain) continue;
    counts.set(domain, (counts.get(domain) ?? 0) + 1);
  }

  const hits: RuleHit[] = [];
  domains.forEach((domain, entryIndex) => {
    if (!domain) return;
    const tld = tldOf(entries[entryIndex].destUrl);
    const rare = counts.get(domain) === 1;
    const suspicious = tld !== null && denylist.has(tld);
    if (rare || suspicious) {
      hits.push({ entryIndex, rule: "rare_domain" });
    }
  });
  return hits;
}

export function registrableDomain(url: string): string | null {
  const parsed = parseDomain(withProtocol(url));
  return parsed.domain;
}

export function tldOf(url: string): string | null {
  const parsed = parseDomain(withProtocol(url));
  return parsed.publicSuffix ? parsed.publicSuffix.toLowerCase() : null;
}

function withProtocol(url: string): string {
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(url)) return url;
  return `https://${url}`;
}

function isOffHours(iso: string, config: RuleConfig): boolean {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return false;

  const parts = nyParts(date, config.timezone);
  if (parts.weekday === 0 || parts.weekday === 6) return true;
  return parts.hour < config.businessStartHour || parts.hour >= config.businessEndHour;
}

function nyParts(
  date: Date,
  timeZone: string,
): { weekday: number; hour: number } {
  const fmt = new Intl.DateTimeFormat("en-US", {
    timeZone,
    weekday: "short",
    hour: "numeric",
    hourCycle: "h23",
  });
  const map = Object.fromEntries(
    fmt.formatToParts(date).map((p) => [p.type, p.value]),
  );
  const weekdayName = map.weekday ?? "";
  const weekdayLookup: Record<string, number> = {
    Sun: 0,
    Mon: 1,
    Tue: 2,
    Wed: 3,
    Thu: 4,
    Fri: 5,
    Sat: 6,
  };
  return {
    weekday: weekdayLookup[weekdayName] ?? 1,
    hour: Number.parseInt(map.hour ?? "0", 10),
  };
}

function medianOf(values: number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  if (sorted.length % 2 === 0) {
    return (sorted[mid - 1] + sorted[mid]) / 2;
  }
  return sorted[mid];
}

function readInt(raw: string | undefined, fallback: number): number {
  if (!raw) return fallback;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) ? n : fallback;
}
