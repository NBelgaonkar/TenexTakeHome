import type { LogEntry } from "@/lib/types";

const IPV4 =
  /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const IPV6 = /^[0-9a-f:]+$/i;

export interface ParseResult {
  entries: LogEntry[];
  skipped: number;
}

/**
 * ZScaler NSS Web feed (custom, documented subset).
 *
 * Feed Output Format:
 *   %s{time}\t%s{tz}\t%s{cip}\t%s{login}\t%s{url}\t%s{action}\t%d{reqsize}\t%d{respsize}\t%s{ua}
 *
 * Tabs delimit fields so URLs and user-agents may contain spaces.
 * `login` is consumed for realism then dropped from LogEntry.
 */
export function parseLogLine(rawLine: string): LogEntry | null {
  const line = rawLine.replace(/\s+$/, "");
  if (line.trim() === "") return null;

  const parts = line.split("\t");
  if (parts.length < 9) return null;

  const time = parts[0]?.trim() ?? "";
  const tz = parts[1]?.trim() ?? "";
  const sourceIp = parts[2]?.trim() ?? "";
  const destUrl = parts[4]?.trim() ?? "";
  const actionRaw = parts[5]?.trim() ?? "";
  const bytesSentRaw = parts[6]?.trim() ?? "";
  const bytesReceivedRaw = parts[7]?.trim() ?? "";
  const userAgent = parts.slice(8).join("\t").trim();

  if (!time || !sourceIp || !destUrl || !actionRaw) return null;
  if (!isIp(sourceIp)) return null;

  const timestamp = parseNssTimestamp(time, tz);
  if (!timestamp) return null;

  const bytesSent = Number.parseInt(bytesSentRaw, 10);
  const bytesReceived = Number.parseInt(bytesReceivedRaw, 10);
  if (!Number.isFinite(bytesSent) || bytesSent < 0) return null;
  if (!Number.isFinite(bytesReceived) || bytesReceived < 0) return null;

  return {
    timestamp,
    sourceIp,
    destUrl,
    action: actionRaw.toLowerCase(),
    bytesSent,
    bytesReceived,
    userAgent,
    rawLine: line,
  };
}

export function parseLogFile(content: string): ParseResult {
  const entries: LogEntry[] = [];
  let skipped = 0;

  for (const rawLine of content.split(/\r?\n/)) {
    if (rawLine.trim() === "") continue;
    const parsed = parseLogLine(rawLine);
    if (!parsed) {
      skipped += 1;
      continue;
    }
    entries.push(parsed);
  }

  return { entries, skipped };
}

function parseNssTimestamp(time: string, tz: string): string | null {
  const zone = tz || "GMT";
  const parsed = new Date(`${time} ${zone}`);
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed.toISOString();
}

function isIp(value: string): boolean {
  if (IPV4.test(value)) return true;
  return value.includes(":") && IPV6.test(value) && value.length >= 3;
}
