"use client";

import dynamic from "next/dynamic";
import { useCallback, useEffect, useMemo, useState } from "react";
import { SeverityBadge } from "@/components/severity-badge";
import { formatBytes, formatTimestamp } from "@/lib/format";
import { ruleLabel } from "@/lib/anomaly/labels";
import type { AnomalyRule, TimelineBucket } from "@/lib/types";

const TimelineChart = dynamic(
  () => import("@/components/timeline-chart").then((m) => m.TimelineChart),
  { ssr: false, loading: () => <div className="h-64 animate-pulse rounded-lg bg-ink-700/50" /> },
);

interface SummaryResponse {
  session: {
    id: string;
    filename: string;
    uploadedAt: string;
    status: string;
    totalEntries: number;
    anomalyCount: number;
  };
  stats: {
    totalEvents: number;
    uniqueSourceIps: number;
    anomalyCount: number;
    dateRange: { start: string | null; end: string | null };
  };
  timeline: TimelineBucket[];
  entries: EntryRow[];
  pagination: { limit: number; offset: number; total: number };
  error?: string;
}

interface EntryRow {
  id: number;
  timestamp: string;
  sourceIp: string;
  destUrl: string;
  action: string;
  bytesSent: number;
  bytesReceived: number;
  userAgent: string;
  rawLine: string;
  anomaly: { rules: string[]; maxSeverity: string } | null;
}

interface AnomalyRow {
  id: number;
  entryId: number;
  ruleTriggered: AnomalyRule;
  explanation: string | null;
  confidence: number | null;
  recommendedAction: string | null;
  severity: string;
  entry: {
    id: number;
    timestamp: string;
    sourceIp: string;
    destUrl: string;
    action: string;
    bytesSent: number;
    bytesReceived: number;
    userAgent: string;
  } | null;
}

type SortKey = "timestamp" | "sourceIp" | "action" | "bytes";

export function ResultsView({ sessionId }: { sessionId: string }) {
  const [summary, setSummary] = useState<SummaryResponse | null>(null);
  const [anomalies, setAnomalies] = useState<AnomalyRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState("");
  const [actionFilter, setActionFilter] = useState("all");
  const [anomaliesOnly, setAnomaliesOnly] = useState(false);
  const [sortKey, setSortKey] = useState<SortKey>("timestamp");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [expanded, setExpanded] = useState<number | null>(null);
  const [offset, setOffset] = useState(0);

  const load = useCallback(async () => {
    setError(null);
    const [summaryRes, anomalyRes] = await Promise.all([
      fetch(`/api/logs/${sessionId}/summary?limit=200&offset=${offset}`),
      fetch(`/api/logs/${sessionId}/anomalies`),
    ]);
    const summaryJson = (await summaryRes.json()) as SummaryResponse;
    const anomalyJson = (await anomalyRes.json()) as {
      anomalies?: AnomalyRow[];
      error?: string;
    };
    if (!summaryRes.ok) {
      setError(summaryJson.error ?? "Failed to load summary.");
      return;
    }
    if (!anomalyRes.ok) {
      setError(anomalyJson.error ?? "Failed to load anomalies.");
      return;
    }
    setSummary(summaryJson);
    setAnomalies(anomalyJson.anomalies ?? []);
  }, [sessionId, offset]);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    load()
      .catch(() => {
        if (!cancelled) setError("Network error.");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [load]);

  const anomalyByEntry = useMemo(() => {
    const map = new Map<number, AnomalyRow[]>();
    for (const row of anomalies) {
      const list = map.get(row.entryId) ?? [];
      list.push(row);
      map.set(row.entryId, list);
    }
    return map;
  }, [anomalies]);

  const actions = useMemo(() => {
    const set = new Set((summary?.entries ?? []).map((e) => e.action).filter(Boolean));
    return Array.from(set).sort();
  }, [summary]);

  const rows = useMemo(() => {
    let list = [...(summary?.entries ?? [])];
    if (anomaliesOnly) list = list.filter((e) => e.anomaly);
    if (actionFilter !== "all") list = list.filter((e) => e.action === actionFilter);
    const q = query.trim().toLowerCase();
    if (q) {
      list = list.filter(
        (e) =>
          e.sourceIp.toLowerCase().includes(q) ||
          (e.destUrl ?? "").toLowerCase().includes(q) ||
          (e.userAgent ?? "").toLowerCase().includes(q),
      );
    }
    list.sort((a, b) => {
      const dir = sortDir === "asc" ? 1 : -1;
      if (sortKey === "bytes") {
        return (a.bytesSent + a.bytesReceived - (b.bytesSent + b.bytesReceived)) * dir;
      }
      const field = sortKey;
      const av = String(a[field] ?? "");
      const bv = String(b[field] ?? "");
      return av.localeCompare(bv) * dir;
    });
    return list;
  }, [summary, anomaliesOnly, actionFilter, query, sortKey, sortDir]);

  function toggleSort(key: SortKey) {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir(key === "timestamp" ? "asc" : "asc");
    }
  }

  if (loading && !summary) {
    return (
      <div className="panel px-8 py-16 text-center">
        <p className="text-signal">Analyzing session…</p>
        <p className="mt-2 text-sm text-mist">Loading parsed events and anomaly explanations.</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="panel border-alert-high/30 px-8 py-12 text-center text-alert-high">
        {error}
      </div>
    );
  }

  if (!summary) return null;

  if (summary.session.status === "processing") {
    return (
      <div className="panel px-8 py-16 text-center">
        <p className="text-alert-medium">Still processing</p>
        <p className="mt-2 text-sm text-mist">Refresh in a moment — parsing is synchronous on upload.</p>
      </div>
    );
  }

  if (summary.session.status === "failed") {
    return (
      <div className="panel px-8 py-12 text-center text-alert-high">
        This session failed during processing.
      </div>
    );
  }

  const { stats } = summary;

  return (
    <div className="space-y-8">
      <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard label="Total events" value={String(stats.totalEvents)} />
        <StatCard label="Unique source IPs" value={String(stats.uniqueSourceIps)} />
        <StatCard
          label="Anomalies"
          value={String(stats.anomalyCount)}
          warn={stats.anomalyCount > 0}
        />
        <StatCard
          label="Date range"
          value={
            stats.dateRange.start
              ? `${formatTimestamp(stats.dateRange.start).slice(0, 16)} → ${formatTimestamp(stats.dateRange.end ?? "").slice(0, 16)}`
              : "—"
          }
          small
        />
      </section>

      <section className="panel p-5">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-sm font-semibold">Events per hour (UTC)</h2>
          <span className="font-mono text-[11px] text-mist">{summary.session.filename}</span>
        </div>
        {summary.timeline.length === 0 ? (
          <p className="py-12 text-center text-sm text-mist">No timeline data.</p>
        ) : (
          <TimelineChart data={summary.timeline} />
        )}
      </section>

      {anomalies.length > 0 ? (
        <section className="panel overflow-hidden">
          <div className="border-b border-line px-4 py-3">
            <h2 className="text-sm font-semibold">Flagged anomalies</h2>
            <p className="mt-1 text-xs text-mist">
              One row per finding. Request bursts are grouped, not listed per
              event.
            </p>
          </div>
          <ul>
            {anomalies.map((flag) => (
              <li
                key={flag.id}
                className="border-b border-line/50 px-4 py-3 last:border-b-0"
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <p className="font-medium">
                      {findingHeading(flag)}{" "}
                      <SeverityBadge severity={flag.severity} />
                    </p>
                    <p className="mt-1 font-mono text-[11px] text-mist">
                      {flag.entry
                        ? `${formatTimestamp(flag.entry.timestamp)} · ${flag.entry.sourceIp} → ${flag.entry.destUrl}`
                        : `Entry ${flag.entryId}`}
                    </p>
                    <p className="mt-1 max-w-3xl text-sm text-mist">
                      {flag.explanation ?? "No explanation available."}
                    </p>
                  </div>
                  <div className="text-right font-mono text-xs text-mist">
                    <p>
                      Confidence{" "}
                      {flag.confidence === null
                        ? "—"
                        : `${Math.round(flag.confidence * 100)}%`}
                    </p>
                    <p className="mt-1 text-foam">{flag.recommendedAction}</p>
                  </div>
                </div>
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      <section className="panel overflow-hidden">
        <div className="flex flex-wrap items-center gap-3 border-b border-line px-4 py-3">
          <input
            className="input max-w-xs"
            placeholder="Filter IP, URL, user-agent"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <select
            className="input max-w-[10rem]"
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
          >
            <option value="all">All actions</option>
            {actions.map((action) => (
              <option key={action} value={action}>
                {action}
              </option>
            ))}
          </select>
          <label className="flex items-center gap-2 text-sm text-mist">
            <input
              type="checkbox"
              checked={anomaliesOnly}
              onChange={(e) => setAnomaliesOnly(e.target.checked)}
            />
            Anomalies only
          </label>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px] text-left text-sm">
            <thead className="bg-ink-900/80 font-mono text-[11px] uppercase tracking-wider text-mist">
              <tr>
                <SortHead label="Time" active={sortKey === "timestamp"} dir={sortDir} onClick={() => toggleSort("timestamp")} />
                <SortHead label="Source IP" active={sortKey === "sourceIp"} dir={sortDir} onClick={() => toggleSort("sourceIp")} />
                <th className="px-3 py-2 font-medium">Destination</th>
                <SortHead label="Action" active={sortKey === "action"} dir={sortDir} onClick={() => toggleSort("action")} />
                <SortHead label="Bytes" active={sortKey === "bytes"} dir={sortDir} onClick={() => toggleSort("bytes")} />
                <th className="px-3 py-2 font-medium">Flags</th>
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-12 text-center text-mist">
                    No matching events.
                  </td>
                </tr>
              ) : (
                rows.map((row) => {
                  const flags = anomalyByEntry.get(row.id) ?? [];
                  const open = expanded === row.id;
                  const severity = row.anomaly?.maxSeverity ?? "medium";
                  const rowTone =
                    flags.length === 0
                      ? ""
                      : severity === "high"
                        ? "bg-alert-high/10"
                        : severity === "low"
                          ? "bg-alert-low/10"
                          : "bg-alert-medium/10";
                  return (
                    <EntryBlock
                      key={row.id}
                      row={row}
                      flags={flags}
                      open={open}
                      rowTone={rowTone}
                      onToggle={() => setExpanded(open ? null : row.id)}
                    />
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {summary.pagination.total > summary.pagination.limit ? (
          <div className="flex items-center justify-between border-t border-line px-4 py-3 text-sm text-mist">
            <span>
              Showing {summary.pagination.offset + 1}–
              {Math.min(
                summary.pagination.offset + summary.pagination.limit,
                summary.pagination.total,
              )}{" "}
              of {summary.pagination.total}
            </span>
            <div className="flex gap-2">
              <button
                className="btn-ghost"
                type="button"
                disabled={offset === 0}
                onClick={() => setOffset(Math.max(0, offset - 200))}
              >
                Prev
              </button>
              <button
                className="btn-ghost"
                type="button"
                disabled={offset + 200 >= summary.pagination.total}
                onClick={() => setOffset(offset + 200)}
              >
                Next
              </button>
            </div>
          </div>
        ) : null}
      </section>

      {stats.anomalyCount === 0 ? (
        <div className="panel px-6 py-10 text-center">
          <p className="text-lg font-medium text-signal">No anomalies detected</p>
          <p className="mt-1 text-sm text-mist">
            Heuristics did not flag any events in this session.
          </p>
        </div>
      ) : null}
    </div>
  );
}

function EntryBlock({
  row,
  flags,
  open,
  rowTone,
  onToggle,
}: {
  row: EntryRow;
  flags: AnomalyRow[];
  open: boolean;
  rowTone: string;
  onToggle: () => void;
}) {
  return (
    <>
      <tr
        className={`border-b border-line/50 ${rowTone} ${flags.length ? "cursor-pointer" : ""}`}
        onClick={() => {
          if (flags.length) onToggle();
        }}
      >
        <td className="px-3 py-2 font-mono text-xs text-mist">
          {formatTimestamp(row.timestamp)}
        </td>
        <td className="px-3 py-2 font-mono text-xs">{row.sourceIp}</td>
        <td className="max-w-[280px] truncate px-3 py-2 font-mono text-xs" title={row.destUrl}>
          {row.destUrl}
        </td>
        <td className="px-3 py-2">
          <span
            className={
              row.action === "blocked" ? "text-alert-high" : "text-signal"
            }
          >
            {row.action}
          </span>
        </td>
        <td className="px-3 py-2 font-mono text-xs">
          {formatBytes((row.bytesSent ?? 0) + (row.bytesReceived ?? 0))}
        </td>
        <td className="px-3 py-2">
          {flags.length === 0 ? (
            <span className="text-mist">—</span>
          ) : (
            <span className="flex flex-wrap gap-1">
              {row.anomaly ? <SeverityBadge severity={row.anomaly.maxSeverity} /> : null}
              {flags.map((flag) => (
                <span
                  key={flag.id}
                  className="font-mono text-[10px] uppercase tracking-wider text-mist"
                >
                  {ruleLabel(flag.ruleTriggered)}
                </span>
              ))}
            </span>
          )}
        </td>
      </tr>
      {open
        ? flags.map((flag) => (
            <tr key={flag.id} className="border-b border-line/50 bg-ink-900/80">
              <td colSpan={6} className="px-4 py-3">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <p className="font-medium">
                      {findingHeading(flag)}{" "}
                      <SeverityBadge severity={flag.severity} />
                    </p>
                    <p className="mt-1 max-w-3xl text-sm text-mist">
                      {flag.explanation ?? "No explanation available."}
                    </p>
                  </div>
                  <div className="text-right font-mono text-xs text-mist">
                    <p>
                      Confidence{" "}
                      {flag.confidence === null
                        ? "—"
                        : `${Math.round(flag.confidence * 100)}%`}
                    </p>
                    <p className="mt-1 text-foam">{flag.recommendedAction}</p>
                  </div>
                </div>
              </td>
            </tr>
          ))
        : null}
    </>
  );
}

function findingHeading(flag: AnomalyRow): string {
  if (flag.ruleTriggered !== "high_request_rate") {
    return ruleLabel(flag.ruleTriggered);
  }
  const match = flag.explanation?.match(/made (\d+) requests/i);
  const count = match ? Number.parseInt(match[1], 10) : NaN;
  if (Number.isFinite(count) && count > 0) {
    return `High request rate (${count} requests; only the first is highlighted in the events table)`;
  }
  return "High request rate (grouped burst; only the first request is highlighted in the events table)";
}

function StatCard({
  label,
  value,
  warn,
  small,
}: {
  label: string;
  value: string;
  warn?: boolean;
  small?: boolean;
}) {
  return (
    <div className="panel p-4">
      <p className="font-mono text-[11px] uppercase tracking-wider text-mist">{label}</p>
      <p className={`mt-2 font-semibold ${small ? "text-sm" : "text-2xl"} ${warn ? "text-alert-medium" : "text-foam"}`}>
        {value}
      </p>
    </div>
  );
}

function SortHead({
  label,
  active,
  dir,
  onClick,
}: {
  label: string;
  active: boolean;
  dir: "asc" | "desc";
  onClick: () => void;
}) {
  return (
    <th className="px-3 py-2 font-medium">
      <button type="button" onClick={onClick} className="hover:text-foam">
        {label}
        {active ? (dir === "asc" ? " ↑" : " ↓") : ""}
      </button>
    </th>
  );
}
