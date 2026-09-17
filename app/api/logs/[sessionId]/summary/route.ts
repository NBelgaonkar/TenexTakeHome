import { NextResponse } from "next/server";
import { requireOwnedSession, requireUser } from "@/lib/auth";
import { bucketHourly } from "@/lib/format";
import { DEFAULT_ENTRY_PAGE_SIZE } from "@/lib/types";

export async function GET(
  request: Request,
  { params }: { params: { sessionId: string } },
) {
  // 1) Session check — never trust a client-supplied user id.
  const { user } = await requireUser();
  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  // 2) Ownership check (RLS is the second line of defense).
  const { supabase, session } = await requireOwnedSession(
    params.sessionId,
    user.id,
  );
  if (!session) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  const url = new URL(request.url);
  const limit = clampInt(url.searchParams.get("limit"), DEFAULT_ENTRY_PAGE_SIZE, 1, 500);
  const offset = clampInt(url.searchParams.get("offset"), 0, 0, 1_000_000);

  const { data: metaRows, error: metaError } = await supabase
    .from("log_entries")
    .select("timestamp, source_ip")
    .eq("session_id", session.id)
    .order("timestamp", { ascending: true });

  if (metaError) {
    return NextResponse.json({ error: metaError.message }, { status: 500 });
  }

  const timestamps = (metaRows ?? []).map((row) => row.timestamp as string);
  const uniqueIps = new Set((metaRows ?? []).map((row) => row.source_ip as string));

  const { data: entries, error: entryError } = await supabase
    .from("log_entries")
    .select(
      "id, timestamp, source_ip, dest_url, action, bytes_sent, bytes_received, user_agent, raw_line",
    )
    .eq("session_id", session.id)
    .order("timestamp", { ascending: true })
    .range(offset, offset + limit - 1);

  if (entryError) {
    return NextResponse.json({ error: entryError.message }, { status: 500 });
  }

  const { data: anomalyRows } = await supabase
    .from("anomalies")
    .select("entry_id, rule_triggered, severity")
    .eq("session_id", session.id);

  const anomalyByEntry = new Map<
    number,
    { rules: string[]; maxSeverity: string }
  >();
  for (const row of anomalyRows ?? []) {
    const current = anomalyByEntry.get(row.entry_id) ?? {
      rules: [],
      maxSeverity: "low",
    };
    current.rules.push(row.rule_triggered);
    current.maxSeverity = higherSeverity(current.maxSeverity, row.severity ?? "medium");
    anomalyByEntry.set(row.entry_id, current);
  }

  return NextResponse.json({
    session: {
      id: session.id,
      filename: session.filename,
      uploadedAt: session.uploaded_at,
      status: session.status,
      totalEntries: session.total_entries,
      anomalyCount: session.anomaly_count,
    },
    stats: {
      totalEvents: timestamps.length,
      uniqueSourceIps: uniqueIps.size,
      anomalyCount: session.anomaly_count,
      dateRange: {
        start: timestamps[0] ?? null,
        end: timestamps[timestamps.length - 1] ?? null,
      },
    },
    timeline: bucketHourly(timestamps),
    entries: (entries ?? []).map((row) => ({
      id: row.id,
      timestamp: row.timestamp,
      sourceIp: row.source_ip,
      destUrl: row.dest_url,
      action: row.action,
      bytesSent: row.bytes_sent,
      bytesReceived: row.bytes_received,
      userAgent: row.user_agent,
      rawLine: row.raw_line,
      anomaly: anomalyByEntry.get(row.id) ?? null,
    })),
    pagination: {
      limit,
      offset,
      total: timestamps.length,
    },
  });
}

function clampInt(
  raw: string | null,
  fallback: number,
  min: number,
  max: number,
): number {
  if (raw === null) return fallback;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

function higherSeverity(a: string, b: string): string {
  const rank: Record<string, number> = { low: 1, medium: 2, high: 3 };
  return (rank[b] ?? 0) >= (rank[a] ?? 0) ? b : a;
}
