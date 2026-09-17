import { NextResponse } from "next/server";
import { requireOwnedSession, requireUser } from "@/lib/auth";

export async function GET(
  _request: Request,
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

  const { data, error } = await supabase
    .from("anomalies")
    .select(
      "id, entry_id, rule_triggered, explanation, confidence, recommended_action, severity, log_entries ( id, timestamp, source_ip, dest_url, action, bytes_sent, bytes_received, user_agent )",
    )
    .eq("session_id", session.id)
    .order("id", { ascending: true });

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  return NextResponse.json({
    anomalies: (data ?? []).map((row) => {
      const entry = unwrapOne(row.log_entries);
      return {
        id: row.id,
        entryId: row.entry_id,
        ruleTriggered: row.rule_triggered,
        explanation: row.explanation,
        confidence: row.confidence === null ? null : Number(row.confidence),
        recommendedAction: row.recommended_action,
        severity: row.severity,
        entry: entry
          ? {
              id: entry.id,
              timestamp: entry.timestamp,
              sourceIp: entry.source_ip,
              destUrl: entry.dest_url,
              action: entry.action,
              bytesSent: entry.bytes_sent,
              bytesReceived: entry.bytes_received,
              userAgent: entry.user_agent,
            }
          : null,
      };
    }),
  });
}

function unwrapOne<T>(value: T | T[] | null): T | null {
  if (Array.isArray(value)) return value[0] ?? null;
  return value;
}
