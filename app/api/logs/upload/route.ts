import { NextResponse } from "next/server";
import { runAnomalyPipeline } from "@/lib/anomaly/pipeline";
import { requireUser } from "@/lib/auth";
import { chunk } from "@/lib/format";
import { parseLogFile } from "@/lib/parser/zscaler";
import { rateLimit } from "@/lib/rate-limit";
import { validateUpload } from "@/lib/upload/validate";

export const runtime = "nodejs";
export const maxDuration = 60;

export async function POST(request: Request) {
  // 1) Session check — never trust a client-supplied user id.
  const { supabase, user } = await requireUser();
  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const limited = rateLimit(`upload:${user.id}`, 10, 60 * 60 * 1000);
  if (!limited.ok) {
    return NextResponse.json(
      { error: "Upload rate limit exceeded. Try again later." },
      { status: 429 },
    );
  }

  const formData = await request.formData();
  const file = formData.get("file");
  if (!(file instanceof File)) {
    return NextResponse.json({ error: "Missing file field." }, { status: 400 });
  }

  const validated = await validateUpload(file);
  if (!validated.ok) {
    return NextResponse.json({ error: validated.error }, { status: 400 });
  }

  const sessionId = crypto.randomUUID();
  const storagePath = `${user.id}/${sessionId}/${validated.filename}`;

  const { error: storageError } = await supabase.storage
    .from("log-files")
    .upload(storagePath, validated.bytes, {
      contentType: "text/plain",
      upsert: false,
    });

  if (storageError) {
    return NextResponse.json(
      { error: `Storage upload failed: ${storageError.message}` },
      { status: 500 },
    );
  }

  const { error: sessionError } = await supabase.from("log_sessions").insert({
    id: sessionId,
    user_id: user.id,
    filename: validated.filename,
    storage_path: storagePath,
    status: "processing",
  });

  if (sessionError) {
    return NextResponse.json(
      { error: `Failed to create session: ${sessionError.message}` },
      { status: 500 },
    );
  }

  try {
    const parsed = parseLogFile(validated.bytes.toString("utf8"));
    if (parsed.entries.length === 0) {
      await supabase
        .from("log_sessions")
        .update({ status: "failed", total_entries: 0, anomaly_count: 0 })
        .eq("id", sessionId)
        .eq("user_id", user.id);
      return NextResponse.json(
        { error: "No valid ZScaler log lines found in the file." },
        { status: 400 },
      );
    }

    const inserted: Array<{ id: number }> = [];
    for (const group of chunk(parsed.entries, 400)) {
      const rows = group.map((entry) => ({
        session_id: sessionId,
        timestamp: entry.timestamp,
        source_ip: entry.sourceIp,
        dest_url: entry.destUrl,
        action: entry.action,
        bytes_sent: entry.bytesSent,
        bytes_received: entry.bytesReceived,
        user_agent: entry.userAgent,
        raw_line: entry.rawLine,
      }));
      const { data, error } = await supabase
        .from("log_entries")
        .insert(rows)
        .select("id");
      if (error || !data) {
        throw new Error(error?.message ?? "Failed to insert log entries");
      }
      inserted.push(...data);
    }

    const withIds = parsed.entries.map((entry, index) => ({
      ...entry,
      id: inserted[index].id,
    }));

    const anomalies = await runAnomalyPipeline(sessionId, withIds);
    if (anomalies.length > 0) {
      for (const group of chunk(anomalies, 400)) {
        const { error } = await supabase.from("anomalies").insert(group);
        if (error) throw new Error(error.message);
      }
    }

    await supabase
      .from("log_sessions")
      .update({
        status: "complete",
        total_entries: parsed.entries.length,
        anomaly_count: anomalies.length,
      })
      .eq("id", sessionId)
      .eq("user_id", user.id);

    return NextResponse.json({
      sessionId,
      totalEntries: parsed.entries.length,
      skipped: parsed.skipped,
      anomalyCount: anomalies.length,
    });
  } catch (err) {
    await supabase
      .from("log_sessions")
      .update({ status: "failed" })
      .eq("id", sessionId)
      .eq("user_id", user.id);
    const message = err instanceof Error ? err.message : "Processing failed";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
