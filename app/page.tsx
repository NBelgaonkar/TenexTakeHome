import Link from "next/link";
import { AppHeader } from "@/components/app-header";
import { requireUser } from "@/lib/auth";
import { formatTimestamp } from "@/lib/format";

export const dynamic = "force-dynamic";

interface SessionRow {
  id: string;
  filename: string;
  uploaded_at: string;
  status: string;
  total_entries: number;
  anomaly_count: number;
}

export default async function DashboardPage() {
  const { supabase, user } = await requireUser();
  if (!user) return null;

  const { data } = await supabase
    .from("log_sessions")
    .select("id, filename, uploaded_at, status, total_entries, anomaly_count")
    .eq("user_id", user.id)
    .order("uploaded_at", { ascending: false });

  const sessions = (data ?? []) as SessionRow[];

  return (
    <>
      <AppHeader email={user.email} />
      <main className="mx-auto max-w-6xl px-6 py-10">
        <div className="mb-8 flex flex-wrap items-end justify-between gap-4">
          <div>
            <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-signal">
              Workspace
            </p>
            <h1 className="mt-1 text-3xl font-semibold">Log sessions</h1>
            <p className="mt-2 max-w-xl text-sm text-mist">
              Upload a ZScaler NSS web log to parse events and flag heuristic
              anomalies with analyst-facing explanations.
            </p>
          </div>
          <Link href="/upload" className="btn-primary">
            Upload log
          </Link>
        </div>

        {sessions.length === 0 ? (
          <div className="panel px-8 py-16 text-center">
            <p className="text-lg font-medium">No sessions yet</p>
            <p className="mt-2 text-sm text-mist">
              Start with{" "}
              <code className="font-mono text-signal">sample-logs/anomalous.log</code>{" "}
              to see the detection pipeline.
            </p>
            <Link href="/upload" className="btn-primary mt-6">
              Upload a file
            </Link>
          </div>
        ) : (
          <div className="panel overflow-hidden">
            <table className="w-full text-left text-sm">
              <thead className="border-b border-line bg-ink-900/80 font-mono text-[11px] uppercase tracking-wider text-mist">
                <tr>
                  <th className="px-4 py-3 font-medium">File</th>
                  <th className="px-4 py-3 font-medium">Uploaded</th>
                  <th className="px-4 py-3 font-medium">Status</th>
                  <th className="px-4 py-3 font-medium">Events</th>
                  <th className="px-4 py-3 font-medium">Anomalies</th>
                </tr>
              </thead>
              <tbody>
                {sessions.map((session) => (
                  <tr
                    key={session.id}
                    className="border-b border-line/70 last:border-0 hover:bg-ink-700/40"
                  >
                    <td className="px-4 py-3">
                      <Link
                        href={`/results/${session.id}`}
                        className="font-medium text-foam hover:text-signal"
                      >
                        {session.filename}
                      </Link>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-mist">
                      {formatTimestamp(session.uploaded_at)}
                    </td>
                    <td className="px-4 py-3">
                      <StatusPill status={session.status} />
                    </td>
                    <td className="px-4 py-3 font-mono">{session.total_entries}</td>
                    <td className="px-4 py-3 font-mono">
                      {session.anomaly_count > 0 ? (
                        <span className="text-alert-medium">{session.anomaly_count}</span>
                      ) : (
                        session.anomaly_count
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </main>
    </>
  );
}

function StatusPill({ status }: { status: string }) {
  const cls =
    status === "complete"
      ? "border-signal/30 text-signal"
      : status === "failed"
        ? "border-alert-high/40 text-alert-high"
        : "border-alert-medium/40 text-alert-medium";
  return (
    <span className={`rounded-full border px-2 py-0.5 font-mono text-[10px] uppercase ${cls}`}>
      {status}
    </span>
  );
}
