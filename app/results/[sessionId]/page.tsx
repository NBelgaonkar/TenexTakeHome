import { AppHeader } from "@/components/app-header";
import { ResultsView } from "@/app/results/[sessionId]/results-view";
import { requireOwnedSession, requireUser } from "@/lib/auth";
import { notFound } from "next/navigation";

export const dynamic = "force-dynamic";

export default async function ResultsPage({
  params,
}: {
  params: { sessionId: string };
}) {
  const { user } = await requireUser();
  if (!user) return null;

  const { session } = await requireOwnedSession(params.sessionId, user.id);
  if (!session) notFound();

  return (
    <>
      <AppHeader email={user.email} />
      <main className="mx-auto max-w-6xl px-6 py-10">
        <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-signal">
          Session
        </p>
        <h1 className="mt-1 text-3xl font-semibold">{session.filename}</h1>
        <p className="mt-2 mb-8 text-sm text-mist">
          Parsed ZScaler events with heuristic flags. Expand a highlighted row
          for the explanation, confidence, and recommended action.
        </p>
        <ResultsView sessionId={params.sessionId} />
      </main>
    </>
  );
}
