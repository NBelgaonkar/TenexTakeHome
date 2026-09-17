import { AppHeader } from "@/components/app-header";
import { UploadForm } from "@/app/upload/upload-form";
import { requireUser } from "@/lib/auth";

export const dynamic = "force-dynamic";

export default async function UploadPage() {
  const { user } = await requireUser();
  if (!user) return null;

  return (
    <>
      <AppHeader email={user.email} />
      <main className="mx-auto max-w-2xl px-6 py-10">
        <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-signal">
          Ingest
        </p>
        <h1 className="mt-1 text-3xl font-semibold">Upload web proxy log</h1>
        <p className="mt-2 mb-8 text-sm text-mist">
          Parsing and rule-based detection run synchronously. Claude is called
          only for rows already flagged by heuristics.
        </p>
        <div className="panel p-6">
          <UploadForm />
        </div>
      </main>
    </>
  );
}
