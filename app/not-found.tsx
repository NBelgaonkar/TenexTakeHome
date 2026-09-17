import Link from "next/link";

export default function NotFound() {
  return (
    <main className="flex min-h-screen items-center justify-center px-4">
      <div className="panel max-w-md p-8 text-center">
        <p className="font-mono text-xs uppercase tracking-[0.2em] text-mist">404</p>
        <h1 className="mt-2 text-2xl font-semibold">Session not found</h1>
        <p className="mt-2 text-sm text-mist">
          That log session does not exist or you do not have access.
        </p>
        <Link href="/" className="btn-primary mt-6">
          Back to sessions
        </Link>
      </div>
    </main>
  );
}
