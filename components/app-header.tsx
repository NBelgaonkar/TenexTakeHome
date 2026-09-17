import Link from "next/link";
import { LogoutButton } from "@/components/logout-button";

export function AppHeader({ email }: { email?: string }) {
  return (
    <header className="border-b border-line/80 bg-ink-900/80 backdrop-blur">
      <div className="mx-auto flex max-w-6xl items-center justify-between gap-4 px-6 py-4">
        <Link href="/" className="group flex items-center gap-3">
          <span className="flex h-8 w-8 items-center justify-center rounded-md border border-signal/40 bg-signal/10 font-mono text-xs text-signal">
            S
          </span>
          <span>
            <span className="block text-sm font-semibold tracking-wide text-foam">
              Sentinel
            </span>
            <span className="block font-mono text-[11px] uppercase tracking-[0.18em] text-mist">
              SOC log analyzer
            </span>
          </span>
        </Link>
        <nav className="flex items-center gap-3 text-sm">
          <Link href="/" className="text-mist hover:text-foam">
            Sessions
          </Link>
          <Link href="/upload" className="text-mist hover:text-foam">
            Upload
          </Link>
          {email ? (
            <span className="hidden font-mono text-xs text-mist sm:inline">{email}</span>
          ) : null}
          <LogoutButton />
        </nav>
      </div>
    </header>
  );
}
