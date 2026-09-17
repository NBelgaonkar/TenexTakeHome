import { LoginForm } from "@/app/login/login-form";

export default function LoginPage() {
  return (
    <main className="flex min-h-screen items-center justify-center px-4 py-16">
      <div className="panel w-full max-w-md p-8">
        <div className="mb-8 flex items-center gap-3">
          <span className="flex h-10 w-10 items-center justify-center rounded-md border border-signal/40 bg-signal/10 font-mono text-signal">
            S
          </span>
          <div>
            <h1 className="text-xl font-semibold">Sentinel</h1>
            <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-mist">
              Analyst access only
            </p>
          </div>
        </div>
        <p className="mb-6 text-sm text-mist">
          Sign in with the seeded demo account. Public signup is disabled.
        </p>
        <LoginForm />
      </div>
    </main>
  );
}
