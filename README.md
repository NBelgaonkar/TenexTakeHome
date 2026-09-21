# Sentinel — AI-Powered Security Log Analyzer

Next.js **14.2.35** (App Router, TypeScript) take-home app: sign in, upload a **ZScaler NSS web proxy** log, inspect a parsed event timeline, and review heuristic anomalies with optional Claude explanations for a SOC analyst.

## Architecture

```
Browser  →  middleware.ts (refresh cookie session, gate dashboard + /api/logs/*)
         →  App Router pages + Route Handlers
         →  Supabase Auth / Postgres (RLS) / Storage
         →  Parser → Stage 1 rules → Stage 2 Claude (flagged rows only)
```

There is no separate Express server. All backend logic lives in Next.js Route Handlers.

| Surface | Path |
| --- | --- |
| Login | `/login` |
| Session list | `/` |
| Upload | `/upload` |
| Results | `/results/[sessionId]` |
| APIs | `POST /api/auth/login`, `POST /api/logs/upload`, `GET /api/logs/[sessionId]/summary`, `GET /api/logs/[sessionId]/anomalies` |

## How AI is used (two-stage pipeline)

**Stage 1 — deterministic heuristics** (`lib/anomaly/rules.ts`). No LLM, no API cost:

- `high_request_rate` — same source IP ≥ 20 requests in a 60s sliding window (one grouped finding per contiguous violating burst)
- `off_hours` — outside 08:00–18:00 **America/New_York** on weekdays; weekends count as off-hours
- `large_transfer` — `bytesSent + bytesReceived` ≥ `max(10 × session median, 5MB)`
- `rare_domain` — registrable domain appears once in the session **or** the TLD is on a small denylist (`.xyz`, `.tk`, `.top`, `.click`, `.gq`, `.ml`, `.cf`, `.zip`)

**Stage 2 — Claude explanation pass** (`lib/anomaly/llm.ts`). Runs **only** on Stage-1 hits (capped at 25), in a **single batched** tool-use call. Output: `explanation`, `confidence` (0–1), `severity`, `recommendedAction`.

If `ANTHROPIC_API_KEY` is missing or the call fails, the same rows are still stored with template explanations so the demo works offline. **Claude is never used to parse raw logs.**

## ZScaler log format

Documented NSS Web feed (tab-delimited so URLs and user-agents may contain spaces):

```
%s{time}\t%s{tz}\t%s{cip}\t%s{login}\t%s{url}\t%s{action}\t%d{reqsize}\t%d{respsize}\t%s{ua}
```

Example:

```
Mon Oct 16 22:55:48 2023	GMT	10.1.2.3	jdoe@corp.com	https://www.office.com/	Allowed	1234	56780	Mozilla/5.0 ...
```

`login` is parsed then dropped. `time` + `tz` normalize to ISO-8601. Malformed lines are skipped; the session fails only if **zero** lines parse.

Sample files: `sample-logs/normal.log` (~180 benign weekday lines) and `sample-logs/anomalous.log` (same baseline plus two request bursts, off-hours access, a ~50MB transfer, rare / denylisted domains, and a ~4MB Zoom download that stays under the large-transfer threshold). Regenerate with `npm run generate:logs`.

## Local setup

### 1. App

```bash
npm install
cp .env.example .env.local
```

### 2. Supabase project

1. Create a project at [supabase.com](https://supabase.com).
2. **Authentication → Providers → Email** enabled. **Disable** “Allow new users to sign up” (or turn off public signup under Auth settings) so this is invite-only.
3. **Authentication → Users → Add user** — seed one demo analyst (remember the email/password).
4. **SQL Editor** — paste and run [`supabase/migrations/20240917120000_init.sql`](supabase/migrations/20240917120000_init.sql). That creates tables, RLS, indexes, and the private `log-files` bucket.
5. Copy **Project URL** and **anon public** key into `.env.local` (`NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY`).
6. Optional: `ANTHROPIC_API_KEY` and `ANTHROPIC_MODEL` (default `claude-sonnet-4-5`).

You do **not** need the service role key. All queries use the user session so RLS is actually exercised.

### 3. Run

```bash
npm test
npm run dev
```

Open [http://localhost:3000](http://localhost:3000), sign in with the demo user, upload `sample-logs/anomalous.log`.

## Auth & API notes

- Sessions are **httpOnly cookies** via `@supabase/ssr`, not `localStorage`.
- `middleware.ts` refreshes the session and redirects anonymous users away from `/`, `/upload`, `/results/*`, and `/api/logs/*`.
- Every API route calls `supabase.auth.getUser()` then checks `log_sessions.user_id` **before** RLS (defense in depth — see comments in the route files).
- Login is rate-limited at **5 attempts / minute / IP**. Upload is **10 files / hour / user**. The limiter is an in-memory `Map` (`lib/rate-limit.ts`). On Vercel that is per-isolate; production should use Upstash Redis / Vercel KV.

Upload validation: extension allowlist (`.log`, `.txt`), 10MB cap, declared Content-Type check, and magic-byte / printable-text sniffing on the actual bytes.

`GET /api/logs/[sessionId]/summary` paginates entries (`limit`/`offset`, default 200) so a 10MB file cannot exceed typical serverless response limits. Stats and the hourly UTC timeline use the full session.

Synchronous parse + LLM on upload is in scope for this take-home (`maxDuration = 60`). A production port would enqueue a job (Inngest, QStash, or a worker) because Hobby Vercel functions time out at 10s.

## Vercel deployment

Do **not** deploy until env vars are set.

1. Push this repo to GitHub.
2. [Import the project on Vercel](https://vercel.com/new) (framework preset: Next.js).
3. Add the same env vars as `.env.example` (production + preview).
4. In Supabase **Authentication → URL configuration**, set Site URL to the Vercel domain and add `https://<project>.vercel.app/**` to Redirect URLs.
5. Deploy. Signup stays disabled; only the seeded user can sign in.

## Tests

Vitest covers the parser (including a malformed line) and each anomaly rule, plus a no-false-positive check against `sample-logs/normal.log`:

```bash
npm test
```

## Security

See [SECURITY.md](SECURITY.md).
