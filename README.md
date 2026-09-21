# Sentinel: ZScaler log analyzer for SOC analysts

Sentinel is a Next.js 14 app for a SOC analyst: sign in, upload a ZScaler NSS web proxy log, inspect parsed events on a timeline, and review rule-based anomalies with optional Claude explanations. The only supported format is the tab-delimited NSS web feed documented below.

## Feature checklist (assignment)

- Login with a seeded email and password (invite-only; no registration UI)
- Upload `.log` and `.txt` files (10MB cap)
- Parsed event table plus an hourly UTC chart
- Results view with filters, pagination, and a findings list
- Anomaly detection that highlights flagged events
- Per-anomaly plain-language explanation
- Per-anomaly confidence score (0-1)

## Tech stack and architecture

Next.js **14.2.35** App Router in TypeScript. Route Handlers are the REST backend. There is no separate Express server because the App Router already serves pages and `/api/*` from the same process.

Supabase provides Auth (email/password, httpOnly cookies via `@supabase/ssr`), Postgres with RLS, and a private Storage bucket for original uploads.

```
Browser  →  middleware.ts (refresh cookie session, gate non-public routes)
         →  App Router pages + Route Handlers
         →  Supabase Auth / Postgres (RLS) / Storage
         →  Parser → Stage 1 rules → Stage 2 Claude (priority-capped subset)
```

| Surface | Path |
| --- | --- |
| Login | `/login` |
| Session list | `/` |
| Upload | `/upload` |
| Results | `/results/[sessionId]` |
| Login API | `POST /api/auth/login` |
| Logout API | `POST /api/auth/logout` |
| Upload API | `POST /api/logs/upload` |
| Summary API | `GET /api/logs/[sessionId]/summary` |
| Anomalies API | `GET /api/logs/[sessionId]/anomalies` |

Anonymous users can reach `/login` and `POST /api/auth/login`. Everything else is redirected or returns 401 until a session cookie exists. `GET /api/logs/[sessionId]/summary` and `GET /api/logs/[sessionId]/anomalies` also check that `log_sessions.user_id` matches the current user. Upload creates a new session for that user and does not take a `sessionId`.

## Quick start (local)

**Prerequisites:** Node.js **18.17 or later** (required by Next.js 14.2.35; this repo has no `engines` field of its own), npm, and a Supabase project.

On Windows PowerShell, if script execution is disabled and `npm` fails, use `npm.cmd` for the same commands (`npm.cmd install`, `npm.cmd test`, `npm.cmd run dev`).

### 1. Install and env file

```bash
npm install
```

macOS / Linux:

```bash
cp .env.example .env.local
```

Windows PowerShell:

```powershell
Copy-Item .env.example .env.local
```

Next.js loads `.env.local` automatically for `next dev` and `next build`. This repo does not use `node --env-file`.

### 2. Supabase

1. Create a project at [supabase.com](https://supabase.com).
2. **Authentication → Providers → Email:** enable Email.
3. Disable public signup: **Authentication** settings, turn off **Allow new users to sign up** (wording may be under Auth / sign-up). This app has a login page only.
4. **Authentication → Users → Add user:** create one demo analyst. Save the email and password; they are not in this repo.
5. **SQL Editor:** paste and run [`supabase/migrations/20240917120000_init.sql`](supabase/migrations/20240917120000_init.sql). That creates tables, RLS, indexes, and the private `log-files` bucket.
6. Copy **Project URL** and **anon public** key into `.env.local`.

You do not need the service role key. Queries use the user session so RLS is actually enforced.

### 3. Run and test

```bash
npm test
npm run dev
```

Open [http://localhost:3000](http://localhost:3000). If port 3000 is taken, `next dev` binds the next free port and prints it in the terminal.

### Environment variables

Every name below is read via `process.env` in application code. Next.js also sets `NODE_ENV`; that is not listed.

| Variable | Required | Default | Where |
| --- | --- | --- | --- |
| `NEXT_PUBLIC_SUPABASE_URL` | Yes | none (throws if missing in the server client) | `lib/supabase/server.ts`, `client.ts`, `middleware.ts` |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | Yes | none (same as above) | same |
| `ANTHROPIC_API_KEY` | No | unset: Stage 2 uses templates | `lib/anomaly/llm.ts` |
| `ANTHROPIC_MODEL` | No | `claude-sonnet-4-5` | `lib/anomaly/llm.ts` |
| `ANOMALY_OFF_HOURS_TZ` | No | `America/New_York` | `lib/anomaly/rules.ts` |
| `ANOMALY_BUSINESS_START_HOUR` | No | `8` | `lib/anomaly/rules.ts` |
| `ANOMALY_BUSINESS_END_HOUR` | No | `18` | `lib/anomaly/rules.ts` |
| `ANOMALY_RATE_THRESHOLD` | No | `20` | `lib/anomaly/rules.ts` |
| `ANOMALY_RATE_WINDOW_SECONDS` | No | `60` | `lib/anomaly/rules.ts` |
| `ANOMALY_TRANSFER_MEDIAN_MULTIPLIER` | No | `10` | `lib/anomaly/rules.ts` |
| `ANOMALY_TRANSFER_FLOOR_BYTES` | No | `5242880` (5MB) | `lib/anomaly/rules.ts` |

The TLD denylist is not an env var. It is hardcoded in `DEFAULT_RULE_CONFIG.suspiciousTlds`.

## Try it

1. Sign in at `/login` with the user you created in Supabase.
2. Upload `sample-logs/normal.log`. Expect **180** parsed events and **0** findings (`detectAnomalies` on this file returns `[]`; parser skipped count is 0).
3. Upload `sample-logs/anomalous.log`. Expect **246** parsed events, **1** skipped line (a `#` comment in the fixture), and **11** findings:

| Rule | Count | What you should see |
| --- | --- | --- |
| `high_request_rate` | 2 grouped findings | 25 requests from `10.9.9.9` to `https://www.office.com/`; 28 from `10.4.4.20` to `https://login.salesforce.com/` |
| `off_hours` | 4 | GitHub requests at 07:10 GMT (03:10 America/New_York) |
| `large_transfer` | 1 | `https://www.office.com/share/export` (~50MB) |
| `rare_domain` | 4 | `steal-session.xyz`, `portal.docusign.net`, `status.pagerduty.com`, `payload-cdn.click` |

The ~4.2MB Zoom download at `https://zoom.us/recording/download` is **not** a `large_transfer` hit. Request bursts appear as one finding; the events table highlights the first request of the burst.

## How AI is used

### a. Runtime AI usage

| Task | Where in code | Uses LLM? | Notes |
| --- | --- | --- | --- |
| Parse NSS lines | `lib/parser/zscaler.ts` | No | Deterministic tab split and field checks |
| Stage 1 detection | `lib/anomaly/rules.ts` | No | Four heuristics; no API call |
| Orchestrate persist | `lib/anomaly/pipeline.ts` | No | Calls Stage 1 then Stage 2, maps rows |
| Stage 2 explanations | `lib/anomaly/llm.ts` | Yes, Claude only | One batched tool call on a capped subset |
| Results UI | `app/results/[sessionId]/results-view.tsx` | No | Renders stored explanation and confidence |

Claude is never used to parse logs or to decide which rows are anomalies.

### b. Two-stage approach

**Stage 1** (`lib/anomaly/rules.ts`), defaults unless overridden by env:

- `high_request_rate`: same `sourceIp`, sliding window of `rateWindowSeconds` (default 60s). If the window contains at least `rateThreshold` (default 20) requests, those indexes are flagged, then collapsed into one hit per contiguous burst (`entryCount`, `relatedEntryIndexes`). A gap larger than the window starts a new burst.
- `off_hours`: timestamp converted in `timezone` (default `America/New_York`). Saturday and Sunday always flag. Weekdays flag when local hour is `< businessStartHour` (8) or `>= businessEndHour` (18).
- `large_transfer`: `bytesSent + bytesReceived >= max(median * transferMedianMultiplier, transferFloorBytes)` with multiplier 10 and floor 5MB. Median is `medianOf` in `rules.ts` (average of the two middle values when the count is even).
- `rare_domain`: registrable domain (via `tldts`) appears once in the session, **or** the public suffix is on `{xyz, tk, top, click, gq, ml, cf, zip}`.

Hits are sorted by `entryIndex`, then rule name.

**Stage 2** (`lib/anomaly/llm.ts`):

- Model: `process.env.ANTHROPIC_MODEL` or **`claude-sonnet-4-5`**.
- One `messages.create` call with `tool_choice` forced to `record_anomaly_explanations` and a JSON schema for `explanations[]`.
- Returned fields: `explanation`, `confidence`, `severity`, `recommendedAction` (plus `id` to join back).
- Cap: `LLM_ANOMALY_CAP` is **25**. `selectHitsForLlm` ranks `large_transfer`, then `high_request_rate`, then `rare_domain`, then `off_hours`, keeping original order within a rule.
- **Every Stage 1 hit is stored.** Only the selected subset is sent to Claude. The rest keep `fallbackExplanation`.

### c. What the model sees and what it does not

`callClaude` sends a JSON array of:

`id`, `rule`, `ruleLabel`, `timestamp`, `sourceIp`, `destUrl`, `action`, `bytesSent`, `bytesReceived`, and `context` (`rule`, `sourceIp`, `destUrl`, `action`, `bytes`, `sessionSize`, `sameIpCount`, `sessionMedianBytes`, `entryCount`, `rateWindowSeconds`).

Not sent: `rawLine`, `userAgent`, and the NSS `login` field (parsed in `parseLogLine` then dropped from `LogEntry`). Explanations are hypotheses from this metadata, not evidence from the raw file.

### d. Safety and reliability

The system prompt states that event fields (URLs, IPs, user agents) are untrusted log data and must not be followed as instructions. Instructions live in `system`; the user message is `JSON.stringify(payload)`.

`parseLlmItems` keeps only objects with the expected types. `clampConfidence` maps non-finite values to 0.5 and clamps to 0-1 (two decimal places). Unknown severity becomes `medium`. Missing tool output leaves the templates in place.

If `ANTHROPIC_API_KEY` is missing, or `callClaude` throws, `explainAnomalies` returns those templates. The `catch` block does **not** log the error.

### e. Confidence scores

Claude confidence is self-reported by the model. It is not a calibrated probability. In fallback mode the templates are:

| Rule | Confidence | Severity |
| --- | --- | --- |
| `high_request_rate` | 0.82 | high |
| `off_hours` | 0.7 | medium |
| `large_transfer` | 0.78 | high |
| `rare_domain` | 0.66 | medium |

### f. Why this design

- Detection is cheap, deterministic, and testable without an API key.
- The LLM is used only to write analyst-facing prose for rows already flagged.
- Cost and latency are bounded (one call, 25 findings).
- The demo still works offline with template copy.

### g. AI usage during development

Cursor and Claude were used to help write code, tests, and docs. The author reviewed and tested the result and can explain it in an interview. Runtime Claude usage is only the Stage 2 pass above.

## Sample log files

ZScaler NSS web (tabs so URLs and user-agents may contain spaces):

```
%s{time}\t%s{tz}\t%s{cip}\t%s{login}\t%s{url}\t%s{action}\t%d{reqsize}\t%d{respsize}\t%s{ua}
```

Example:

```
Mon Oct 16 22:55:48 2023	GMT	10.1.2.3	jdoe@corp.com	https://www.office.com/	Allowed	1234	56780	Mozilla/5.0 ...
```

`login` is parsed then dropped. `time` + `tz` become ISO-8601. Malformed lines are skipped. The session is marked failed only if **zero** lines parse.

| File | Parsed events | Planted findings |
| --- | --- | --- |
| `sample-logs/normal.log` | 180 weekday baseline rows | none |
| `sample-logs/anomalous.log` | 246 (plus 1 skipped `#` comment) | two bursts, 4 off-hours GitHub rows, ~50MB export, 4 rare/denylisted domains |

Intentionally **not** flagged: Zoom recording ~4.2MB (`120000 + 4194304` bytes), under the 5MB `large_transfer` floor. Zoom heartbeats keep `zoom.us` from looking like a first-seen domain.

Regenerate both files:

```bash
npm run generate:logs
```

## Security notes

- Passwords: Supabase Auth only. Sessions: httpOnly cookies via `@supabase/ssr`, not `localStorage`.
- Invite-only: disable public signup in Supabase; this app has no sign-up page.
- `POST /api/logs/upload`, summary, and anomalies call `getUser()`. Summary and anomalies also filter `log_sessions` by `user_id` before returning rows. Login and logout do not do an ownership check (login has no session yet; logout only calls `signOut`).
- RLS on `log_sessions`, `log_entries`, and `anomalies`. Storage bucket `log-files` is private; object paths start with `auth.uid()`.
- Upload checks: `.log` / `.txt`, 10MB, Content-Type `text/plain` or `application/octet-stream` (or empty), no NUL bytes, deny-listed magic bytes, >= 85% printable in the first 8KB.
- Rate limits in `lib/rate-limit.ts`: **5 login attempts per minute per IP**, **10 uploads per hour per user**. In-memory `Map`, per process, not shared across serverless isolates.

See [SECURITY.md](SECURITY.md).

## Testing

```bash
npm test
```

Vitest (watch: `npm run test:watch`). **21** tests in 2 files:

- `__tests__/parser.test.ts` (6): NSS field mapping, malformed line, bad timestamp, non-IP, skip/count, `normal.log` parse range
- `__tests__/anomaly.test.ts` (15): each rule, `normal.log` has 0 hits, `anomalous.log` has all four rule types (including the Zoom non-flag), LLM cap persistence, `selectHitsForLlm` order

## Deployment

Local `npm run dev` is the default way to run this take-home.

Live demo: [ADD LIVE URL IF DEPLOYED]

Vercel (bonus):

1. Push the repo to GitHub.
2. Import the project on [Vercel](https://vercel.com/new) (Next.js preset).
3. Set the env vars from the table above (Production and Preview). `ANTHROPIC_API_KEY` must be set in the host if you want Claude explanations. Never commit `.env.local`.
4. In Supabase **Authentication → URL configuration**, set Site URL to the Vercel origin and add `https://<project>.vercel.app/**` to Redirect URLs.
5. Deploy. Signup stays disabled; only the seeded user can sign in.

The upload route sets `maxDuration = 60`. Confirm the function timeout on your Vercel plan. A shorter limit can cut off parse plus Stage 2.

## Known limitations and next steps

- Rate limiter is in-memory per process, not shared.
- Parse and Stage 2 run synchronously on upload.
- `rare_domain` flags any domain seen once, so it is noisy on large real logs.
- Confidence is not a calibrated probability.
- Only ZScaler NSS web tab-delimited format is supported.
- Claude sees metadata only, not `rawLine`.
- `GET /api/logs/[sessionId]/anomalies` is not paginated.

Possible next steps: per-user baselines instead of session-only stats, threat-intel lookups for rare domains, a background job queue for parse/LLM, calibration of confidence against labeled findings.

## Submission notes

Repository shared with venkata@tenex.ai. [CONFIRM BEFORE SUBMITTING]. Walkthrough video submitted separately.
