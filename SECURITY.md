# Security notes

Threat → mitigation (one line each):

- Password handling → delegated entirely to Supabase Auth (no custom hashing or JWT signing).
- Session storage → httpOnly cookies via `@supabase/ssr`, not `localStorage` (reduces XSS token theft).
- File upload → extension allowlist (`.log`/`.txt`) + Content-Type check + magic-byte / printable-text sniffing + 10MB size cap.
- File storage → private Supabase Storage bucket `log-files` with per-user folder RLS; objects are not served from the app filesystem.
- SQL injection → all queries go through the Supabase client (parameterized); no string-concatenated SQL.
- Authorization → RLS on every table **and** explicit `getUser()` + ownership checks in API routes (defense in depth).
- Cross-user session access → `log_sessions.user_id = auth.uid()` plus a matching API filter before returning rows.
- Rate limiting → login (5/min/IP) and upload (10/hour/user); in-memory for this take-home, Redis/Upstash in production.
- Secrets → `.env.example` committed with placeholders; real `.env.local` is gitignored.
- Public signup → disabled in Supabase Auth; this app has a login page only (no registration UI).
- LLM scope → Claude sees only Stage-1 flagged rows (capped), never the raw unparsed file and never used as an auth oracle.
