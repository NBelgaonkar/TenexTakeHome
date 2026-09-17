-- Sentinel SOC log analyzer — initial schema
-- Run this in the Supabase SQL editor (or via supabase db push).

create table if not exists public.log_sessions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) not null,
  filename text not null,
  storage_path text,
  uploaded_at timestamptz default now(),
  status text default 'processing', -- processing | complete | failed
  total_entries int default 0,
  anomaly_count int default 0
);

create table if not exists public.log_entries (
  id bigint generated always as identity primary key,
  session_id uuid references public.log_sessions(id) on delete cascade not null,
  timestamp timestamptz not null,
  source_ip text not null,
  dest_url text,
  action text,
  bytes_sent int,
  bytes_received int,
  user_agent text,
  raw_line text not null
);

create table if not exists public.anomalies (
  id bigint generated always as identity primary key,
  session_id uuid references public.log_sessions(id) on delete cascade not null,
  entry_id bigint references public.log_entries(id) not null,
  rule_triggered text not null,
  explanation text,
  confidence numeric(3,2),
  recommended_action text,
  severity text default 'medium' -- low | medium | high
);

create index if not exists log_entries_session_ts_idx
  on public.log_entries (session_id, timestamp);

create index if not exists anomalies_session_idx
  on public.anomalies (session_id);

alter table public.log_sessions enable row level security;
alter table public.log_entries enable row level security;
alter table public.anomalies enable row level security;

drop policy if exists "own sessions" on public.log_sessions;
create policy "own sessions" on public.log_sessions
  for all
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

drop policy if exists "own entries" on public.log_entries;
create policy "own entries" on public.log_entries
  for all
  using (
    session_id in (select id from public.log_sessions where user_id = auth.uid())
  )
  with check (
    session_id in (select id from public.log_sessions where user_id = auth.uid())
  );

drop policy if exists "own anomalies" on public.anomalies;
create policy "own anomalies" on public.anomalies
  for all
  using (
    session_id in (select id from public.log_sessions where user_id = auth.uid())
  )
  with check (
    session_id in (select id from public.log_sessions where user_id = auth.uid())
  );

-- Defense in depth: the anon role (unauthenticated requests) cannot touch these tables
-- even if an RLS policy were misconfigured. The browser uses the anon key *with a user JWT*,
-- which runs as the `authenticated` role.
revoke all on table public.log_sessions from anon, public;
revoke all on table public.log_entries from anon, public;
revoke all on table public.anomalies from anon, public;

grant select, insert, update, delete on table public.log_sessions to authenticated;
grant select, insert, update, delete on table public.log_entries to authenticated;
grant select, insert, update, delete on table public.anomalies to authenticated;
grant usage, select on all sequences in schema public to authenticated;

-- Private bucket: original uploads, never served from the app filesystem.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'log-files',
  'log-files',
  false,
  10485760,
  array['text/plain', 'application/octet-stream']::text[]
)
on conflict (id) do update
  set public = excluded.public,
      file_size_limit = excluded.file_size_limit,
      allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "users upload own logs" on storage.objects;
create policy "users upload own logs"
on storage.objects for insert
to authenticated
with check (
  bucket_id = 'log-files'
  and (storage.foldername(name))[1] = auth.uid()::text
);

drop policy if exists "users read own logs" on storage.objects;
create policy "users read own logs"
on storage.objects for select
to authenticated
using (
  bucket_id = 'log-files'
  and (storage.foldername(name))[1] = auth.uid()::text
);

drop policy if exists "users delete own logs" on storage.objects;
create policy "users delete own logs"
on storage.objects for delete
to authenticated
using (
  bucket_id = 'log-files'
  and (storage.foldername(name))[1] = auth.uid()::text
);
