import { createClient } from "@/lib/supabase/server";

export async function requireUser() {
  const supabase = createClient();
  // Re-verify the session server-side. Never trust a client-supplied user id.
  const {
    data: { user },
    error,
  } = await supabase.auth.getUser();

  if (error || !user) {
    return { supabase, user: null as null };
  }

  return { supabase, user };
}

export async function requireOwnedSession(sessionId: string, userId: string) {
  const supabase = createClient();
  // Explicit ownership check (defense in depth; RLS also enforces this).
  const { data, error } = await supabase
    .from("log_sessions")
    .select(
      "id, user_id, filename, storage_path, uploaded_at, status, total_entries, anomaly_count",
    )
    .eq("id", sessionId)
    .eq("user_id", userId)
    .maybeSingle();

  if (error || !data) return { supabase, session: null };
  return { supabase, session: data };
}
