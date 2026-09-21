import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { checkRateLimit, clientIp, rateLimitKey } from "@/lib/rate-limit";

export async function POST(request: Request) {
  const ip = clientIp(request);
  const ipLimited = await checkRateLimit(rateLimitKey("login-ip", ip), 5, 60);
  if (!ipLimited.allowed) {
    return tooManyAttempts(ipLimited.retryAfterSeconds);
  }

  let body: { email?: string; password?: string };
  try {
    body = (await request.json()) as { email?: string; password?: string };
  } catch {
    return NextResponse.json({ error: "Invalid request body." }, { status: 400 });
  }

  const email = (body.email ?? "").trim();
  const password = body.password ?? "";
  if (!email || !password) {
    return NextResponse.json({ error: "Email and password are required." }, { status: 400 });
  }

  const emailLimited = await checkRateLimit(
    rateLimitKey("login-email", email.toLowerCase()),
    10,
    15 * 60,
  );
  if (!emailLimited.allowed) {
    return tooManyAttempts(emailLimited.retryAfterSeconds);
  }

  const supabase = createClient();
  const { error } = await supabase.auth.signInWithPassword({ email, password });
  if (error) {
    return NextResponse.json({ error: "Invalid credentials." }, { status: 401 });
  }

  return NextResponse.json({ ok: true });
}

function tooManyAttempts(retryAfterSeconds: number) {
  return NextResponse.json(
    { error: "Too many login attempts. Try again shortly." },
    {
      status: 429,
      headers: { "Retry-After": String(retryAfterSeconds) },
    },
  );
}
