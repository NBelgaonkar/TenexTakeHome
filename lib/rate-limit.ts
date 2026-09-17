/**
 * In-memory sliding-window limiter.
 *
 * Fine for a take-home / single-instance `next dev`. In production swap this
 * for a shared store (Upstash Redis, Vercel KV, or a Postgres counter) so
 * limits hold across serverless isolates and deploys.
 */

type Hits = number[];

const buckets = new Map<string, Hits>();

export function rateLimit(
  key: string,
  limit: number,
  windowMs: number,
): { ok: true } | { ok: false; retryAfterMs: number } {
  const now = Date.now();
  const recent = (buckets.get(key) ?? []).filter((t) => now - t < windowMs);

  if (recent.length >= limit) {
    buckets.set(key, recent);
    const oldest = recent[0] ?? now;
    return { ok: false, retryAfterMs: Math.max(0, windowMs - (now - oldest)) };
  }

  recent.push(now);
  buckets.set(key, recent);
  return { ok: true };
}

export function clientIp(request: Request): string {
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded) {
    const first = forwarded.split(",")[0]?.trim();
    if (first) return first;
  }
  return request.headers.get("x-real-ip") ?? "unknown";
}
