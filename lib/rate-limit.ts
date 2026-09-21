/**
 * Rate limiter with two backends behind checkRateLimit:
 * Upstash Redis when UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN
 * are set (shared across instances); otherwise an in-memory Map (per process).
 * If the Redis call throws, that request falls back to memory and is logged.
 */

import { Redis } from "@upstash/redis";

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  retryAfterSeconds: number;
}

type Hits = number[];

const buckets = new Map<string, Hits>();

export function rateLimitKey(
  kind: "login-ip" | "login-email" | "upload-user",
  id: string,
): string {
  switch (kind) {
    case "login-ip":
      return `rl:login:ip:${id}`;
    case "login-email":
      return `rl:login:email:${id}`;
    case "upload-user":
      return `rl:upload:user:${id}`;
  }
}

export async function checkRateLimit(
  key: string,
  limit: number,
  windowSeconds: number,
): Promise<RateLimitResult> {
  if (upstashConfigured()) {
    try {
      return await checkRedis(key, limit, windowSeconds);
    } catch (err) {
      const name = err instanceof Error ? err.name : "Error";
      const message = err instanceof Error ? err.message : "unknown error";
      console.error(
        `Upstash rate limit failed: ${name} ${message}; using in-memory limiter`,
      );
      return checkMemory(key, limit, windowSeconds);
    }
  }
  return checkMemory(key, limit, windowSeconds);
}

function upstashConfigured(): boolean {
  return Boolean(
    process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN,
  );
}

async function checkRedis(
  key: string,
  limit: number,
  windowSeconds: number,
): Promise<RateLimitResult> {
  const redis = new Redis({
    url: process.env.UPSTASH_REDIS_REST_URL as string,
    token: process.env.UPSTASH_REDIS_REST_TOKEN as string,
  });
  const count = Number(await redis.incr(key));
  if (count === 1) {
    await redis.expire(key, windowSeconds);
  }
  if (count > limit) {
    const ttl = Number(await redis.ttl(key));
    return {
      allowed: false,
      remaining: 0,
      retryAfterSeconds: ttl > 0 ? ttl : windowSeconds,
    };
  }
  return {
    allowed: true,
    remaining: Math.max(0, limit - count),
    retryAfterSeconds: 0,
  };
}

function checkMemory(
  key: string,
  limit: number,
  windowSeconds: number,
): RateLimitResult {
  const now = Date.now();
  const windowMs = windowSeconds * 1000;
  const recent = (buckets.get(key) ?? []).filter((t) => now - t < windowMs);

  if (recent.length >= limit) {
    buckets.set(key, recent);
    const oldest = recent[0] ?? now;
    const retryAfterMs = Math.max(0, windowMs - (now - oldest));
    return {
      allowed: false,
      remaining: 0,
      retryAfterSeconds: Math.ceil(retryAfterMs / 1000),
    };
  }

  recent.push(now);
  buckets.set(key, recent);
  return {
    allowed: true,
    remaining: Math.max(0, limit - recent.length),
    retryAfterSeconds: 0,
  };
}

/**
 * Best-effort client IP. x-forwarded-for is only trustworthy behind a
 * reverse proxy that overwrites it (for example Vercel). Use the first
 * hop; later values can be client-supplied.
 */
export function clientIp(request: Request): string {
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded) {
    const first = forwarded.split(",")[0]?.trim();
    if (first) return first;
  }
  return request.headers.get("x-real-ip") ?? "unknown";
}
