import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { mockIncr, mockExpire, mockTtl } = vi.hoisted(() => ({
  mockIncr: vi.fn(),
  mockExpire: vi.fn(),
  mockTtl: vi.fn(),
}));

vi.mock("@upstash/redis", () => ({
  Redis: class {
    incr = mockIncr;
    expire = mockExpire;
    ttl = mockTtl;
  },
}));

import { checkRateLimit, rateLimitKey } from "@/lib/rate-limit";

describe("rateLimitKey", () => {
  it("namespaces keys by kind", () => {
    expect(rateLimitKey("login-ip", "203.0.113.9")).toBe(
      "rl:login:ip:203.0.113.9",
    );
    expect(rateLimitKey("login-email", "a@b.com")).toBe(
      "rl:login:email:a@b.com",
    );
    expect(rateLimitKey("upload-user", "user-1")).toBe(
      "rl:upload:user:user-1",
    );
  });
});

describe("in-memory backend", () => {
  beforeEach(() => {
    delete process.env.UPSTASH_REDIS_REST_URL;
    delete process.env.UPSTASH_REDIS_REST_TOKEN;
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2024-03-11T15:00:00.000Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("allows up to the limit, blocks after, and resets after the window", async () => {
    const key = rateLimitKey("login-ip", `mem-${Date.now()}-${Math.random()}`);
    const first = await checkRateLimit(key, 2, 60);
    const second = await checkRateLimit(key, 2, 60);
    const third = await checkRateLimit(key, 2, 60);

    expect(first.allowed).toBe(true);
    expect(second.allowed).toBe(true);
    expect(third.allowed).toBe(false);
    expect(third.remaining).toBe(0);
    expect(third.retryAfterSeconds).toBeGreaterThan(0);

    vi.advanceTimersByTime(60_000);
    const afterWindow = await checkRateLimit(key, 2, 60);
    expect(afterWindow.allowed).toBe(true);
  });
});

describe("Upstash fallback", () => {
  const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

  beforeEach(() => {
    process.env.UPSTASH_REDIS_REST_URL = "https://example.upstash.io";
    process.env.UPSTASH_REDIS_REST_TOKEN = "upstash-test-token";
    mockIncr.mockReset();
    mockExpire.mockReset();
    mockTtl.mockReset();
    errorSpy.mockClear();
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2024-03-11T16:00:00.000Z"));
  });

  afterEach(() => {
    delete process.env.UPSTASH_REDIS_REST_URL;
    delete process.env.UPSTASH_REDIS_REST_TOKEN;
    vi.useRealTimers();
  });

  it("falls back to in-memory when Redis throws, logs without secrets, and still enforces the limit", async () => {
    mockIncr.mockRejectedValue(new Error("redis unavailable"));
    const key = rateLimitKey("login-ip", `fallback-${Math.random()}`);

    const first = await checkRateLimit(key, 1, 60);
    const second = await checkRateLimit(key, 1, 60);

    expect(first.allowed).toBe(true);
    expect(second.allowed).toBe(false);
    expect(errorSpy).toHaveBeenCalled();
    const logged = errorSpy.mock.calls
      .flat()
      .map((arg) => (typeof arg === "string" ? arg : String(arg)))
      .join("\n");
    expect(logged).toContain("redis unavailable");
    expect(logged).not.toContain("upstash-test-token");
  });

  it("passes the namespaced key to Redis INCR", async () => {
    mockIncr.mockResolvedValue(1);
    mockExpire.mockResolvedValue(1);
    const key = rateLimitKey("login-ip", "198.51.100.10");
    const result = await checkRateLimit(key, 5, 60);
    expect(result.allowed).toBe(true);
    expect(mockIncr).toHaveBeenCalledWith(key);
    expect(key.startsWith("rl:")).toBe(true);
    expect(mockExpire).toHaveBeenCalledWith(key, 60);
  });
});
