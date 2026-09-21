import { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { config, middleware } from "@/middleware";

const {
  mockCheckRateLimit,
  mockClientIp,
  mockCreateClient,
  mockRequireUser,
  mockRequireOwnedSession,
  mockGetUser,
} = vi.hoisted(() => ({
  mockCheckRateLimit: vi.fn(),
  mockClientIp: vi.fn(() => "203.0.113.10"),
  mockCreateClient: vi.fn(),
  mockRequireUser: vi.fn(),
  mockRequireOwnedSession: vi.fn(),
  mockGetUser: vi.fn(),
}));

vi.mock("@/lib/rate-limit", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/rate-limit")>();
  return {
    ...actual,
    checkRateLimit: mockCheckRateLimit,
    clientIp: mockClientIp,
  };
});

vi.mock("@/lib/supabase/server", () => ({
  createClient: mockCreateClient,
}));

vi.mock("@/lib/auth", () => ({
  requireUser: mockRequireUser,
  requireOwnedSession: mockRequireOwnedSession,
}));

vi.mock("@supabase/ssr", () => ({
  createServerClient: vi.fn(() => ({
    auth: { getUser: mockGetUser },
  })),
}));

import { POST as loginPost } from "@/app/api/auth/login/route";
import { POST as logoutPost } from "@/app/api/auth/logout/route";
import { POST as uploadPost } from "@/app/api/logs/upload/route";
import { GET as summaryGet } from "@/app/api/logs/[sessionId]/summary/route";
import { GET as anomaliesGet } from "@/app/api/logs/[sessionId]/anomalies/route";

const signInWithPassword = vi.fn();
const signOut = vi.fn();

function jsonRequest(url: string, body: unknown): Request {
  return new Request(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

function matcherRegex(): RegExp {
  return new RegExp(`^${config.matcher[0]}$`);
}

describe("login route", () => {
  beforeEach(() => {
    mockCheckRateLimit.mockReset();
    mockCheckRateLimit.mockResolvedValue({
      allowed: true,
      remaining: 4,
      retryAfterSeconds: 0,
    });
    mockClientIp.mockReturnValue("203.0.113.10");
    signInWithPassword.mockReset();
    mockCreateClient.mockReturnValue({
      auth: { signInWithPassword, signOut },
    });
  });

  it("returns 400 on invalid JSON body", async () => {
    const res = await loginPost(
      jsonRequest("http://localhost/api/auth/login", "not-json"),
    );
    expect(res.status).toBe(400);
    await expect(res.json()).resolves.toEqual({ error: "Invalid request body." });
  });

  it("returns 400 on missing email or password", async () => {
    const res = await loginPost(
      jsonRequest("http://localhost/api/auth/login", { email: "a@b.com" }),
    );
    expect(res.status).toBe(400);
    await expect(res.json()).resolves.toEqual({
      error: "Email and password are required.",
    });
  });

  it("returns 401 with a generic message when Supabase returns an error", async () => {
    signInWithPassword.mockResolvedValue({
      data: { user: null, session: null },
      error: { message: "Invalid login credentials" },
    });
    const res = await loginPost(
      jsonRequest("http://localhost/api/auth/login", {
        email: "analyst@example.com",
        password: "wrong",
      }),
    );
    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body).toEqual({ error: "Invalid credentials." });
    expect(JSON.stringify(body)).not.toContain("Invalid login credentials");
    expect(JSON.stringify(body)).not.toMatch(/exist|unknown user|no user/i);
  });

  it("returns 429 when the limiter denies", async () => {
    mockCheckRateLimit.mockResolvedValue({
      allowed: false,
      remaining: 0,
      retryAfterSeconds: 42,
    });
    const res = await loginPost(
      jsonRequest("http://localhost/api/auth/login", {
        email: "analyst@example.com",
        password: "secret",
      }),
    );
    expect(res.status).toBe(429);
    expect(res.headers.get("Retry-After")).toBe("42");
    await expect(res.json()).resolves.toEqual({
      error: "Too many login attempts. Try again shortly.",
    });
  });

  it("returns 200 on success and rate-limits by IP and lowercased email", async () => {
    signInWithPassword.mockResolvedValue({
      data: { user: { id: "u1" }, session: {} },
      error: null,
    });
    const res = await loginPost(
      jsonRequest("http://localhost/api/auth/login", {
        email: "Analyst@Example.com",
        password: "correct",
      }),
    );
    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({ ok: true });
    expect(mockCheckRateLimit).toHaveBeenCalledWith(
      "rl:login:ip:203.0.113.10",
      5,
      60,
    );
    expect(mockCheckRateLimit).toHaveBeenCalledWith(
      "rl:login:email:analyst@example.com",
      10,
      15 * 60,
    );
  });
});

describe("logout route", () => {
  it("calls signOut and returns success", async () => {
    signOut.mockResolvedValue({ error: null });
    mockCreateClient.mockReturnValue({
      auth: { signInWithPassword, signOut },
    });
    const res = await logoutPost();
    expect(signOut).toHaveBeenCalled();
    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({ ok: true });
  });
});

describe("upload route", () => {
  beforeEach(() => {
    mockCheckRateLimit.mockReset();
    mockCheckRateLimit.mockResolvedValue({
      allowed: true,
      remaining: 9,
      retryAfterSeconds: 0,
    });
    mockRequireUser.mockReset();
  });

  it("returns 401 when getUser returns no user", async () => {
    mockRequireUser.mockResolvedValue({ user: null, supabase: {} });
    const res = await uploadPost(
      new Request("http://localhost/api/logs/upload", { method: "POST" }),
    );
    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body).toEqual({ error: "Unauthorized" });
    expect(mockCheckRateLimit).not.toHaveBeenCalled();
  });

  it("returns 429 when the upload limiter denies", async () => {
    mockRequireUser.mockResolvedValue({
      user: { id: "user-1" },
      supabase: {},
    });
    mockCheckRateLimit.mockResolvedValue({
      allowed: false,
      remaining: 0,
      retryAfterSeconds: 120,
    });
    const res = await uploadPost(
      new Request("http://localhost/api/logs/upload", { method: "POST" }),
    );
    expect(res.status).toBe(429);
    expect(res.headers.get("Retry-After")).toBe("120");
    await expect(res.json()).resolves.toEqual({
      error: "Upload rate limit exceeded. Try again later.",
    });
  });

  it("returns 400 when the file field is missing", async () => {
    mockRequireUser.mockResolvedValue({
      user: { id: "user-1" },
      supabase: {},
    });
    const res = await uploadPost(
      new Request("http://localhost/api/logs/upload", {
        method: "POST",
        body: new FormData(),
      }),
    );
    expect(res.status).toBe(400);
    await expect(res.json()).resolves.toEqual({ error: "Missing file field." });
  });
});

describe("summary and anomalies routes", () => {
  const params = { params: { sessionId: "sess-1" } };

  beforeEach(() => {
    mockRequireUser.mockReset();
    mockRequireOwnedSession.mockReset();
  });

  it("summary returns 401 when unauthenticated with no data", async () => {
    mockRequireUser.mockResolvedValue({ user: null, supabase: {} });
    const res = await summaryGet(
      new Request("http://localhost/api/logs/sess-1/summary"),
      params,
    );
    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body).toEqual({ error: "Unauthorized" });
    expect(Object.keys(body)).toEqual(["error"]);
    expect(mockRequireOwnedSession).not.toHaveBeenCalled();
  });

  it("anomalies returns 401 when unauthenticated with no data", async () => {
    mockRequireUser.mockResolvedValue({ user: null, supabase: {} });
    const res = await anomaliesGet(
      new Request("http://localhost/api/logs/sess-1/anomalies"),
      params,
    );
    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body).toEqual({ error: "Unauthorized" });
    expect(Object.keys(body)).toEqual(["error"]);
    expect(mockRequireOwnedSession).not.toHaveBeenCalled();
  });

  it("summary returns 404 when the session is not owned, with no data leaked", async () => {
    mockRequireUser.mockResolvedValue({
      user: { id: "user-1" },
      supabase: {},
    });
    mockRequireOwnedSession.mockResolvedValue({
      supabase: {},
      session: null,
    });
    const res = await summaryGet(
      new Request("http://localhost/api/logs/sess-1/summary"),
      params,
    );
    expect(res.status).toBe(404);
    const body = await res.json();
    expect(body).toEqual({ error: "Not found" });
    expect(Object.keys(body)).toEqual(["error"]);
    expect(JSON.stringify(body)).not.toContain("sess-1");
  });

  it("anomalies returns 404 when the session is not owned, with no data leaked", async () => {
    mockRequireUser.mockResolvedValue({
      user: { id: "user-1" },
      supabase: {},
    });
    mockRequireOwnedSession.mockResolvedValue({
      supabase: {},
      session: null,
    });
    const res = await anomaliesGet(
      new Request("http://localhost/api/logs/sess-1/anomalies"),
      params,
    );
    expect(res.status).toBe(404);
    const body = await res.json();
    expect(body).toEqual({ error: "Not found" });
    expect(Object.keys(body)).toEqual(["error"]);
    expect(JSON.stringify(body)).not.toContain("filename");
  });
});

describe("middleware", () => {
  beforeEach(() => {
    process.env.NEXT_PUBLIC_SUPABASE_URL = "https://example.supabase.co";
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY = "test-anon-key";
    mockGetUser.mockReset();
    mockGetUser.mockResolvedValue({ data: { user: null }, error: null });
  });

  it("matcher covers app and API routes and skips static assets", () => {
    const re = matcherRegex();
    expect(re.test("/upload")).toBe(true);
    expect(re.test("/results/abc")).toBe(true);
    expect(re.test("/api/logs/x")).toBe(true);
    expect(re.test("/login")).toBe(true);
    expect(re.test("/_next/static/chunk.js")).toBe(false);
    expect(re.test("/favicon.ico")).toBe(false);
    expect(re.test("/logo.svg")).toBe(false);
  });

  it("redirects unauthenticated page requests and rejects API logs", async () => {
    const upload = await middleware(
      new NextRequest("http://localhost:3000/upload"),
    );
    expect(upload.status).toBeGreaterThanOrEqual(300);
    expect(upload.status).toBeLessThan(400);
    expect(new URL(upload.headers.get("location") ?? "").pathname).toBe(
      "/login",
    );

    const results = await middleware(
      new NextRequest("http://localhost:3000/results/abc"),
    );
    expect(results.status).toBeGreaterThanOrEqual(300);
    expect(results.status).toBeLessThan(400);
    expect(new URL(results.headers.get("location") ?? "").pathname).toBe(
      "/login",
    );

    const api = await middleware(
      new NextRequest("http://localhost:3000/api/logs/x"),
    );
    expect(api.status).toBe(401);
    const body = await api.json();
    expect(body).toEqual({ error: "Unauthorized" });
  });

  it("lets unauthenticated users reach /login", async () => {
    const res = await middleware(new NextRequest("http://localhost:3000/login"));
    expect(res.status).toBe(200);
    expect(res.headers.get("location")).toBeNull();
  });
});
