import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  explainAnomalies,
  fallbackExplanation,
} from "@/lib/anomaly/llm";
import { loadRuleConfigFromEnv } from "@/lib/anomaly/rules";
import type { LogEntry, RuleHit } from "@/lib/types";

const { mockCreate } = vi.hoisted(() => ({
  mockCreate: vi.fn(),
}));

vi.mock("@anthropic-ai/sdk", () => ({
  default: class Anthropic {
    constructor(_opts: { apiKey: string }) {}
    messages = { create: mockCreate };
  },
}));

const FAKE_KEY = "sk-ant-test-secret";

function sampleEntry(): LogEntry {
  return {
    timestamp: "2024-03-11T15:00:00.000Z",
    sourceIp: "10.0.0.1",
    destUrl: "https://www.google.com/",
    action: "allowed",
    bytesSent: 500,
    bytesReceived: 1500,
    userAgent: "Mozilla/5.0",
    rawLine: "raw",
  };
}

function serializeLogs(
  spies: Array<ReturnType<typeof vi.spyOn>>,
): string {
  return spies
    .flatMap((spy) => spy.mock.calls)
    .map((args) =>
      args
        .map((arg) => {
          if (typeof arg === "string") return arg;
          if (arg instanceof Error) return `${arg.name} ${arg.message}`;
          try {
            return JSON.stringify(arg) ?? "";
          } catch {
            return String(arg);
          }
        })
        .join(" "),
    )
    .join("\n");
}

describe("explainAnomalies logging", () => {
  const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
  const infoSpy = vi.spyOn(console, "info").mockImplementation(() => {});
  let previousKey: string | undefined;

  beforeEach(() => {
    previousKey = process.env.ANTHROPIC_API_KEY;
    mockCreate.mockReset();
    errorSpy.mockClear();
    warnSpy.mockClear();
    infoSpy.mockClear();
  });

  afterEach(() => {
    if (previousKey === undefined) {
      delete process.env.ANTHROPIC_API_KEY;
    } else {
      process.env.ANTHROPIC_API_KEY = previousKey;
    }
  });

  afterEach(() => {
    errorSpy.mockClear();
    warnSpy.mockClear();
    infoSpy.mockClear();
  });

  it("logs console.error on a thrown API error and still returns template explanations", async () => {
    process.env.ANTHROPIC_API_KEY = FAKE_KEY;
    const apiError = Object.assign(new Error("overloaded_error"), {
      name: "APIError",
      status: 529,
    });
    mockCreate.mockRejectedValue(apiError);

    const entries = [sampleEntry()];
    const hits: RuleHit[] = [{ entryIndex: 0, rule: "off_hours" }];
    const result = await explainAnomalies(entries, hits);

    expect(errorSpy).toHaveBeenCalled();
    const logged = serializeLogs([errorSpy, warnSpy, infoSpy]);
    expect(logged).toContain("APIError");
    expect(logged).toContain("529");
    expect(logged).toContain("overloaded_error");
    expect(logged).not.toContain(FAKE_KEY);

    expect(result).toHaveLength(1);
    const context = {
      entryCount: 1,
      rateWindowSeconds: loadRuleConfigFromEnv().rateWindowSeconds,
    };
    expect(result[0].explanation).toEqual(
      fallbackExplanation("off_hours", entries[0], context),
    );
  });

  it("calls console.info on success with sent and returned counts", async () => {
    process.env.ANTHROPIC_API_KEY = FAKE_KEY;
    mockCreate.mockResolvedValue({
      content: [
        {
          type: "tool_use",
          input: {
            explanations: [
              {
                id: 0,
                explanation: "After-hours access from this IP.",
                confidence: 0.9,
                severity: "medium",
                recommendedAction: "Confirm expected access",
              },
            ],
          },
        },
      ],
    });

    const entries = [sampleEntry()];
    const hits: RuleHit[] = [{ entryIndex: 0, rule: "off_hours" }];
    const result = await explainAnomalies(entries, hits);

    expect(infoSpy).toHaveBeenCalled();
    const logged = serializeLogs([infoSpy, errorSpy, warnSpy]);
    expect(logged).toContain("sent 1");
    expect(logged).toContain("returned 1");
    expect(logged).not.toContain(FAKE_KEY);
    expect(result[0].explanation.explanation).toBe(
      "After-hours access from this IP.",
    );
  });

  it("warns once when the API key is missing and there are hits to explain", async () => {
    delete process.env.ANTHROPIC_API_KEY;
    const entries = [sampleEntry()];
    const hits: RuleHit[] = [{ entryIndex: 0, rule: "off_hours" }];
    await explainAnomalies(entries, hits);
    expect(warnSpy).toHaveBeenCalledWith(
      "ANTHROPIC_API_KEY not set, using template explanations",
    );
    expect(mockCreate).not.toHaveBeenCalled();
  });
});
