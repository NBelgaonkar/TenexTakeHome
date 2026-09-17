import Anthropic from "@anthropic-ai/sdk";
import { ruleLabel } from "@/lib/anomaly/labels";
import type {
  AnomalyExplanation,
  AnomalyRule,
  LogEntry,
  RuleHit,
  Severity,
} from "@/lib/types";
import { LLM_ANOMALY_CAP } from "@/lib/types";

export interface FlaggedAnomaly {
  hit: RuleHit;
  entry: LogEntry;
  context: Record<string, string | number>;
  explanation: AnomalyExplanation;
}

interface LlmItem {
  id: number;
  explanation: string;
  confidence: number;
  severity: Severity;
  recommendedAction: string;
}

/**
 * Stage 2 — LLM explanation pass.
 * Only flagged Stage-1 rows are sent, capped, and batched into a single Claude call.
 * If ANTHROPIC_API_KEY is missing or the call fails, heuristic copy is used so
 * the rest of the demo still works.
 */
export async function explainAnomalies(
  entries: LogEntry[],
  hits: RuleHit[],
): Promise<FlaggedAnomaly[]> {
  const limited = hits.slice(0, LLM_ANOMALY_CAP);
  const flagged = limited.map((hit) => {
    const entry = entries[hit.entryIndex];
    const context = buildContext(entries, hit);
    return {
      hit,
      entry,
      context,
      explanation: fallbackExplanation(hit.rule, entry, context),
    };
  });

  if (flagged.length === 0) return flagged;

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return flagged;

  try {
    const llm = await callClaude(apiKey, flagged);
    return flagged.map((item, index) => {
      const match = llm.find((row) => row.id === index);
      if (!match) return item;
      return {
        ...item,
        explanation: {
          explanation: match.explanation,
          confidence: clampConfidence(match.confidence),
          severity: normalizeSeverity(match.severity),
          recommendedAction: match.recommendedAction,
        },
      };
    });
  } catch {
    return flagged;
  }
}

function buildContext(
  entries: LogEntry[],
  hit: RuleHit,
): Record<string, string | number> {
  const entry = entries[hit.entryIndex];
  const sameIp = entries.filter((e) => e.sourceIp === entry.sourceIp).length;
  const totals = entries.map((e) => e.bytesSent + e.bytesReceived);
  const median =
    totals.length === 0
      ? 0
      : [...totals].sort((a, b) => a - b)[Math.floor(totals.length / 2)];

  return {
    rule: hit.rule,
    sourceIp: entry.sourceIp,
    destUrl: entry.destUrl,
    action: entry.action,
    bytes: entry.bytesSent + entry.bytesReceived,
    sessionSize: entries.length,
    sameIpCount: sameIp,
    sessionMedianBytes: median,
  };
}

export function fallbackExplanation(
  rule: AnomalyRule,
  entry: LogEntry,
  context: Record<string, string | number>,
): AnomalyExplanation {
  switch (rule) {
    case "high_request_rate":
      return {
        explanation: `Source IP ${entry.sourceIp} generated a burst of ${context.sameIpCount} requests in this session, exceeding the sliding-window rate threshold.`,
        confidence: 0.82,
        severity: "high",
        recommendedAction: "Investigate source IP",
      };
    case "off_hours":
      return {
        explanation: `Activity from ${entry.sourceIp} to ${entry.destUrl} occurred outside configured business hours.`,
        confidence: 0.7,
        severity: "medium",
        recommendedAction: "Confirm expected after-hours access",
      };
    case "large_transfer":
      return {
        explanation: `Transfer of ${context.bytes} bytes is far above the session median (${context.sessionMedianBytes} bytes) and the absolute floor.`,
        confidence: 0.78,
        severity: "high",
        recommendedAction: "Review destination and data-loss risk",
      };
    case "rare_domain":
      return {
        explanation: `Destination ${entry.destUrl} is rare in this session or uses a commonly abused TLD.`,
        confidence: 0.66,
        severity: "medium",
        recommendedAction: "Check domain reputation",
      };
  }
}

async function callClaude(
  apiKey: string,
  flagged: FlaggedAnomaly[],
): Promise<LlmItem[]> {
  const client = new Anthropic({ apiKey });
  const model = process.env.ANTHROPIC_MODEL || "claude-sonnet-4-5";

  const payload = flagged.map((item, id) => ({
    id,
    rule: item.hit.rule,
    ruleLabel: ruleLabel(item.hit.rule),
    timestamp: item.entry.timestamp,
    sourceIp: item.entry.sourceIp,
    destUrl: item.entry.destUrl,
    action: item.entry.action,
    bytesSent: item.entry.bytesSent,
    bytesReceived: item.entry.bytesReceived,
    context: item.context,
  }));

  const response = await client.messages.create({
    model,
    max_tokens: 4096,
    tools: [
      {
        name: "record_anomaly_explanations",
        description:
          "Submit SOC-analyst explanations for each flagged log anomaly.",
        input_schema: {
          type: "object",
          properties: {
            explanations: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  id: { type: "number" },
                  explanation: { type: "string" },
                  confidence: { type: "number" },
                  severity: {
                    type: "string",
                    enum: ["low", "medium", "high"],
                  },
                  recommendedAction: { type: "string" },
                },
                required: [
                  "id",
                  "explanation",
                  "confidence",
                  "severity",
                  "recommendedAction",
                ],
              },
            },
          },
          required: ["explanations"],
        },
      },
    ],
    tool_choice: { type: "tool", name: "record_anomaly_explanations" },
    messages: [
      {
        role: "user",
        content: `You are assisting a SOC analyst. For each flagged ZScaler web-proxy event, write a 1–2 sentence plain-English explanation, a confidence 0–1, severity, and a short recommended action (e.g. "investigate source IP" or "likely false positive, monitor"). Do not invent fields that are not in the JSON. Events:\n${JSON.stringify(payload)}`,
      },
    ],
  });

  const tool = response.content.find((block) => block.type === "tool_use");
  if (!tool || tool.type !== "tool_use") return [];
  return parseLlmItems(tool.input);
}

function parseLlmItems(input: unknown): LlmItem[] {
  if (!input || typeof input !== "object" || !("explanations" in input)) {
    return [];
  }
  const explanations = (input as { explanations: unknown }).explanations;
  if (!Array.isArray(explanations)) return [];
  const items: LlmItem[] = [];
  for (const row of explanations) {
    if (!row || typeof row !== "object") continue;
    const rec = row as Record<string, unknown>;
    if (typeof rec.id !== "number") continue;
    if (typeof rec.explanation !== "string") continue;
    if (typeof rec.confidence !== "number") continue;
    if (typeof rec.severity !== "string") continue;
    if (typeof rec.recommendedAction !== "string") continue;
    items.push({
      id: rec.id,
      explanation: rec.explanation,
      confidence: rec.confidence,
      severity: normalizeSeverity(rec.severity),
      recommendedAction: rec.recommendedAction,
    });
  }
  return items;
}

function clampConfidence(value: number): number {
  if (!Number.isFinite(value)) return 0.5;
  return Math.min(1, Math.max(0, Math.round(value * 100) / 100));
}

function normalizeSeverity(value: string): Severity {
  if (value === "low" || value === "medium" || value === "high") return value;
  return "medium";
}
