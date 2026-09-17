import { explainAnomalies } from "@/lib/anomaly/llm";
import {
  detectAnomalies,
  loadRuleConfigFromEnv,
} from "@/lib/anomaly/rules";
import type { LogEntry } from "@/lib/types";

export interface PersistedAnomaly {
  session_id: string;
  entry_id: number;
  rule_triggered: string;
  explanation: string;
  confidence: number;
  recommended_action: string;
  severity: string;
}

export async function runAnomalyPipeline(
  sessionId: string,
  entries: Array<LogEntry & { id: number }>,
): Promise<PersistedAnomaly[]> {
  const config = loadRuleConfigFromEnv();
  const plain: LogEntry[] = entries.map(
    ({ timestamp, sourceIp, destUrl, action, bytesSent, bytesReceived, userAgent, rawLine }) => ({
      timestamp,
      sourceIp,
      destUrl,
      action,
      bytesSent,
      bytesReceived,
      userAgent,
      rawLine,
    }),
  );

  const hits = detectAnomalies(plain, config);
  const explained = await explainAnomalies(plain, hits);

  return explained.map((item) => {
    const row = entries[item.hit.entryIndex];
    return {
      session_id: sessionId,
      entry_id: row.id,
      rule_triggered: item.hit.rule,
      explanation: item.explanation.explanation,
      confidence: item.explanation.confidence,
      recommended_action: item.explanation.recommendedAction,
      severity: item.explanation.severity,
    };
  });
}
