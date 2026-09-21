export interface LogEntry {
  timestamp: string;
  sourceIp: string;
  destUrl: string;
  action: string;
  bytesSent: number;
  bytesReceived: number;
  userAgent: string;
  rawLine: string;
}

export interface LogEntryRecord extends LogEntry {
  id: number;
  sessionId: string;
}

export type SessionStatus = "processing" | "complete" | "failed";

export interface LogSession {
  id: string;
  userId: string;
  filename: string;
  storagePath: string | null;
  uploadedAt: string;
  status: SessionStatus;
  totalEntries: number;
  anomalyCount: number;
}

export type AnomalyRule =
  | "high_request_rate"
  | "off_hours"
  | "large_transfer"
  | "rare_domain";

export type Severity = "low" | "medium" | "high";

export interface RuleHit {
  entryIndex: number;
  rule: AnomalyRule;
  /** Size of a grouped finding (high_request_rate burst). Defaults to 1. */
  entryCount?: number;
  /** Log indexes covered by a grouped finding, including entryIndex. */
  relatedEntryIndexes?: number[];
}

export interface AnomalyExplanation {
  explanation: string;
  confidence: number;
  severity: Severity;
  recommendedAction: string;
}

export interface TimelineBucket {
  hour: string;
  count: number;
}

export const MAX_UPLOAD_BYTES = 10 * 1024 * 1024;
export const ALLOWED_EXTENSIONS = [".log", ".txt"] as const;
export const DEFAULT_ENTRY_PAGE_SIZE = 200;
export const LLM_ANOMALY_CAP = 25;
