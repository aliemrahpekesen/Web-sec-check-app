// Shared, framework-neutral types used across the scanner, worker, API, and UI.

export type LogLevel =
  | "info"
  | "step"
  | "tool"
  | "finding"
  | "warn"
  | "error"
  | "success";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export type ScanProfile = "PASSIVE" | "STANDARD" | "DEEP";

export interface LiveEvent {
  type: "log" | "finding" | "status" | "done";
  seq: number;
  at: string;
  level?: LogLevel;
  message?: string;
  meta?: Record<string, unknown>;
  finding?: FindingDraft;
  status?: string;
  riskScore?: number;
  grade?: string;
}

export interface FindingDraft {
  checkId: string;
  title: string;
  severity: Severity;
  cwe?: string;
  owasp?: string;
  location: string;
  description: string;
  evidence?: string;
  remediation: string;
  confidence?: "tentative" | "firm" | "confirmed";
}

// A single observation produced by an analyzer/tool. The orchestrator (AI or
// deterministic) turns raw observations into findings via the knowledge base.
export interface Observation {
  checkId: string;
  location: string;
  detail: string;
  evidence?: string;
  // Present means "this is a problem"; absent means informational only.
  positive?: boolean;
}

// Emitter passed into the scanning engine so every step can stream live.
export type Emit = (event: Omit<LiveEvent, "seq" | "at">) => Promise<void>;
