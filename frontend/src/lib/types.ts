// ============================================================
// ARGUS — Shared TypeScript types (mirrors backend Pydantic models)
// ============================================================

// ---- Finding -----------------------------------------------

export type SeverityLevel = "info" | "low" | "medium" | "high" | "critical";
export type NodeStateType = "discovered" | "probing" | "exploitable" | "chained";

export interface Finding {
  id: string;                     // ULID
  layer: number;                  // 1–8
  title: string;
  severity: SeverityLevel;
  owasp_ref: string | null;       // e.g. "LLM01:2025"
  mitre_ref: string | null;       // e.g. "T1046"
  evidence: Record<string, unknown>;
  exploitable: boolean;
  confidence: number;             // 0–1
  node_state: NodeStateType;
}

// ---- Chain -------------------------------------------------

export interface Remediation {
  layer: number;
  action: string;
  ref: string;
}

export interface Chain {
  id: string;
  steps: string[];                // ordered Finding IDs
  narrative: string;
  exploitability: number;         // 0–1
  impact: number;                 // 0–1
  novelty: number;                // 0–1  high = novel technique
  priority: number;               // 0–1  composite score
  remediations: Remediation[];
}

// ---- StreamEvent -------------------------------------------

export type EventType =
  | "node_state"
  | "reasoning_token"
  | "chain_found"
  | "layer_done"
  | "error"
  | "complete";

export interface NodeStatePayload {
  finding_id: string;
  state: NodeStateType;
}

export interface ReasoningTokenPayload {
  token: string;
}

export interface LayerDonePayload {
  layer: number;
  finding_count: number;
}

export interface ErrorPayload {
  message: string;
}

export interface CompletePayload {
  session_id: string;
}

export interface StreamEvent {
  type: EventType;
  payload: Record<string, unknown>;
  ts: number;
}

// ---- Session -----------------------------------------------

export type SessionStatus = "pending" | "running" | "complete" | "error";
export type AnalysisMode = "basic" | "advanced";

export interface AnalysisTarget {
  url?: string;
  llm_endpoint?: string;
  description?: string;
}

export interface Session {
  id: string;
  mode: AnalysisMode;
  target: AnalysisTarget;
  status: SessionStatus;
  active_layers: number[];
  finding_ids: string[];
  chain_ids: string[];
  created_at: number;
  updated_at: number;
  error?: string;
}

// ---- API request/response ----------------------------------

export interface StartAnalysisRequest {
  mode: AnalysisMode;
  target: AnalysisTarget;
  layers?: number[];              // advanced: override active layers
}

export interface StartAnalysisResponse {
  session_id: string;
  stream_url: string;
}
