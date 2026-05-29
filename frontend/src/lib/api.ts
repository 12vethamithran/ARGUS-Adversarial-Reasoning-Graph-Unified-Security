// ============================================================
// ARGUS — Typed API client
// ============================================================
import type { AnalysisTarget, AnalysisMode, StreamEvent } from "./types";

const BASE = import.meta.env.VITE_API_URL ?? "";

// ── Helpers ──────────────────────────────────────────────────

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...init?.headers },
    ...init,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`[ARGUS API] ${res.status} ${path}: ${text}`);
  }
  return res.json() as Promise<T>;
}

// ── Analysis ─────────────────────────────────────────────────

export interface StartAnalysisBody {
  mode: AnalysisMode;
  target: AnalysisTarget;
  layers?: number[];
}

/**
 * POST /api/analyze — returns an SSE EventSource-compatible response.
 * The caller receives a ReadableStream of StreamEvent objects.
 * sessionId is parsed from the X-Session-Id response header.
 */
export async function startAnalysis(
  body: StartAnalysisBody,
  onEvent: (event: StreamEvent) => void,
  onSessionId?: (id: string) => void,
): Promise<void> {
  const res = await fetch(`${BASE}/api/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`Analysis failed: ${res.status} ${text}`);
  }

  const sessionId = res.headers.get("X-Session-Id");
  if (sessionId && onSessionId) onSessionId(sessionId);

  const reader = res.body?.getReader();
  if (!reader) throw new Error("No response body");

  const decoder = new TextDecoder();
  let buffer = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop() ?? "";

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed.startsWith("data:")) continue;
      const json = trimmed.slice(5).trim();
      if (!json) continue;
      try {
        onEvent(JSON.parse(json) as StreamEvent);
      } catch {
        // ignore malformed frames
      }
    }
  }
}

// ── Sessions ─────────────────────────────────────────────────

export interface SessionMeta {
  id: string;
  status: string;
  created_at: number;
}

export const listSessions = (): Promise<{ sessions: SessionMeta[] }> =>
  request("/api/sessions");

export const getSession = (id: string): Promise<Record<string, unknown>> =>
  request(`/api/sessions/${id}`);

export const deleteSession = (id: string): Promise<{ deleted: boolean }> =>
  request(`/api/sessions/${id}`, { method: "DELETE" });

// ── Reports ──────────────────────────────────────────────────

/** Open the HTML report in a new tab. */
export function openHtmlReport(sessionId: string): void {
  window.open(`${BASE}/api/reports/${sessionId}/html`, "_blank");
}

/** Trigger PDF download. */
export function downloadPdfReport(sessionId: string): void {
  const a = document.createElement("a");
  a.href = `${BASE}/api/reports/${sessionId}/pdf`;
  a.download = `argus-report-${sessionId.slice(0, 8)}.pdf`;
  a.click();
}

/** Trigger STIX 2.1 JSON download. */
export function downloadStixReport(sessionId: string): void {
  const a = document.createElement("a");
  a.href = `${BASE}/api/reports/${sessionId}/stix`;
  a.download = `argus-stix-${sessionId.slice(0, 8)}.json`;
  a.click();
}

export const generateReports = (sessionId: string) =>
  request(`/api/reports/${sessionId}/generate`, { method: "POST" });
