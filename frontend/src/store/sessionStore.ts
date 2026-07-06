import { create } from "zustand";
import type { Finding, Chain, Session, AnalysisMode, AnalysisTarget, StreamEvent } from "../lib/types";

interface SessionState {
  session: Session | null;
  mode: AnalysisMode;
  isRunning: boolean;
  findings: Record<string, Finding>;
  chains: Chain[];
  reasoningLog: string[];
  layerStatus: Record<number, { done: boolean; findingCount: number }>;
  setMode: (mode: AnalysisMode) => void;
  setSessionId: (sessionId: string) => void;
  startSession: (target: AnalysisTarget) => void;
  applyEvent: (event: StreamEvent) => void;
  reset: () => void;
}

export const useSessionStore = create<SessionState>((set, get) => ({
  session: null,
  mode: "basic",
  isRunning: false,
  findings: {},
  chains: [],
  reasoningLog: [],
  layerStatus: {},

  setMode: (mode) => set({ mode }),

  setSessionId: (sessionId) => set((state) => ({
    session: state.session ? { ...state.session, id: sessionId } : state.session,
  })),

  startSession: (target) => {
    const { mode } = get();
    const session: Session = {
      id: crypto.randomUUID(),
      mode,
      target,
      status: "running",
      active_layers: mode === "basic" ? [1, 2, 3] : [1, 2, 3, 4, 5, 6, 7, 8],
      finding_ids: [],
      chain_ids: [],
      created_at: Date.now() / 1000,
      updated_at: Date.now() / 1000,
    };
    set({ session, isRunning: true, findings: {}, chains: [], reasoningLog: [], layerStatus: {} });
  },

  applyEvent: (event: StreamEvent) => {
    const state = get();

    switch (event.type) {
      case "node_state": {
        const p = event.payload as any;
        const { finding_id, state: nodeState, finding: fullFinding } = p;

        if (fullFinding) {
          // Full finding data included — use it directly
          const f: Finding = { ...fullFinding, node_state: nodeState };
          set({ findings: { ...state.findings, [finding_id]: f } });
        } else if (state.findings[finding_id]) {
          // Update existing finding's node_state only
          set({
            findings: {
              ...state.findings,
              [finding_id]: { ...state.findings[finding_id], node_state: nodeState },
            },
          });
        } else {
          // Fallback placeholder (shouldn't happen with new backend)
          set({
            findings: {
              ...state.findings,
              [finding_id]: {
                id: finding_id, layer: 0, title: "Analyzing...",
                severity: "info", owasp_ref: null, mitre_ref: null,
                evidence: {}, exploitable: false, confidence: 0.5,
                node_state: nodeState,
              },
            },
          });
        }
        break;
      }

      case "chain_found": {
        const chain = event.payload as unknown as Chain;
        const updatedFindings = { ...state.findings };
        for (const fid of chain.steps) {
          if (updatedFindings[fid]) {
            updatedFindings[fid] = { ...updatedFindings[fid], node_state: "chained" };
          }
        }
        set({ chains: [...state.chains, chain], findings: updatedFindings });
        break;
      }

      case "reasoning_token": {
        const { token } = event.payload as { token: string };
        set({ reasoningLog: [...state.reasoningLog, token] });
        break;
      }

      case "layer_done": {
        const { layer, finding_count } = event.payload as { layer: number; finding_count: number };
        set({ layerStatus: { ...state.layerStatus, [layer]: { done: true, findingCount: finding_count } } });
        break;
      }

      case "complete": {
        const sessionId = (event.payload as any).session_id;
        set({
          isRunning: false,
          session: state.session
            ? { ...state.session, id: sessionId || state.session.id, status: "complete" }
            : null,
        });
        break;
      }

      case "error": {
        set({ isRunning: false, session: state.session ? { ...state.session, status: "error" } : null });
        break;
      }
    }
  },

  reset: () => set({
    session: null, isRunning: false, findings: {},
    chains: [], reasoningLog: [], layerStatus: {},
  }),
}));
