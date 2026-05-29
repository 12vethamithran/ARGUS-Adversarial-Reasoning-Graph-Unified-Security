import type { StreamEvent, AnalysisTarget, AnalysisMode } from "../lib/types";
import { useSessionStore } from "./sessionStore";
import { toast } from "../components/ui/Toast";

const API_BASE = import.meta.env.VITE_API_URL ?? "";

export function startAnalysisStream(
  target: AnalysisTarget,
  mode: AnalysisMode,
  layers?: number[]
): Promise<void> {
  const { applyEvent, startSession } = useSessionStore.getState();
  startSession(target);

  return (async () => {
    let response: Response;
    try {
      response = await fetch(`${API_BASE}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode, target, layers }),
      });
    } catch (e: any) {
      toast.error("Cannot reach backend — is it running on :8000?");
      throw e;
    }

    if (!response.ok) {
      toast.error(`Analysis error: ${response.statusText}`);
      throw new Error(response.statusText);
    }

    const reader = response.body!.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const chunks = buffer.split("\n\n");
      buffer = chunks.pop() ?? "";

      for (const chunk of chunks) {
        const line = chunk.trim();
        if (!line.startsWith("data:")) continue;
        const jsonStr = line.replace(/^data:\s*/, "");
        if (!jsonStr) continue;
        try {
          const event: StreamEvent = JSON.parse(jsonStr);
          applyEvent(event);
          if (event.type === "chain_found") {
            const p = event.payload as any;
            toast.success(`Attack chain found — priority ${((p.priority ?? 0) * 100).toFixed(0)}%`);
          }
          if (event.type === "complete") toast.success("Analysis complete");
          if (event.type === "error") toast.error((event.payload as any).message ?? "Analysis error");
        } catch {
          // malformed SSE chunk — skip
        }
      }
    }
  })();
}
