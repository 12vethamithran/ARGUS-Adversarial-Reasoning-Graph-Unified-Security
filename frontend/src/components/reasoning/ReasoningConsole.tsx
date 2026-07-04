import { useEffect, useMemo, useRef } from "react";
import { BrainCircuit } from "lucide-react";
import { useSessionStore } from "../../store/sessionStore";

type LineKind = "header" | "arrow" | "score" | "system" | "layer" | "text";

function classify(line: string): LineKind {
  const t = line.trim();
  if (t.startsWith("──") || t.endsWith("──")) return "header";
  if (t.startsWith("→") || t.startsWith("->")) return "arrow";
  if (/^(Exploitability|Impact|Novelty|Priority)\b/i.test(t)) return "score";
  if (t.startsWith("[ARGUS]")) return "system";
  if (/^L\d\b/.test(t)) return "layer";
  return "text";
}

const KIND_CLS: Record<LineKind, string> = {
  header: "text-accent font-semibold tracking-wide mt-2 mb-0.5",
  arrow: "text-text-secondary pl-3 border-l border-accent/30 ml-0.5",
  score: "text-node-probing",
  system: "text-accent-green",
  layer: "text-text-primary",
  text: "text-text-secondary",
};

export function ReasoningConsole() {
  const { reasoningLog, isRunning, chains } = useSessionStore();
  const bottomRef = useRef<HTMLDivElement>(null);

  // Tokens may be partial fragments; stitch then split into clean lines.
  const lines = useMemo(
    () => reasoningLog.join("").split("\n").map((l) => l.replace(/\r$/, "")),
    [reasoningLog],
  );

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [reasoningLog]);

  const nonEmpty = lines.filter((l) => l.trim().length > 0).length;

  return (
    <div className="argus-panel-shell flex flex-col h-full bg-surface rounded-lg border border-line/15 overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-2 border-b border-line/10 shrink-0">
        <BrainCircuit className="w-3.5 h-3.5 text-accent" />
        <span className="text-xs font-mono text-text-muted uppercase tracking-widest">Reasoning Console</span>
        {isRunning && <span className="w-1.5 h-1.5 rounded-full bg-accent animate-pulse" />}
        <span className="ml-auto text-[10px] font-mono text-text-muted">
          {nonEmpty} lines · {chains.length} chain{chains.length !== 1 ? "s" : ""}
        </span>
      </div>

      <div className="flex-1 overflow-y-auto p-4 font-mono text-[11px] leading-relaxed">
        {nonEmpty === 0 ? (
          <p className="text-text-muted italic">Awaiting reasoning stream…</p>
        ) : (
          lines.map((line, i) => {
            if (!line.trim()) return <div key={i} className="h-1.5" />;
            const kind = classify(line);
            return <div key={i} className={`block ${KIND_CLS[kind]}`}>{line}</div>;
          })
        )}
        {isRunning && <span className="inline-block w-2 h-3 bg-accent cursor-blink ml-0.5 align-middle" />}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
