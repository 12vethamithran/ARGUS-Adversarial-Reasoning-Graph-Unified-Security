import { useRef, useState } from "react";
import { Plus, Minus, Maximize2, X, CircleAlert, ShieldCheck, Radar } from "lucide-react";
import { useSessionStore } from "../../store/sessionStore";
import { useForceGraph, type GraphControls } from "./useForceGraph";
import { describeFinding, evidenceEntries } from "../../lib/findingKb";
import type { SeverityLevel } from "../../lib/types";

const SEV_TEXT: Record<SeverityLevel, string> = {
  critical: "text-severity-critical", high: "text-severity-high",
  medium: "text-severity-medium", low: "text-severity-low", info: "text-severity-info",
};

const NODE_LEGEND = [
  { state: "discovered", v: "--node-discovered" },
  { state: "probing", v: "--node-probing" },
  { state: "exploitable", v: "--node-exploitable" },
  { state: "chained", v: "--node-chained" },
];

export function AttackGraph() {
  const svgRef = useRef<SVGSVGElement>(null);
  const controlsRef = useRef<GraphControls | null>(null);
  const { findings, chains, isRunning, session } = useSessionStore();
  const [selectedId, setSelectedId] = useState<string | null>(null);

  useForceGraph(svgRef, findings, chains, setSelectedId, controlsRef);

  const empty = Object.keys(findings).length === 0;
  const selected = selectedId ? findings[selectedId] : null;
  const detail = selected ? describeFinding(selected) : null;

  return (
    <div className="argus-panel-shell relative w-full h-full bg-bg-base scanlines rounded-lg border border-line/15 overflow-hidden">
      {/* Header */}
      <div className="absolute top-3 left-4 flex items-center gap-2 z-10">
        <span className="text-xs font-mono text-text-muted uppercase tracking-widest">Attack Graph</span>
        {isRunning && (
          <span className="flex gap-1 items-center">
            <span className="w-1.5 h-1.5 rounded-full bg-accent animate-ping" />
            <span className="text-xs text-accent font-mono">LIVE</span>
          </span>
        )}
        {!isRunning && session?.status === "complete" && (
          <span className="text-xs text-accent-green font-mono">COMPLETE</span>
        )}
      </div>

      {/* Legend */}
      <div className="absolute top-3 right-4 flex gap-3 z-10">
        {NODE_LEGEND.map(({ state, v }) => (
          <div key={state} className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full" style={{ background: `rgb(var(${v}))` }} />
            <span className="text-xs text-text-muted font-mono capitalize hidden sm:block">{state}</span>
          </div>
        ))}
      </div>

      {/* Graph or empty state */}
      {empty ? (
        <div className="flex flex-col items-center justify-center h-full text-center gap-3 p-8">
          <div className="w-16 h-16 rounded-full border border-line/20 flex items-center justify-center">
            <Radar className="w-7 h-7 text-accent/35" />
          </div>
          <p className="text-text-muted text-sm font-mono">
            {session ? "Waiting for first finding…" : "Configure a target and start analysis"}
          </p>
        </div>
      ) : (
        <svg ref={svgRef} className="w-full h-full" />
      )}

      {/* Zoom controls */}
      {!empty && (
        <div className="absolute bottom-3 right-3 flex flex-col gap-1 z-10">
          <CtrlBtn onClick={() => controlsRef.current?.zoomIn()} label="Zoom in"><Plus className="w-3.5 h-3.5" /></CtrlBtn>
          <CtrlBtn onClick={() => controlsRef.current?.zoomOut()} label="Zoom out"><Minus className="w-3.5 h-3.5" /></CtrlBtn>
          <CtrlBtn onClick={() => controlsRef.current?.reset()} label="Reset view"><Maximize2 className="w-3.5 h-3.5" /></CtrlBtn>
        </div>
      )}

      {/* Hint */}
      {!empty && !selected && (
        <div className="absolute bottom-3 left-4 text-[11px] font-mono text-text-muted z-10">
          {Object.keys(findings).length} findings · {chains.length} chain{chains.length !== 1 ? "s" : ""}
          <span className="ml-2 opacity-60">· click a node · drag to reposition</span>
        </div>
      )}

      {/* Detail panel */}
      {selected && detail && (
        <div className="absolute top-12 right-3 bottom-3 w-72 max-w-[80%] z-20 glass rounded-xl border border-accent/25 p-4 overflow-y-auto animate-fade-in">
          <button onClick={() => setSelectedId(null)}
            className="absolute top-3 right-3 text-text-muted hover:text-text-primary" aria-label="Close">
            <X className="w-4 h-4" />
          </button>
          <div className="flex items-center gap-2 mb-2">
            <span className="text-[10px] font-mono text-accent">L{selected.layer} · {detail.layerName}</span>
            <span className={`text-[10px] font-mono uppercase ${SEV_TEXT[selected.severity]}`}>{selected.severity}</span>
          </div>
          <p className="text-sm font-semibold text-text-primary leading-snug pr-5">{selected.title}</p>

          <div className="flex flex-wrap gap-1 mt-2">
            {detail.refs.map((r) => (
              <span key={r} className="text-[10px] font-mono text-text-secondary bg-overlay/60 px-1.5 py-0.5 rounded">{r}</span>
            ))}
            <span className="text-[10px] font-mono text-text-muted ml-auto">conf {(selected.confidence * 100).toFixed(0)}%</span>
          </div>

          <div className="mt-3 flex items-center gap-2 text-[11px] font-mono">
            {selected.exploitable ? (
              <span className="flex items-center gap-1 text-severity-critical"><CircleAlert className="w-3.5 h-3.5" /> Exploitable</span>
            ) : (
              <span className="flex items-center gap-1 text-accent-green"><ShieldCheck className="w-3.5 h-3.5" /> Not directly exploitable</span>
            )}
          </div>

          <Field label="What it is" text={detail.description} />
          <Field label="Impact" text={detail.impact} />
          <Field label="Remediation" text={detail.remediation} />

          {evidenceEntries(selected).length > 0 && (
            <div className="mt-3">
              <p className="text-[10px] font-mono uppercase tracking-widest text-text-muted mb-1">Evidence</p>
              <div className="rounded-md bg-bg/60 border border-line/10 p-2 space-y-1">
                {evidenceEntries(selected).map(([k, v]) => (
                  <div key={k} className="text-[10px] font-mono flex gap-2">
                    <span className="text-accent shrink-0">{k}</span>
                    <span className="text-text-secondary break-all">{v}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function CtrlBtn({ children, onClick, label }: { children: React.ReactNode; onClick: () => void; label: string }) {
  return (
    <button onClick={onClick} aria-label={label}
      className="w-7 h-7 rounded-md glass border border-line/20 flex items-center justify-center text-text-secondary hover:text-accent hover:border-accent/40 transition-all">
      {children}
    </button>
  );
}

function Field({ label, text }: { label: string; text: string }) {
  return (
    <div className="mt-3">
      <p className="text-[10px] font-mono uppercase tracking-widest text-text-muted mb-1">{label}</p>
      <p className="text-[11px] text-text-secondary leading-relaxed">{text}</p>
    </div>
  );
}
