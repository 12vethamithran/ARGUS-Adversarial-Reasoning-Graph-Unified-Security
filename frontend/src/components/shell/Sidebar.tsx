import { useState } from "react";
import { ChevronRight, CircleAlert, ShieldCheck, Loader2 } from "lucide-react";
import { useSessionStore } from "../../store/sessionStore";
import { LAYER_META, describeFinding, SEVERITY_ORDER } from "../../lib/findingKb";
import type { Finding, SeverityLevel } from "../../lib/types";

const SEV_DOT: Record<SeverityLevel, string> = {
  critical: "bg-severity-critical",
  high: "bg-severity-high",
  medium: "bg-severity-medium",
  low: "bg-severity-low",
  info: "bg-severity-info",
};

export function Sidebar() {
  const { mode, layerStatus, session, findings, chains } = useSessionStore();
  const activeLayers = session?.active_layers ?? (mode === "basic" ? [1, 2, 3] : [1, 2, 3, 4, 5, 6, 7, 8]);
  const [expanded, setExpanded] = useState<Record<number, boolean>>({});

  const byLayer: Record<number, Finding[]> = {};
  for (const f of Object.values(findings)) (byLayer[f.layer] ??= []).push(f);
  for (const list of Object.values(byLayer))
    list.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  const critCount = Object.values(findings).filter((f) => f.severity === "critical").length;
  const highCount = Object.values(findings).filter((f) => f.severity === "high").length;
  const exploitable = Object.values(findings).filter((f) => f.exploitable).length;

  return (
    <aside className="w-72 shrink-0 border-r border-line/15 bg-surface flex flex-col overflow-hidden">
      <div className="px-3 py-3 border-b border-line/10">
        <p className="text-text-muted text-xs font-mono uppercase tracking-widest">Attack Layers</p>
        <p className="text-text-muted/70 text-[11px] mt-0.5">{activeLayers.length} active · {Object.keys(findings).length} findings</p>
      </div>

      <div className="flex-1 overflow-y-auto p-2 space-y-1">
        {activeLayers.map((id) => {
          const meta = LAYER_META[id];
          const list = byLayer[id] ?? [];
          const status = layerStatus[id];
          const done = status?.done;
          const isOpen = expanded[id] ?? false;
          const crit = list.filter((f) => f.severity === "critical" || f.severity === "high").length;

          return (
            <div key={id} className="rounded-lg border border-line/10 bg-bg/30 overflow-hidden">
              <button
                onClick={() => setExpanded((e) => ({ ...e, [id]: !e[id] }))}
                className="w-full flex items-center gap-2 px-2.5 py-2 text-left hover:bg-accent/5 transition-colors"
              >
                <ChevronRight className={`w-3.5 h-3.5 text-text-muted shrink-0 transition-transform ${isOpen ? "rotate-90" : ""}`} />
                <span className="text-[10px] font-mono text-accent w-5 shrink-0">L{id}</span>
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-semibold text-text-primary truncate">{meta?.name ?? `Layer ${id}`}</p>
                  <p className="text-[10px] text-text-muted font-mono truncate">{meta?.standard}</p>
                </div>
                {/* status / count */}
                {!done && session ? (
                  <Loader2 className="w-3 h-3 text-accent animate-spin shrink-0" />
                ) : list.length > 0 ? (
                  <span className={`text-[10px] font-mono font-bold shrink-0 ${crit > 0 ? "text-severity-critical" : "text-text-secondary"}`}>
                    {list.length}
                  </span>
                ) : done ? (
                  <ShieldCheck className="w-3.5 h-3.5 text-accent-green shrink-0" />
                ) : null}
              </button>

              {isOpen && (
                <div className="px-2.5 pb-2.5 pt-0.5 space-y-1.5 border-t border-line/10">
                  <p className="text-[10px] text-text-muted leading-relaxed pt-1.5">{meta?.description}</p>
                  {list.length === 0 ? (
                    <p className="text-[10px] font-mono text-text-muted/70 italic">
                      {done ? "No findings on this layer." : "Scanning…"}
                    </p>
                  ) : (
                    list.map((f) => {
                      const d = describeFinding(f);
                      return (
                        <div key={f.id} className="rounded-md bg-surface/60 border border-line/10 p-2">
                          <div className="flex items-start gap-1.5">
                            <span className={`w-1.5 h-1.5 rounded-full mt-1 shrink-0 ${SEV_DOT[f.severity]}`} />
                            <div className="min-w-0">
                              <p className="text-[11px] text-text-primary leading-snug">{f.title}</p>
                              <p className="text-[10px] text-text-muted leading-snug mt-0.5">{d.description}</p>
                              <div className="flex flex-wrap items-center gap-1 mt-1">
                                <span className="text-[9px] font-mono uppercase text-text-muted">{f.severity}</span>
                                {f.exploitable && (
                                  <span className="text-[9px] font-mono text-severity-critical flex items-center gap-0.5">
                                    <CircleAlert className="w-2.5 h-2.5" /> exploitable
                                  </span>
                                )}
                                {d.refs.map((r) => (
                                  <span key={r} className="text-[9px] font-mono text-text-muted/80 bg-overlay/60 px-1 rounded">{r}</span>
                                ))}
                              </div>
                            </div>
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>

      <div className="border-t border-line/15 p-3 grid grid-cols-3 gap-2 text-center">
        <Stat label="Critical" value={critCount} cls="text-severity-critical" />
        <Stat label="Exploit" value={exploitable} cls="text-severity-high" />
        <Stat label="Chains" value={chains.length} cls="text-accent" />
      </div>
    </aside>
  );
}

function Stat({ label, value, cls }: { label: string; value: number; cls: string }) {
  return (
    <div>
      <p className={`text-lg font-mono font-bold ${cls}`}>{value}</p>
      <p className="text-[10px] text-text-muted">{label}</p>
    </div>
  );
}
