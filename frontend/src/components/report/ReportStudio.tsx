import { FileText, FileDown, Braces, ShieldAlert } from "lucide-react";
import { useSessionStore } from "../../store/sessionStore";
import { openHtmlReport, downloadPdfReport, downloadStixReport } from "../../lib/api";
import { toast } from "../ui/Toast";
import { FindingCard } from "./FindingCard";
import { riskScore, SEVERITY_ORDER, LAYER_META } from "../../lib/findingKb";
import type { SeverityLevel } from "../../lib/types";

const SEV_BAR: Record<SeverityLevel, string> = {
  critical: "bg-severity-critical", high: "bg-severity-high",
  medium: "bg-severity-medium", low: "bg-severity-low", info: "bg-severity-info",
};
const SEV_LIST: SeverityLevel[] = ["critical", "high", "medium", "low", "info"];

export function ReportStudio() {
  const { findings, chains, session, isRunning } = useSessionStore();

  const findingList = Object.values(findings);
  const exploitableCount = findingList.filter((f) => f.exploitable).length;

  const score = riskScore(findingList);
  const riskLabel = score >= 80 ? "CRITICAL" : score >= 60 ? "HIGH" : score >= 35 ? "MODERATE" : score > 0 ? "LOW" : "—";
  const sevCounts = SEV_LIST.map((s) => ({ s, n: findingList.filter((f) => f.severity === s).length }));
  const total = findingList.length || 1;
  const layersHit = new Set(findingList.map((f) => f.layer)).size;

  const canExport = !!session && !isRunning;
  function guard(fn: () => void) {
    if (!session) return toast.error("No session to export yet.");
    if (isRunning) return toast.info("Wait for the analysis to finish before exporting.");
    fn();
  }

  const exportBtn = "flex items-center gap-1 text-xs font-mono px-2.5 py-1 rounded border border-line/20 text-text-secondary hover:text-accent hover:border-accent/40 transition-all disabled:opacity-40 disabled:cursor-not-allowed";

  return (
    <div className="argus-panel-shell flex flex-col h-full bg-surface rounded-lg border border-line/15 overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2 border-b border-line/15 shrink-0">
        <span className="text-xs font-mono text-text-muted uppercase tracking-widest">Report Studio</span>
        <div className="flex items-center gap-1.5">
          <button disabled={!canExport} className={exportBtn} onClick={() => guard(() => openHtmlReport(session!.id))} title="Open HTML report">
            <FileText className="w-3.5 h-3.5" /> HTML
          </button>
          <button disabled={!canExport} className={exportBtn} onClick={() => guard(() => downloadPdfReport(session!.id))} title="Download full analyst PDF report">
            <FileDown className="w-3.5 h-3.5" /> Analyst PDF
          </button>
          <button disabled={!canExport} className={exportBtn} onClick={() => guard(() => downloadStixReport(session!.id))} title="Download STIX 2.1 JSON">
            <Braces className="w-3.5 h-3.5" /> STIX
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-5">
        {/* Executive summary */}
        {session && findingList.length > 0 && (
          <div className="rounded-lg bg-raised border border-line/10 p-4 space-y-3">
            <div className="flex items-center gap-4">
              {/* risk gauge */}
              <div className="relative w-16 h-16 shrink-0">
                <svg viewBox="0 0 36 36" className="w-16 h-16 -rotate-90">
                  <circle cx="18" cy="18" r="15.5" fill="none" stroke="rgb(var(--border) / 0.25)" strokeWidth="3" />
                  <circle cx="18" cy="18" r="15.5" fill="none" stroke="rgb(var(--accent))" strokeWidth="3"
                    strokeDasharray={`${score} 100`} strokeLinecap="round" />
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <span className="text-lg font-mono font-bold text-text-primary leading-none">{score}</span>
                  <span className="text-[8px] font-mono text-text-muted">RISK</span>
                </div>
              </div>
              <div className="flex-1">
                <p className="text-xs font-mono text-text-muted uppercase tracking-widest">Executive Summary</p>
                <p className="text-sm text-text-primary mt-0.5">
                  <span className="font-bold text-accent">{riskLabel}</span> risk — {findingList.length} findings across {layersHit} layers,
                  {" "}{exploitableCount} exploitable, {chains.length} attack chain{chains.length !== 1 ? "s" : ""}.
                </p>
              </div>
            </div>
            {/* severity distribution */}
            <div>
              <div className="flex h-2 rounded-full overflow-hidden bg-overlay/50">
                {sevCounts.map(({ s, n }) => n > 0 && (
                  <div key={s} className={SEV_BAR[s]} style={{ width: `${(n / total) * 100}%` }} title={`${n} ${s}`} />
                ))}
              </div>
              <div className="flex flex-wrap gap-x-3 gap-y-1 mt-2 text-[10px] font-mono text-text-muted">
                {sevCounts.map(({ s, n }) => (
                  <span key={s} className="flex items-center gap-1">
                    <span className={`w-2 h-2 rounded-full ${SEV_BAR[s]}`} /> {s} {n}
                  </span>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Chains */}
        {chains.length > 0 && (
          <div className="space-y-2">
            <p className="text-xs font-mono text-text-muted uppercase tracking-widest flex items-center gap-1.5">
              <ShieldAlert className="w-3.5 h-3.5 text-accent" /> Attack Chains ({chains.length})
            </p>
            {chains.map((chain) => (
              <div key={chain.id} className="bg-raised rounded-lg border border-accent/20 p-4 space-y-2">
                <div className="flex items-center gap-3">
                  <span className="text-xs font-mono text-accent">Priority</span>
                  <div className="flex-1 bg-overlay rounded-full h-1.5">
                    <div className="argus-live-pill h-full rounded-full bg-accent transition-all duration-700" style={{ width: `${chain.priority * 100}%` }} />
                  </div>
                  <span className="text-xs font-mono text-accent">{(chain.priority * 100).toFixed(0)}%</span>
                </div>
                {/* layer path */}
                <div className="flex flex-wrap items-center gap-1">
                  {chain.steps.map((fid, i) => {
                    const f = findings[fid];
                    return (
                      <span key={fid} className="flex items-center gap-1">
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-accent/10 border border-accent/20 text-accent">
                          {f ? `L${f.layer} ${LAYER_META[f.layer]?.short ?? ""}` : "?"}
                        </span>
                        {i < chain.steps.length - 1 && <span className="text-text-muted text-[10px]">→</span>}
                      </span>
                    );
                  })}
                </div>
                <p className="text-text-secondary text-xs leading-relaxed">{chain.narrative}</p>
                <div className="flex gap-4 text-xs font-mono text-text-muted">
                  <span>Exploit <span className="text-severity-critical">{(chain.exploitability * 100).toFixed(0)}%</span></span>
                  <span>Impact <span className="text-severity-high">{(chain.impact * 100).toFixed(0)}%</span></span>
                  <span>Novelty <span className="text-node-probing">{(chain.novelty * 100).toFixed(0)}%</span></span>
                </div>
                {chain.remediations.length > 0 && (
                  <div className="pt-2 border-t border-line/10 space-y-1">
                    <p className="text-xs font-mono text-text-muted">Remediations</p>
                    {chain.remediations.map((r, i) => (
                      <div key={i} className="flex items-start gap-2 text-xs">
                        <span className="text-accent-green shrink-0">→</span>
                        <span className="text-text-secondary">{r.action}</span>
                        <span className="text-text-muted font-mono shrink-0 ml-auto">{r.ref}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        {/* Findings */}
        {findingList.length > 0 && (
          <div className="space-y-2">
            <p className="text-xs font-mono text-text-muted uppercase tracking-widest">
              All Findings ({findingList.length}) · click to expand
            </p>
            {findingList
              .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])
              .map((f) => <FindingCard key={f.id} finding={f} />)}
          </div>
        )}

        {findingList.length === 0 && !isRunning && (
          <div className="text-center text-text-muted text-sm font-mono py-12">
            No findings yet. Start an analysis to populate the report.
          </div>
        )}
      </div>
    </div>
  );
}
