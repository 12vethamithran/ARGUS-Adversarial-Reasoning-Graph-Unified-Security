import { useEffect, useRef, useState } from "react";
import { Play, Pause, SkipBack, SkipForward, GitBranch, Zap } from "lucide-react";
import { useSessionStore } from "../../store/sessionStore";
import { describeFinding, LAYER_META } from "../../lib/findingKb";
import type { SeverityLevel } from "../../lib/types";

const SEV_TEXT: Record<SeverityLevel, string> = {
  critical: "text-severity-critical", high: "text-severity-high",
  medium: "text-severity-medium", low: "text-severity-low", info: "text-severity-info",
};

function Shell({ children }: { children: React.ReactNode }) {
  return (
    <div className="argus-panel-shell flex flex-col h-full bg-surface rounded-lg border border-line/15 overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-2 border-b border-line/10 shrink-0">
        <GitBranch className="w-3.5 h-3.5 text-accent" />
        <span className="text-xs font-mono text-text-muted uppercase tracking-widest">Chain Replay</span>
      </div>
      {children}
    </div>
  );
}

export function ChainReplay() {
  const { chains, findings } = useSessionStore();
  const [sel, setSel] = useState(0);
  const [step, setStep] = useState(0);
  const [playing, setPlaying] = useState(false);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  const chain = chains[Math.min(sel, Math.max(0, chains.length - 1))];
  const maxStep = chain ? chain.steps.length - 1 : 0;

  useEffect(() => {
    if (!playing || !chain) return;
    timer.current = setInterval(() => {
      setStep((s) => {
        if (s >= maxStep) { setPlaying(false); return s; }
        return s + 1;
      });
    }, 1400);
    return () => { if (timer.current) clearInterval(timer.current); };
  }, [playing, chain, maxStep]);

  // Reset replay position when the selected chain changes.
  // eslint-disable-next-line react-hooks/set-state-in-effect
  useEffect(() => { setStep(0); setPlaying(false); }, [sel]);

  if (!chain) {
    return (
      <Shell>
        <div className="flex-1 flex flex-col items-center justify-center text-text-muted gap-2 p-4 text-center">
          <GitBranch className="w-6 h-6 opacity-30" />
          <p className="text-sm font-mono">No attack chains yet</p>
          <p className="text-xs">Chains appear once the reasoner correlates exploitable findings across layers.</p>
        </div>
      </Shell>
    );
  }

  const currentFinding = findings[chain.steps[step]];
  const detail = currentFinding ? describeFinding(currentFinding) : null;

  return (
    <Shell>
      <div className="flex items-center gap-2 px-3 py-2 border-b border-line/10 shrink-0">
        {chains.length > 1 ? (
          <select value={sel} onChange={(e) => setSel(Number(e.target.value))}
            className="bg-raised border border-line/20 rounded text-xs font-mono text-text-secondary px-2 py-1">
            {chains.map((c, i) => (
              <option key={c.id} value={i}>Chain {i + 1} — {(c.priority * 100).toFixed(0)}%</option>
            ))}
          </select>
        ) : (
          <span className="text-xs font-mono text-text-secondary">Chain 1</span>
        )}
        <span className="ml-auto flex items-center gap-1 text-xs font-mono text-accent">
          <Zap className="w-3 h-3" /> priority {(chain.priority * 100).toFixed(0)}%
        </span>
      </div>

      <div className="flex-1 overflow-y-auto p-3 flex flex-col gap-3">
        <p className="text-[11px] text-text-secondary leading-relaxed bg-bg/40 border border-line/10 rounded-md p-2">
          {chain.narrative}
        </p>

        <div className="flex items-center gap-1 overflow-x-auto pb-1">
          {chain.steps.map((fid, i) => {
            const f = findings[fid];
            const layer = f?.layer;
            return (
              <div key={fid} className="flex items-center shrink-0">
                <button onClick={() => setStep(i)} title={f?.title}
                  className={`w-8 h-8 rounded-full border text-[10px] font-mono font-bold transition-all ${
                    i === step ? "bg-accent text-[rgb(var(--accent-contrast))] border-accent scale-110"
                    : i < step ? "bg-accent/20 text-accent border-accent/40"
                    : "bg-transparent text-text-muted border-line/30"
                  }`}>
                  {layer ? `L${layer}` : i + 1}
                </button>
                {i < maxStep && <div className={`w-6 h-0.5 ${i < step ? "argus-live-pill bg-accent/60" : "bg-line/20"}`} />}
              </div>
            );
          })}
        </div>

        {currentFinding && detail ? (
          <div className="bg-bg/40 rounded-lg border border-line/10 p-3 space-y-2">
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono text-accent">Step {step + 1}/{chain.steps.length}</span>
              <span className="text-xs text-text-muted">·</span>
              <span className="text-xs font-mono text-text-secondary">L{currentFinding.layer} {LAYER_META[currentFinding.layer]?.name}</span>
              <span className={`ml-auto text-[10px] font-mono uppercase ${SEV_TEXT[currentFinding.severity]}`}>{currentFinding.severity}</span>
            </div>
            <p className="text-sm text-text-primary leading-snug">{currentFinding.title}</p>
            <p className="text-[11px] text-text-muted leading-relaxed">{detail.description}</p>
            <p className="text-[11px] text-text-secondary leading-relaxed">
              <span className="text-accent font-mono">impact: </span>{detail.impact}
            </p>
            <div className="flex flex-wrap gap-1">
              {detail.refs.map((r) => (
                <span key={r} className="text-[10px] font-mono text-text-secondary bg-overlay/60 px-1.5 py-0.5 rounded">{r}</span>
              ))}
            </div>
          </div>
        ) : (
          <div className="bg-bg/40 rounded-lg border border-line/10 p-3 text-text-muted text-xs font-mono">
            Finding data unavailable for this step.
          </div>
        )}
      </div>

      <div className="flex items-center gap-2 px-3 py-2 border-t border-line/10 shrink-0">
        <button onClick={() => { setStep(0); setPlaying(false); }} disabled={step === 0}
          className="p-1.5 rounded text-text-secondary hover:text-accent disabled:opacity-30" aria-label="Restart">
          <SkipBack className="w-4 h-4" />
        </button>
        <button onClick={() => setPlaying((p) => !p)} disabled={maxStep === 0}
          className="p-1.5 rounded bg-accent/15 border border-accent/30 text-accent hover:bg-accent/25 disabled:opacity-40"
          aria-label={playing ? "Pause" : "Play"}>
          {playing ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
        </button>
        <button onClick={() => setStep((s) => Math.min(maxStep, s + 1))} disabled={step === maxStep}
          className="p-1.5 rounded text-text-secondary hover:text-accent disabled:opacity-30" aria-label="Next step">
          <SkipForward className="w-4 h-4" />
        </button>
        <input type="range" min={0} max={maxStep} value={step}
          onChange={(e) => { setStep(Number(e.target.value)); setPlaying(false); }}
          className="flex-1 accent-accent" />
        <span className="text-[10px] font-mono text-text-muted w-10 text-right">{step + 1}/{chain.steps.length}</span>
      </div>
    </Shell>
  );
}
