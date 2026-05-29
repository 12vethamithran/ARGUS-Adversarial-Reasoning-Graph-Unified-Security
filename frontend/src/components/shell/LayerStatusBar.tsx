import { Zap, Microscope, Check, CircleDot } from "lucide-react";
import { useSessionStore } from "../../store/sessionStore";

export function LayerStatusBar() {
  const { session, isRunning, layerStatus, mode, findings, chains } = useSessionStore();
  const activeLayers = session?.active_layers ?? (mode === "basic" ? [1, 2, 3] : [1, 2, 3, 4, 5, 6, 7, 8]);

  return (
    <div className="flex items-center gap-4 px-4 py-2 border-b border-line/15 bg-surface/80 backdrop-blur-sm shrink-0">
      {/* Mode badge */}
      <div className="flex items-center gap-1.5 px-3 py-1 rounded-full border border-accent/30 text-accent bg-accent/5 text-xs font-mono">
        {isRunning && <span className="w-1.5 h-1.5 rounded-full animate-pulse bg-accent" />}
        {mode === "basic"
          ? <><Zap className="w-3 h-3" /> BASIC</>
          : <><Microscope className="w-3 h-3" /> ADVANCED</>}
      </div>

      {/* Layer pills */}
      <div className="flex items-center gap-1 overflow-x-auto">
        {activeLayers.map((l) => {
          const status = layerStatus[l];
          const isActive = isRunning && !status?.done;
          return (
            <div
              key={l}
              className={`flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono border transition-all duration-500 ${
                status?.done
                  ? "border-accent-green/30 text-accent-green bg-accent-green/5"
                  : isActive
                  ? "border-accent/40 text-accent bg-accent/10 animate-pulse"
                  : "border-line/15 text-text-muted"
              }`}
            >
              {status?.done && <Check className="w-3 h-3 text-accent-green" />}
              {isActive && <CircleDot className="w-2.5 h-2.5" />}
              <span>L{l}</span>
              {status?.done && status.findingCount > 0 && (
                <span className="text-severity-critical">+{status.findingCount}</span>
              )}
            </div>
          );
        })}
      </div>

      {/* Spacer */}
      <div className="flex-1" />

      {/* Stats */}
      <div className="hidden md:flex items-center gap-4 text-xs font-mono text-text-muted">
        <span>
          <span className="text-text-primary">{Object.keys(findings).length}</span> findings
        </span>
        <span>
          <span className="text-accent">{chains.length}</span> chain{chains.length !== 1 ? "s" : ""}
        </span>
        {isRunning && (
          <span className="flex items-center gap-1.5 text-accent">
            <span className="w-1.5 h-1.5 rounded-full bg-accent animate-ping" />
            LIVE
          </span>
        )}
        {!isRunning && session?.status === "complete" && (
          <span className="text-accent-green">● COMPLETE</span>
        )}
      </div>
    </div>
  );
}
