import { motion } from "framer-motion";
import { Zap, Microscope, Check, CircleDot } from "lucide-react";
import { useSessionStore } from "../../store/sessionStore";
import { LiveDot } from "../motion/ArgusMotion";

export function LayerStatusBar() {
  const { session, isRunning, layerStatus, mode, findings, chains } = useSessionStore();
  const activeLayers = session?.active_layers ?? (mode === "basic" ? [1, 2, 3] : [1, 2, 3, 4, 5, 6, 7, 8]);

  return (
    <div className="relative flex items-center gap-4 px-4 py-2 border-b border-line/15 bg-surface/80 backdrop-blur-sm shrink-0 overflow-hidden">
      {isRunning && <div className="absolute inset-x-0 bottom-0 h-px argus-live-pill bg-accent/30" />}
      {/* Mode badge */}
      <motion.div
        whileHover={{ y: -1 }}
        className={`flex items-center gap-1.5 px-3 py-1 rounded-full border border-accent/30 text-accent bg-accent/5 text-xs font-mono ${isRunning ? "argus-live-pill" : ""}`}
      >
        {isRunning && <LiveDot active />}
        {mode === "basic"
          ? <><Zap className="w-3 h-3" /> BASIC</>
          : <><Microscope className="w-3 h-3" /> ADVANCED</>}
      </motion.div>

      {/* Layer pills */}
      <div className="flex items-center gap-1 overflow-x-auto">
        {activeLayers.map((l) => {
          const status = layerStatus[l];
          const isActive = isRunning && !status?.done;
          return (
            <motion.div
              key={l}
              layout
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              whileHover={{ y: -1 }}
              className={`flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono border transition-all duration-500 ${
                status?.done
                  ? "border-accent-green/30 text-accent-green bg-accent-green/5"
                : isActive
                  ? "argus-live-pill border-accent/40 text-accent bg-accent/10"
                  : "border-line/15 text-text-muted"
              }`}
            >
              {status?.done && <Check className="w-3 h-3 text-accent-green" />}
              {isActive && <CircleDot className="w-2.5 h-2.5" />}
              <span>L{l}</span>
              {status?.done && status.findingCount > 0 && (
                <span className="text-severity-critical">+{status.findingCount}</span>
              )}
            </motion.div>
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
            <LiveDot active />
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
