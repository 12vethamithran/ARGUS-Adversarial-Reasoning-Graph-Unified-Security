import { Bot, Database, Globe, Network, ShieldAlert, Wrench } from "lucide-react";
import { motion, useReducedMotion } from "framer-motion";
import { LiveDot } from "./ArgusMotion";

const NODES = [
  { label: "Web", detail: "Input", Icon: Globe, x: 44, y: 82 },
  { label: "LLM", detail: "Prompt", Icon: Bot, x: 164, y: 42 },
  { label: "RAG", detail: "Corpus", Icon: Database, x: 294, y: 92 },
  { label: "MCP", detail: "Tool", Icon: Wrench, x: 424, y: 54 },
  { label: "Net", detail: "Pivot", Icon: Network, x: 548, y: 100 },
  { label: "Risk", detail: "Chain", Icon: ShieldAlert, x: 662, y: 62 },
];

const PACKET_X = NODES.map((node) => node.x);
const PACKET_Y = NODES.map((node) => node.y);

export function LiveAttackChain() {
  const reducedMotion = useReducedMotion();

  return (
    <div className="argus-panel-shell relative overflow-hidden rounded-lg border border-line/15 bg-surface/55 p-4 md:p-5">
      <div className="absolute inset-0 bg-[linear-gradient(90deg,rgb(var(--accent)/0.08),transparent_42%,rgb(var(--accent)/0.05))]" />
      <div className="relative flex flex-col gap-4">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <div className="flex items-center gap-2">
            <LiveDot active={!reducedMotion} />
            <span className="font-mono text-[11px] uppercase tracking-[0.22em] text-accent">
              Live chain motion
            </span>
          </div>
          <span className="h-px flex-1 bg-line/10" />
          <span className="font-mono text-[10px] uppercase tracking-[0.18em] text-text-muted">
            Web to agent to network
          </span>
        </div>

        <div className="relative h-44 overflow-hidden rounded-md border border-line/10 bg-bg/45">
          <div className="argus-workspace-grid absolute inset-0 opacity-70" />
          <svg viewBox="0 0 706 160" className="relative h-full w-full" role="img" aria-label="Animated attack chain across Argus layers">
            <defs>
              <linearGradient id="chainLine" x1="0" x2="1" y1="0" y2="0">
                <stop offset="0%" stopColor="rgb(var(--accent))" stopOpacity="0.12" />
                <stop offset="50%" stopColor="rgb(var(--accent))" stopOpacity="0.8" />
                <stop offset="100%" stopColor="rgb(var(--node-probing))" stopOpacity="0.65" />
              </linearGradient>
            </defs>
            <path
              d="M44 82 C92 18 122 18 164 42 S248 120 294 92 S374 20 424 54 S506 130 548 100 S620 26 662 62"
              fill="none"
              stroke="rgb(var(--border) / 0.14)"
              strokeWidth="2"
            />
            <motion.path
              d="M44 82 C92 18 122 18 164 42 S248 120 294 92 S374 20 424 54 S506 130 548 100 S620 26 662 62"
              fill="none"
              stroke="url(#chainLine)"
              strokeLinecap="round"
              strokeWidth="3"
              strokeDasharray="64 420"
              animate={reducedMotion ? undefined : { strokeDashoffset: [460, 0] }}
              transition={{ duration: 4.8, repeat: Infinity, ease: "linear" }}
            />
            {!reducedMotion && (
              <motion.g
                animate={{ x: PACKET_X, y: PACKET_Y, opacity: [0, 1, 1, 1, 1, 0.15] }}
                transition={{ duration: 5.4, repeat: Infinity, ease: "easeInOut" }}
              >
                <circle r="8" fill="rgb(var(--accent))" opacity="0.22" />
                <circle r="3.5" fill="rgb(var(--accent))" />
              </motion.g>
            )}
            {NODES.map(({ label, x, y }, index) => (
              <motion.g
                key={label}
                initial={{ opacity: 0, scale: 0.82 }}
                animate={{ opacity: 1, scale: reducedMotion ? 1 : [1, 1.08, 1] }}
                transition={{
                  opacity: { duration: 0.4, delay: index * 0.08 },
                  scale: { duration: 2.8, delay: index * 0.25, repeat: reducedMotion ? 0 : Infinity, ease: "easeInOut" },
                }}
                transform={`translate(${x} ${y})`}
              >
                <circle r="18" fill="rgb(var(--bg))" stroke="rgb(var(--accent) / 0.48)" strokeWidth="1.4" />
                <circle r="26" fill="none" stroke="rgb(var(--accent) / 0.08)" strokeWidth="1" />
              </motion.g>
            ))}
          </svg>

          <div className="pointer-events-none absolute inset-0">
            {NODES.map(({ label, detail, Icon, x, y }, index) => (
              <motion.div
                key={label}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.45, delay: 0.2 + index * 0.08 }}
                className="absolute flex -translate-x-1/2 -translate-y-1/2 flex-col items-center gap-1"
                style={{ left: `${(x / 706) * 100}%`, top: `${(y / 160) * 100}%` }}
              >
                <div className="flex h-8 w-8 items-center justify-center rounded-md border border-accent/35 bg-bg text-accent shadow-[0_0_18px_rgb(var(--accent)/0.14)]">
                  <Icon className="h-4 w-4" />
                </div>
                <div className="text-center leading-none">
                  <p className="font-mono text-[10px] font-semibold text-text-primary">{label}</p>
                  <p className="mt-1 font-mono text-[8px] uppercase tracking-[0.16em] text-text-muted">{detail}</p>
                </div>
              </motion.div>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-3 gap-2 font-mono text-[10px] uppercase tracking-[0.14em] text-text-muted">
          <span><span className="text-accent">08</span> layers</span>
          <span><span className="text-accent">01</span> live chain</span>
          <span><span className="text-accent">94%</span> impact</span>
        </div>
      </div>
    </div>
  );
}
