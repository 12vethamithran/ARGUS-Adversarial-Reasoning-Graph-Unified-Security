import { Bot, Database, Globe, Network, ShieldAlert, Wrench } from "lucide-react";
import { motion, useReducedMotion } from "framer-motion";
import { LiveDot } from "./ArgusMotion";

const NODES = [
  { label: "Web", detail: "Input", Icon: Globe, x: 54, y: 92 },
  { label: "LLM", detail: "Prompt", Icon: Bot, x: 174, y: 52 },
  { label: "RAG", detail: "Corpus", Icon: Database, x: 300, y: 98 },
  { label: "MCP", detail: "Tool", Icon: Wrench, x: 426, y: 58 },
  { label: "Net", detail: "Pivot", Icon: Network, x: 548, y: 104 },
  { label: "Risk", detail: "Chain", Icon: ShieldAlert, x: 664, y: 66 },
];

const PATH = "M54 92 C98 34 128 28 174 52 S250 126 300 98 S376 28 426 58 S504 132 548 104 S616 34 664 66";
const PACKET_X = NODES.map((node) => node.x);
const PACKET_Y = NODES.map((node) => node.y);

export function LiveAttackChain() {
  const reducedMotion = useReducedMotion();

  return (
    <div className="argus-panel-shell relative overflow-hidden rounded-lg border border-accent/25 bg-surface/60 p-4 md:p-5 shadow-[0_0_42px_rgb(var(--accent)/0.08)]">
      <div className="absolute inset-0 bg-[linear-gradient(135deg,rgb(var(--accent)/0.12),transparent_38%,rgb(var(--accent)/0.06))]" />
      <motion.div
        aria-hidden
        className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-accent/80 to-transparent"
        animate={reducedMotion ? undefined : { x: ["-45%", "45%"], opacity: [0.15, 0.8, 0.15] }}
        transition={{ duration: 3.6, repeat: Infinity, ease: "easeInOut" }}
      />

      <div className="relative flex flex-col gap-4">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <div className="flex items-center gap-2">
            <LiveDot active={!reducedMotion} />
            <span className="font-mono text-[11px] uppercase tracking-[0.22em] text-accent">
              Live chain motion
            </span>
          </div>
          <span className="h-px flex-1 bg-line/10" />
          <motion.span
            className="font-mono text-[10px] uppercase tracking-[0.18em] text-text-muted"
            animate={reducedMotion ? undefined : { opacity: [0.45, 1, 0.45] }}
            transition={{ duration: 2.4, repeat: Infinity, ease: "easeInOut" }}
          >
            Correlating layers
          </motion.span>
        </div>

        <div className="grid grid-cols-3 gap-2">
          {[
            ["entry", "web input"],
            ["pivot", "agent tool"],
            ["impact", "risk chain"],
          ].map(([label, value], index) => (
            <motion.div
              key={label}
              initial={{ opacity: 0, y: 8 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: index * 0.08 }}
              className="rounded-md border border-line/10 bg-bg/35 px-3 py-2"
            >
              <p className="font-mono text-[9px] uppercase tracking-[0.18em] text-text-muted">{label}</p>
              <p className="mt-1 font-mono text-[10px] uppercase tracking-[0.12em] text-accent">{value}</p>
            </motion.div>
          ))}
        </div>

        <div className="relative h-56 overflow-hidden rounded-md border border-line/10 bg-bg/55">
          <div className="argus-workspace-grid absolute inset-0 opacity-60" />
          <div className="absolute inset-0 bg-[linear-gradient(180deg,transparent,rgb(var(--accent)/0.07)_52%,transparent)]" />
          {!reducedMotion && (
            <motion.div
              aria-hidden
              className="absolute inset-x-0 h-16 bg-gradient-to-b from-transparent via-accent/10 to-transparent"
              animate={{ y: [-72, 230] }}
              transition={{ duration: 4.8, repeat: Infinity, ease: "linear" }}
            />
          )}

          <svg viewBox="0 0 720 178" className="relative h-full w-full" role="img" aria-label="Animated attack chain across Argus layers">
            <defs>
              <linearGradient id="chainLine" x1="0" x2="1" y1="0" y2="0">
                <stop offset="0%" stopColor="rgb(var(--accent))" stopOpacity="0.1" />
                <stop offset="45%" stopColor="rgb(var(--accent))" stopOpacity="0.95" />
                <stop offset="100%" stopColor="rgb(var(--node-probing))" stopOpacity="0.7" />
              </linearGradient>
              <filter id="chainGlow">
                <feGaussianBlur stdDeviation="3" result="coloredBlur" />
                <feMerge>
                  <feMergeNode in="coloredBlur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>

            <path d={PATH} fill="none" stroke="rgb(var(--border) / 0.16)" strokeWidth="2" />
            <motion.path
              d={PATH}
              fill="none"
              stroke="url(#chainLine)"
              strokeLinecap="round"
              strokeWidth="4"
              strokeDasharray="86 410"
              filter="url(#chainGlow)"
              animate={reducedMotion ? undefined : { strokeDashoffset: [500, 0] }}
              transition={{ duration: 4.6, repeat: Infinity, ease: "linear" }}
            />
            <motion.path
              d={PATH}
              fill="none"
              stroke="rgb(var(--accent) / 0.28)"
              strokeLinecap="round"
              strokeWidth="1"
              strokeDasharray="8 18"
              animate={reducedMotion ? undefined : { strokeDashoffset: [0, -180] }}
              transition={{ duration: 6, repeat: Infinity, ease: "linear" }}
            />

            {!reducedMotion && (
              <>
                <motion.g
                  animate={{ x: PACKET_X, y: PACKET_Y, opacity: [0, 1, 1, 1, 1, 0.1] }}
                  transition={{ duration: 5.2, repeat: Infinity, ease: "easeInOut" }}
                >
                  <circle r="10" fill="rgb(var(--accent))" opacity="0.16" />
                  <circle r="4" fill="rgb(var(--accent))" />
                </motion.g>
                <motion.g
                  animate={{ x: PACKET_X, y: PACKET_Y, opacity: [0, 0.7, 1, 0.8, 0.4, 0] }}
                  transition={{ duration: 5.2, delay: 1.7, repeat: Infinity, ease: "easeInOut" }}
                >
                  <circle r="6" fill="rgb(var(--node-probing))" opacity="0.55" />
                </motion.g>
              </>
            )}

            {NODES.map(({ label, x, y }, index) => (
              <motion.g
                key={label}
                initial={{ opacity: 0, scale: 0.78 }}
                animate={{ opacity: 1, scale: reducedMotion ? 1 : [1, 1.1, 1] }}
                transition={{
                  opacity: { duration: 0.4, delay: index * 0.08 },
                  scale: { duration: 2.7, delay: index * 0.18, repeat: reducedMotion ? 0 : Infinity, ease: "easeInOut" },
                }}
                transform={`translate(${x} ${y})`}
              >
                <circle r="19" fill="rgb(var(--bg))" stroke="rgb(var(--accent) / 0.58)" strokeWidth="1.4" />
                <motion.circle
                  r="29"
                  fill="none"
                  stroke="rgb(var(--accent) / 0.16)"
                  strokeWidth="1"
                  animate={reducedMotion ? undefined : { r: [24, 34, 24], opacity: [0.2, 0, 0.2] }}
                  transition={{ duration: 2.8, delay: index * 0.2, repeat: Infinity, ease: "easeInOut" }}
                />
              </motion.g>
            ))}
          </svg>

          <div className="pointer-events-none absolute inset-0">
            {NODES.map(({ label, detail, Icon, x, y }, index) => (
              <motion.div
                key={label}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.45, delay: 0.2 + index * 0.08 }}
                className="absolute flex -translate-x-1/2 -translate-y-1/2 flex-col items-center gap-1"
                style={{ left: `${(x / 720) * 100}%`, top: `${(y / 178) * 100}%` }}
              >
                <div className="flex h-9 w-9 items-center justify-center rounded-md border border-accent/40 bg-bg text-accent shadow-[0_0_20px_rgb(var(--accent)/0.18)]">
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
          {[
            ["08", "layers"],
            ["01", "live chain"],
            ["94%", "impact"],
          ].map(([value, label], i) => (
            <motion.span
              key={label}
              initial={{ opacity: 0, y: 8 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: 0.2 + i * 0.08 }}
            >
              <span className="text-accent">{value}</span> {label}
            </motion.span>
          ))}
        </div>
      </div>
    </div>
  );
}
