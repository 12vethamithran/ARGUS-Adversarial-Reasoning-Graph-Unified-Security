import { motion, useReducedMotion } from "framer-motion";
import { Bot, Crosshair, GitBranch, Radar, ShieldCheck } from "lucide-react";
import { LiveDot } from "./ArgusMotion";

const FEATURES = [
  { k: "01", title: "Adversarial reasoning", body: "Follows how one weakness becomes a campaign.", Icon: Radar },
  { k: "02", title: "Graph-based clarity", body: "Maps findings, chains, and impact into one view.", Icon: GitBranch },
  { k: "03", title: "Unified security", body: "Connects web, LLM, RAG, agentic, identity, and network risk.", Icon: ShieldCheck },
];

const TELEMETRY = ["Web", "LLM", "RAG", "MCP", "Network", "Identity"];

export function SystemReveal() {
  const reducedMotion = useReducedMotion();

  return (
    <div className="relative overflow-hidden">
      <div className="absolute inset-0 argus-workspace-grid opacity-25" aria-hidden />
      <div className="system-radar pointer-events-none absolute right-[3%] top-[8%] hidden h-64 w-64 md:block" aria-hidden>
        <span className="system-radar-ring system-radar-ring--outer" />
        <span className="system-radar-ring system-radar-ring--inner" />
        <motion.span className="system-radar-sweep" animate={reducedMotion ? undefined : { rotate: 360 }} transition={{ duration: 5.5, repeat: Infinity, ease: "linear" }} />
        <Crosshair className="absolute left-1/2 top-1/2 h-5 w-5 -translate-x-1/2 -translate-y-1/2 text-accent/55" />
      </div>
      <motion.div
        aria-hidden
        className="absolute left-0 right-0 top-1/2 h-px bg-gradient-to-r from-transparent via-accent/55 to-transparent"
        animate={reducedMotion ? undefined : { y: [-180, 180], opacity: [0, 0.75, 0] }}
        transition={{ duration: 4.2, repeat: Infinity, ease: "easeInOut" }}
      />

      <div className="relative z-10">
        <motion.div
          initial={{ opacity: 0, y: 18 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.65, ease: [0.16, 1, 0.3, 1] }}
          className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-accent/30 bg-accent/5 text-accent text-xs font-mono uppercase tracking-[0.22em]"
        >
          <LiveDot active={!reducedMotion} />
          Live system reveal
        </motion.div>

        <div className="relative mt-10">
          <motion.div
            aria-hidden
            className="absolute inset-x-0 top-1/2 h-24 -translate-y-1/2 bg-gradient-to-r from-transparent via-accent/10 to-transparent blur-xl"
            animate={reducedMotion ? undefined : { opacity: [0.25, 0.7, 0.25], scaleX: [0.9, 1.05, 0.9] }}
            transition={{ duration: 3.8, repeat: Infinity, ease: "easeInOut" }}
          />
          <div className="overflow-hidden">
            <motion.h1
              initial={{ y: "105%", opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              transition={{ duration: 1, ease: [0.16, 1, 0.3, 1] }}
              className="halftone-text halftone-breathe text-[clamp(5.5rem,19vw,19rem)] leading-[0.78]"
            >
              ARGUS
            </motion.h1>
          </div>
          <motion.div
            className="mt-5 flex items-center gap-3 font-mono text-[11px] uppercase tracking-[0.22em] text-text-muted"
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.55, duration: 0.65, ease: [0.16, 1, 0.3, 1] }}
          >
            <Bot className="h-4 w-4 text-accent" />
            Adversarial Reasoning Graph Unified Security
          </motion.div>
          <div className="mt-5 flex items-center gap-3 font-mono text-[9px] uppercase tracking-[0.18em] text-text-muted">
            <span className="text-accent">Signal acquired</span>
            <span className="h-px w-16 bg-accent/35" />
            <motion.span animate={reducedMotion ? undefined : { opacity: [0.35, 1, 0.35] }} transition={{ duration: 2.2, repeat: Infinity }}>8-layer reasoning mesh online</motion.span>
          </div>

          <motion.div
            initial={{ opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.68, duration: 0.65, ease: [0.16, 1, 0.3, 1] }}
            className="mt-8 grid gap-2 sm:grid-cols-6"
          >
            {TELEMETRY.map((label, index) => (
              <div key={label} className="relative overflow-hidden rounded-md border border-line/10 bg-bg/45 px-3 py-2">
                <motion.span
                  aria-hidden
                  className="absolute inset-y-0 left-0 w-1/2 bg-gradient-to-r from-transparent via-accent/15 to-transparent"
                  animate={reducedMotion ? undefined : { x: ["-120%", "240%"] }}
                  transition={{ duration: 2.8, delay: index * 0.18, repeat: Infinity, ease: "linear" }}
                />
                <div className="relative flex items-center justify-between gap-2">
                  <span className="font-mono text-[10px] uppercase tracking-[0.16em] text-text-secondary">{label}</span>
                  <span className="h-1.5 w-1.5 rounded-full bg-accent shadow-[0_0_10px_rgb(var(--accent)/0.6)]" />
                </div>
              </div>
            ))}
          </motion.div>
        </div>

        <div className="mt-10 grid gap-3 md:grid-cols-3">
          {FEATURES.map(({ k, title, body, Icon }, i) => (
            <motion.div
              key={k}
              initial={{ opacity: 0, y: 26, filter: "blur(6px)" }}
              animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
              whileHover={{ y: -4 }}
              transition={{ delay: 0.72 + i * 0.12, duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
              className="argus-panel-shell group rounded-lg border border-line/15 bg-surface/55 p-5"
            >
              <div className="flex items-center justify-between gap-4">
                <span className="font-mono text-xs text-accent">{k}</span>
                <span className="h-px flex-1 bg-line/10" />
                <div className="flex h-9 w-9 items-center justify-center rounded-md border border-accent/25 bg-accent/10 text-accent transition-colors group-hover:bg-accent/15">
                  <Icon className="h-4 w-4" />
                </div>
              </div>
              <p className="mt-5 text-lg font-semibold text-text-primary">{title}</p>
              <p className="mt-2 text-sm leading-relaxed text-text-secondary">{body}</p>
            </motion.div>
          ))}
        </div>
      </div>
    </div>
  );
}
