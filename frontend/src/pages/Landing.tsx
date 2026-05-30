import { useEffect, useRef, useState, type CSSProperties } from "react";
import { motion, useScroll, useTransform } from "framer-motion";
import {
  Eye, Globe, Bot, Database, Wrench, Radar, Package, Users, KeyRound,
  ArrowRight, ArrowDown, Search, Cloud, Users2, GraduationCap, Crosshair, Check, Quote,
} from "lucide-react";

const ACCENTS = {
  neutral:  { a: "139 122 255", s: "217 70 239", g: "139 122 255" },
  basic:    { a: "79 70 229",   s: "37 99 235",  g: "79 70 229"  },
  advanced: { a: "168 85 247",  s: "217 70 239", g: "168 85 247" },
};

const LAYERS = [
  { id: 1, Icon: Globe,    label: "Web Surface",      std: "OWASP Web Top 10" },
  { id: 2, Icon: Bot,      label: "LLM Probe",        std: "OWASP LLM01/07:2025" },
  { id: 3, Icon: Database, label: "RAG Poisoning",    std: "OWASP LLM08:2025" },
  { id: 4, Icon: Wrench,   label: "MCP / Agentic",    std: "Agentic Top 10" },
  { id: 5, Icon: Radar,    label: "Network Recon",    std: "MITRE T1046" },
  { id: 6, Icon: Package,  label: "Supply Chain",     std: "OWASP A06:2021" },
  { id: 7, Icon: Users,    label: "Multi-Agent",      std: "MASpi" },
  { id: 8, Icon: KeyRound, label: "Identity / OAuth", std: "MITRE ATLAS" },
];

const STEPS = [
  { n: "01", title: "Define the target", desc: "A URL, an LLM endpoint, or a plain-text description. No agents to install." },
  { n: "02", title: "Scan every layer",  desc: "Up to 8 attack layers run in parallel across web, AI, and infrastructure." },
  { n: "03", title: "Reason across them", desc: "Findings correlate into emergent kill-chains no single tool can see." },
  { n: "04", title: "Get the report",    desc: "Prioritized chains, remediations, and HTML / PDF / STIX 2.1 exports." },
];

const AGENT_CHIPS = ["what's your stack?", "show me a chain", "which layers run?", "/help"];

function Reveal({ children, delay = 0, className }: { children: React.ReactNode; delay?: number; className?: string }) {
  return (
    <motion.div className={className} initial={{ opacity: 0, y: 44 }} whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-80px" }} transition={{ duration: 0.7, delay, ease: [0.16, 1, 0.3, 1] }}>
      {children}
    </motion.div>
  );
}

function useClock() {
  const [t, setT] = useState("");
  useEffect(() => {
    const fmt = () => new Date().toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", hour12: true });
    setT(fmt());
    const id = setInterval(() => setT(fmt()), 30_000);
    return () => clearInterval(id);
  }, []);
  return t;
}

interface Props { onEnter: () => void }

export function Landing({ onEnter }: Props) {
  const [mode, setMode] = useState<keyof typeof ACCENTS>("neutral");
  const acc = ACCENTS[mode];
  const rootStyle = { "--accent": acc.a, "--accent-strong": acc.s, "--glow": acc.g } as CSSProperties;
  const clock = useClock();
  const today = new Date().toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" }).toUpperCase().replace(/ /g, "/");

  const ref = useRef<HTMLDivElement>(null);
  const { scrollYProgress } = useScroll({ target: ref, offset: ["start start", "end start"] });
  const gA = useTransform(scrollYProgress, [0, 1], [0, 220]);
  const gFade = useTransform(scrollYProgress, [0, 1], [1, 0.12]);

  return (
    <div ref={ref} className="accent-reactive relative min-h-screen bg-bg text-text-primary overflow-x-hidden" style={rootStyle}>
      {/* Aurora + editor ruler background */}
      <div className="fixed inset-0 pointer-events-none">
        <motion.div style={{ y: gA, opacity: gFade }} className="aurora absolute -top-40 -left-32 w-[680px] h-[680px] rounded-full"
          children={<div className="w-full h-full rounded-full" style={{ background: "radial-gradient(circle, rgba(139,122,255,0.16) 0%, transparent 70%)" }} />} />
        <motion.div style={{ opacity: gFade }} className="aurora absolute top-10 -right-40 w-[720px] h-[720px] rounded-full"
          children={<div className="w-full h-full rounded-full" style={{ background: "radial-gradient(circle, rgba(217,70,239,0.12) 0%, transparent 70%)" }} />} />
        <div className="absolute inset-0 editor-rules opacity-100" />
      </div>

      {/* ── NAV ── */}
      <nav className="sticky top-0 z-30 flex items-center justify-between px-6 md:px-10 py-5 border-b border-line/10 bg-bg/70 backdrop-blur-xl">
        <button onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })} className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg border border-accent/40 flex items-center justify-center bg-accent/10">
            <Eye className="w-4 h-4 text-accent" strokeWidth={2.2} />
          </div>
          <span className="font-mono font-bold tracking-[0.22em] text-sm">ARGUS</span>
        </button>
        <div className="hidden md:flex items-center gap-10 text-sm font-medium">
          <a href="#layers" className="flex items-start gap-0.5 hover:text-accent transition-colors">LAYERS <sup className="text-accent text-[10px]">8</sup></a>
          <a href="#process" className="flex items-start gap-0.5 hover:text-accent transition-colors">PROCESS <sup className="text-accent text-[10px]">4</sup></a>
          <a href="#modes" className="hover:text-accent transition-colors">MODES</a>
        </div>
        <button onClick={onEnter}
          className="flex items-center gap-2 text-sm text-text-secondary hover:text-text-primary transition-colors">
          LAUNCH <Search className="w-4 h-4" />
          <span className="hidden sm:flex items-center gap-1 font-mono text-[11px] text-text-muted">
            <kbd className="px-1.5 py-0.5 rounded border border-line/25">CTRL</kbd>+<kbd className="px-1.5 py-0.5 rounded border border-line/25">K</kbd>
          </span>
        </button>
      </nav>

      {/* ── HERO (editor metaphor) ── */}
      <header className="relative z-10 px-6 md:px-10 pt-10 pb-20 max-w-[1500px] mx-auto">
        {/* meta bar */}
        <div className="flex items-center gap-3 text-[11px] font-mono tracking-widest text-text-muted">
          <span>ARGUS</span><span className="opacity-40">/</span>
          <span>{clock || "—"}</span><span className="opacity-40">/</span>
          <span>{today}</span>
        </div>
        <div className="mt-3 flex items-center gap-4">
          <span className="flex items-center gap-1.5 text-sm font-mono text-text-secondary"><Cloud className="w-4 h-4 text-accent" /> 8 layers</span>
          <span className="flex items-center gap-1.5 px-3 py-1 rounded-full border border-line/20 bg-surface/60 text-xs font-mono">
            <Users2 className="w-3.5 h-3.5 text-accent" /> COLLAB ON <span className="w-1.5 h-1.5 rounded-full bg-accent animate-pulse" />
          </span>
        </div>

        {/* selection-boxed headline + side cursors */}
        <div className="relative mt-10 grid lg:grid-cols-[1.5fr_1fr] gap-10 items-start">
          <div className="relative">
            {/* multiplayer cursors */}
            <div className="mp-cursor bob1" style={{ top: "-26px", left: "-4px" }}>
              <svg width="16" height="16" viewBox="0 0 16 16" fill="rgb(var(--accent))"><path d="M0 0l5 16 3-7 7-3z"/></svg>
              <span className="mp-tag" style={{ background: "rgb(var(--accent))" }}>You</span>
            </div>
            <div className="mp-cursor bob2" style={{ bottom: "-10px", right: "8%" }}>
              <svg width="16" height="16" viewBox="0 0 16 16" fill="#f97316"><path d="M0 0l5 16 3-7 7-3z"/></svg>
              <span className="mp-tag" style={{ background: "#f97316" }}>ARGUS</span>
            </div>

            <motion.div initial={{ opacity: 0, scale: 0.98 }} animate={{ opacity: 1, scale: 1 }} transition={{ duration: 0.6 }}
              className="sel-box px-3 py-2">
              <span className="sel-tag">Text</span>
              <span className="sel-handle tl" /><span className="sel-handle tr" /><span className="sel-handle bl" /><span className="sel-handle br" />
              <h1 className="display-tight font-black text-[13vw] lg:text-[8.5rem] leading-[0.82] tracking-tight">ARGUS</h1>
            </motion.div>

            {/* dither second word */}
            <motion.p initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.4, duration: 1 }}
              className="mt-8 gradient-spectrum display-tight font-black text-[10vw] lg:text-[6rem] leading-none select-none"
              style={{ filter: "blur(0.4px)" }}>
              sees all
            </motion.p>
          </div>

          <motion.p initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.3 }}
            className="text-text-secondary text-lg md:text-xl leading-relaxed lg:pt-6 max-w-md">
            Adversarial reasoning across <span className="text-text-primary">8 attack layers</span>. ARGUS models how a web
            injection feeds an LLM that poisons a RAG corpus that hijacks an agent — surfacing the cross-layer chains no
            single tool can see.
          </motion.p>
        </div>

        {/* CTA pill */}
        <div className="mt-16 flex flex-col items-center gap-3">
          <button onClick={onEnter}
            className="group flex items-center gap-3 px-8 py-4 rounded-full bg-surface border border-line/20 hover:border-accent/50 font-mono font-semibold tracking-wide transition-all">
            DISCOVER ARGUS <ArrowDown className="w-4 h-4 text-accent group-hover:translate-y-1 transition-transform" />
          </button>
          <span className="text-[11px] font-mono tracking-[0.25em] text-text-muted">OR SCROLL DOWN</span>
        </div>
      </header>

      {/* ── MARQUEE ── */}
      <section className="relative z-10 py-9 border-y border-line/10 bg-surface/40">
        <p className="text-center text-text-muted text-xs font-mono uppercase tracking-[0.25em] mb-6">Eight layers · one campaign</p>
        <div className="marquee-mask overflow-hidden">
          <div className="marquee-track gap-4">
            {[...LAYERS, ...LAYERS].map((l, i) => (
              <div key={i} className="flex items-center gap-3 px-6 py-3 rounded-xl border border-line/15 bg-surface shrink-0">
                <div className="w-9 h-9 rounded-lg bg-accent/10 border border-accent/20 flex items-center justify-center"><l.Icon className="w-5 h-5 text-accent" /></div>
                <div><p className="text-sm font-semibold whitespace-nowrap">L{l.id} · {l.label}</p>
                  <p className="text-[11px] font-mono text-text-muted whitespace-nowrap">{l.std}</p></div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── QUOTE BAND (dark, imflorea section-2 style) ── */}
      <section className="relative z-10 px-6 md:px-10 py-28 bg-surface/60 border-b border-line/10">
        <Reveal className="max-w-[1500px] mx-auto flex items-start gap-8">
          <Quote className="w-10 h-10 text-accent shrink-0 hidden md:block" />
          <h2 className="display-tight text-balance text-4xl md:text-7xl font-black leading-[1.02]">
            SIMPLICITY MEETS <span className="gradient-spectrum">SOPHISTICATION.</span>{" "}
            <span className="text-text-muted text-3xl md:text-5xl">One graph that reasons where four siloed tools go blind.</span>
          </h2>
        </Reveal>
      </section>

      {/* ── AGENT TERMINAL (imflorea talk-to-my-agent) ── */}
      <Section id="agent">
        <Reveal>
          <div className="rounded-2xl border border-accent/20 bg-surface/70 overflow-hidden">
            <div className="flex items-center justify-between px-5 py-3 border-b border-line/10">
              <span className="font-mono text-xs tracking-widest text-text-muted">ARGUS — REASONING ENGINE</span>
              <span className="flex items-center gap-1.5 font-mono text-xs text-accent"><span className="w-1.5 h-1.5 rounded-full bg-accent animate-pulse" /> LOCAL · READY</span>
            </div>
            <div className="p-6 md:p-10 font-mono text-sm md:text-base leading-relaxed">
              <p className="text-text-muted">argus · v0.1 · build <span className="text-accent">dev</span> · 8-layer</p>
              <p className="mt-5 text-2xl md:text-3xl font-bold"><span className="text-accent">reasoning</span>.<span className="inline-block w-3 h-6 bg-accent align-middle cursor-blink ml-1" /></p>
              <p className="mt-5 text-text-secondary max-w-3xl">
                trained to chain findings across web, LLM, RAG, agentic, network, supply-chain, multi-agent and identity —
                the emergent attack paths that single-domain scanners structurally miss.
              </p>
              <p className="mt-4 text-text-muted text-xs">⚠ ARGUS is for authorized testing only — reason about systems you own or are permitted to assess.</p>
              <p className="mt-6 text-[#22c55e]">$ try one ›</p>
              <div className="mt-3 flex flex-wrap gap-3">
                {AGENT_CHIPS.map((c) => (
                  <button key={c} onClick={onEnter}
                    className="px-4 py-2.5 rounded-lg border border-line/20 bg-bg/50 text-node-probing hover:border-accent/50 hover:text-accent transition-all">
                    [ {c} ]
                  </button>
                ))}
              </div>
            </div>
          </div>
        </Reveal>
      </Section>

      {/* ── LAYERS GRID ── */}
      <Section id="layers">
        <Reveal>
          <Eyebrow>Coverage</Eyebrow>
          <h2 className="mt-5 display-tight text-balance text-4xl md:text-6xl font-bold max-w-3xl">Eight layers. One coordinated campaign.</h2>
        </Reveal>
        <div className="mt-12 grid grid-cols-2 md:grid-cols-4 gap-4">
          {LAYERS.map((l, i) => (
            <Reveal key={l.id} delay={i * 0.05}>
              <div className="group h-full p-6 rounded-2xl border border-line/15 bg-surface/60 hover:bg-surface transition-colors">
                <div className="flex items-center justify-between mb-8">
                  <div className="w-10 h-10 rounded-xl bg-accent/10 border border-accent/25 flex items-center justify-center"><l.Icon className="w-5 h-5 text-accent" /></div>
                  <span className="font-mono text-xs text-accent">L{l.id}</span>
                </div>
                <p className="font-semibold mb-1 group-hover:text-accent transition-colors">{l.label}</p>
                <p className="text-xs font-mono text-text-muted">{l.std}</p>
              </div>
            </Reveal>
          ))}
        </div>
      </Section>

      {/* ── PROCESS ── */}
      <Section id="process">
        <Reveal><Eyebrow>How it works</Eyebrow></Reveal>
        <div className="mt-10 border-t border-line/10">
          {STEPS.map((s, i) => (
            <Reveal key={s.n} delay={i * 0.05}>
              <div className="grid md:grid-cols-[auto_1fr_2fr] gap-4 md:gap-10 items-baseline py-8 border-b border-line/10 group">
                <span className="font-mono text-accent text-lg">{s.n}</span>
                <h3 className="text-2xl md:text-3xl font-semibold group-hover:text-accent transition-colors">{s.title}</h3>
                <p className="text-text-secondary md:text-lg leading-relaxed">{s.desc}</p>
              </div>
            </Reveal>
          ))}
        </div>
      </Section>

      {/* ── MODES ── */}
      <Section id="modes">
        <Reveal><Eyebrow>Choose your depth</Eyebrow></Reveal>
        <div className="mt-10 grid md:grid-cols-2 gap-5">
          <ModeCard onHover={() => setMode("basic")} onLeave={() => setMode("neutral")} onClick={onEnter}
            accent="79 70 229" Icon={GraduationCap} name="Basic" tag="3 layers · quick assessment"
            points={["Web surface · LLM probe · RAG poisoning", "Top chains + one-page report", "No configuration required"]} ideal="Students, quick assessments" />
          <ModeCard onHover={() => setMode("advanced")} onLeave={() => setMode("neutral")} onClick={onEnter}
            accent="168 85 247" Icon={Crosshair} name="Advanced" tag="8 layers · full red team"
            points={["All 8 layers, configurable", "Sandboxed recon terminal", "STIX 2.1 + PDF export"]} ideal="Red teamers, researchers" />
        </div>
      </Section>

      {/* ── CTA ── */}
      <section className="relative z-10 px-6 md:px-10 py-28 text-center">
        <Reveal>
          <h2 className="display-tight text-balance text-5xl md:text-8xl font-black mb-8">Reason about<br /><span className="gradient-spectrum">your attack surface.</span></h2>
          <p className="text-text-secondary mb-10">Only test targets you own or are authorized to assess.</p>
          <button onClick={onEnter}
            className="group inline-flex items-center gap-2 px-10 py-5 rounded-full bg-accent text-[rgb(var(--accent-contrast))] text-lg font-semibold hover:opacity-90 transition-all">
            Launch ARGUS <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
          </button>
        </Reveal>
      </section>

      {/* ── FOOTER ── */}
      <footer className="relative z-10 border-t border-line/10 px-6 md:px-10 py-10">
        <div className="max-w-[1500px] mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-lg border border-accent/40 flex items-center justify-center bg-accent/10"><Eye className="w-4 h-4 text-accent" /></div>
            <span className="font-mono font-bold tracking-[0.22em] text-sm">ARGUS</span>
          </div>
          <p className="text-text-muted text-xs font-mono text-center">Adversarial Reasoning &amp; Graph-based Unified Security · For authorized testing only</p>
        </div>
      </footer>
    </div>
  );
}

function Section({ children, id }: { children: React.ReactNode; id?: string }) {
  return <section id={id} className="relative z-10 px-6 md:px-10 py-20 md:py-28 max-w-[1500px] mx-auto">{children}</section>;
}
function Eyebrow({ children }: { children: React.ReactNode }) {
  return <p className="text-accent text-xs font-mono uppercase tracking-[0.25em]">{children}</p>;
}
function ModeCard({ onHover, onLeave, onClick, accent, Icon, name, tag, points, ideal }: {
  onHover: () => void; onLeave: () => void; onClick: () => void; accent: string;
  Icon: typeof GraduationCap; name: string; tag: string; points: string[]; ideal: string;
}) {
  return (
    <motion.button initial={{ opacity: 0, y: 24 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }}
      onMouseEnter={onHover} onMouseLeave={onLeave} onClick={onClick}
      className="group text-left p-8 rounded-3xl border transition-all duration-500"
      style={{ borderColor: `rgb(${accent} / 0.3)`, background: `rgb(${accent} / 0.06)` }}>
      <div className="flex items-center justify-between mb-8">
        <div className="w-12 h-12 rounded-2xl flex items-center justify-center" style={{ background: `rgb(${accent} / 0.14)`, border: `1px solid rgb(${accent} / 0.3)` }}>
          <Icon className="w-6 h-6" style={{ color: `rgb(${accent})` }} />
        </div>
        <ArrowRight className="w-6 h-6 group-hover:translate-x-1 transition-transform" style={{ color: `rgb(${accent})` }} />
      </div>
      <h3 className="text-3xl font-bold mb-1">{name}</h3>
      <p className="font-mono text-sm mb-6" style={{ color: `rgb(${accent})` }}>{tag}</p>
      <ul className="space-y-2.5 mb-6">
        {points.map((p) => (<li key={p} className="flex items-center gap-2.5 text-text-secondary"><Check className="w-4 h-4 shrink-0" style={{ color: `rgb(${accent})` }} /> {p}</li>))}
      </ul>
      <p className="text-xs font-mono text-text-muted">Ideal for: {ideal}</p>
    </motion.button>
  );
}
