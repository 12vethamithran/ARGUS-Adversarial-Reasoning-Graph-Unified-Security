import { useEffect, useRef, useState, type CSSProperties } from "react";
import { motion, useScroll, useTransform } from "framer-motion";
import {
  Globe, Bot, Database, Wrench, Radar, Package, Users, KeyRound,
  ArrowRight, ArrowDown, GraduationCap, Crosshair, Check, X,
} from "lucide-react";

const ACCENTS = {
  neutral:  { a: "255 61 18", s: "217 45 10" },   // Furo orange-red
  basic:    { a: "255 61 18", s: "217 45 10" },   // mono — orange-red everywhere
  advanced: { a: "255 61 18", s: "217 45 10" },
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

const STATS = [
  { v: "8", l: "Attack layers correlated" },
  { v: "24+", l: "OWASP / MITRE references" },
  { v: "3", l: "Security domains unified" },
  { v: "0", l: "Agents to install" },
];

const CHAIN = [
  { Icon: Globe,    l: "L1", t: "Web injection",      d: "Reflected input on a public field" },
  { Icon: Bot,      l: "L2", t: "Prompt injection",   d: "Payload steers the model" },
  { Icon: Database, l: "L3", t: "RAG poisoning",       d: "Adversarial doc enters the corpus" },
  { Icon: Wrench,   l: "L4", t: "Tool-call hijack",    d: "Agent invokes an internal action" },
  { Icon: Radar,    l: "L5", t: "Network pivot",       d: "Lateral movement to internal data" },
];

const COMPARE = [
  { tool: "Burp / ZAP", web: true, llm: false, net: false, chain: false },
  { tool: "Garak / PyRIT", web: false, llm: true, net: false, chain: false },
  { tool: "Nessus / Metasploit", web: false, llm: false, net: true, chain: false },
  { tool: "ARGUS", web: true, llm: true, net: true, chain: true, me: true },
];

const APART = [
  { n: "01", title: "Reasons across layers", body: "Most scanners look at one domain. ARGUS correlates findings across all eight into emergent kill-chains — the attacks that only appear between tools." },
  { n: "02", title: "Built for AI threats", body: "Purpose-built for LLM, RAG, MCP/agentic and multi-agent risks. Not a web scanner with an AI checkbox bolted on." },
  { n: "03", title: "Validates in the open", body: "A sandboxed, whitelisted recon terminal to confirm findings live against the target — exploit and destructive flags blocked." },
];

function Reveal({ children, delay = 0, className }: { children: React.ReactNode; delay?: number; className?: string }) {
  return (
    <motion.div className={className}
      initial={{ opacity: 0, y: 56, filter: "blur(6px)" }}
      whileInView={{ opacity: 1, y: 0, filter: "blur(0px)" }}
      viewport={{ once: true, margin: "-90px" }}
      transition={{ duration: 0.85, delay, ease: [0.16, 1, 0.3, 1] }}>
      {children}
    </motion.div>
  );
}

function useClock() {
  const [t, setT] = useState("");
  useEffect(() => {
    const fmt = () => new Date().toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
    setT(fmt());
    const id = setInterval(() => setT(fmt()), 20_000);
    return () => clearInterval(id);
  }, []);
  return t;
}

// Drifting particle cluster (Furo problem-section motif).
function Particles() {
  const dots = Array.from({ length: 90 }, (_, i) => i);
  return (
    <div className="relative w-full h-72">
      {dots.map((i) => {
        const a = (i / 90) * Math.PI * 2;
        const r = 30 + Math.random() * 120;
        const x = 50 + Math.cos(a) * r * 0.32;
        const y = 50 + Math.sin(a) * r * 0.32;
        return (
          <motion.span key={i} className="absolute text-text-muted font-mono text-xs"
            style={{ left: `${x}%`, top: `${y}%` }}
            animate={{ opacity: [0.15, 0.7, 0.15], scale: [1, 1.4, 1] }}
            transition={{ duration: 3 + (i % 5), repeat: Infinity, delay: i * 0.04 }}>
            +
          </motion.span>
        );
      })}
    </div>
  );
}

interface Props { onEnter: () => void }

export function Landing({ onEnter }: Props) {
  const [mode, setMode] = useState<keyof typeof ACCENTS>("neutral");
  const acc = ACCENTS[mode];
  const rootStyle = { "--accent": acc.a, "--accent-strong": acc.s, "--glow": acc.a } as CSSProperties;
  const clock = useClock();

  const ref = useRef<HTMLDivElement>(null);
  const { scrollYProgress } = useScroll({ target: ref, offset: ["start start", "end start"] });
  const heroY = useTransform(scrollYProgress, [0, 1], [0, -160]);
  const heroFade = useTransform(scrollYProgress, [0, 0.55], [1, 0]);
  const heroScale = useTransform(scrollYProgress, [0, 0.6], [1, 1.12]);

  return (
    <div ref={ref} className="accent-reactive relative min-h-screen bg-bg text-text-primary overflow-x-hidden" style={rootStyle}>
      {/* ── NAV ── */}
      <nav className="sticky top-0 z-30 flex items-center justify-between px-6 md:px-10 py-5 border-b border-line/10 bg-bg/80 backdrop-blur-xl">
        <div className="flex items-center gap-5">
          <button onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
            className="font-black tracking-tight text-2xl">ARGUS</button>
          <span className="hidden sm:block w-px h-5 bg-line/20" />
          <span className="hidden sm:block font-mono text-[11px] tracking-[0.2em] text-text-muted">{clock || "--:--"} · GLOBAL</span>
        </div>
        <div className="flex items-center gap-7 text-xs font-medium tracking-[0.18em]">
          <a href="#layers" className="hidden sm:block text-text-secondary hover:text-text-primary transition-colors">LAYERS</a>
          <a href="#method" className="hidden sm:block text-text-secondary hover:text-text-primary transition-colors">METHOD</a>
          <a href="#modes" className="hidden sm:block text-text-secondary hover:text-text-primary transition-colors">MODES</a>
          <button onClick={onEnter} className="flex items-center gap-2 text-text-primary">
            <span className="w-1.5 h-1.5 rounded-full bg-accent animate-pulse" /> LAUNCH
          </button>
        </div>
      </nav>

      {/* ── HERO (Furo dithered word + serif overlay) ── */}
      <header className="relative px-6 md:px-10 pt-10 pb-20 max-w-[1600px] mx-auto min-h-[92vh] flex flex-col">
        <motion.div style={{ y: heroY, opacity: heroFade, scale: heroScale }} aria-hidden
          className="halftone-text absolute inset-x-4 md:inset-x-10 top-2 text-[24vw] leading-[0.8] pointer-events-none select-none origin-top">
          ARGUS
        </motion.div>

        {/* headline anchored to lower third, well clear of the dithered word */}
        <div className="relative z-10 mt-auto">
          <motion.h1 initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.9, ease: [0.16, 1, 0.3, 1] }}
            className="font-serif-display text-5xl md:text-8xl leading-[0.95] max-w-4xl">
            Security that <span className="serif-italic">sees</span><br />every attack chain.
          </motion.h1>

          {/* CTA (left) + description (right) on one row, generous gap below headline */}
          <div className="mt-16 grid md:grid-cols-[auto_1fr] items-end gap-x-10 gap-y-8">
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.45 }}
              className="flex items-center gap-5">
              <button onClick={onEnter}
                className="group flex items-center gap-3 px-7 py-4 rounded-full bg-accent text-[rgb(var(--accent-contrast))] font-medium tracking-wide hover:opacity-90 transition-all">
                DISCOVER ARGUS <ArrowDown className="w-4 h-4 group-hover:translate-y-1 transition-transform" />
              </button>
              <span className="font-mono text-[11px] tracking-[0.25em] text-text-muted whitespace-nowrap">OR SCROLL DOWN</span>
            </motion.div>
            <motion.p initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.55 }}
              className="md:justify-self-end md:text-right text-text-secondary leading-relaxed max-w-sm">
              Adversarial reasoning across eight layers — modeling how a web injection feeds an LLM that
              poisons a RAG corpus that hijacks an agent.
            </motion.p>
          </div>
        </div>
        {/* end hero content */}
      </header>

      {/* ── PROBLEM BAND ── */}
      <section className="relative px-6 md:px-10 py-28 border-t border-line/10 max-w-[1600px] mx-auto">
        <Reveal>
          <h2 className="font-serif-display text-4xl md:text-7xl leading-[1.05] max-w-4xl">
            Your stack is layered.<br />Your scanners <span className="serif-italic">aren't.</span>
          </h2>
        </Reveal>
        <div className="mt-16 grid md:grid-cols-2 gap-12 items-center">
          <Reveal><Particles /></Reveal>
          <Reveal delay={0.1} className="space-y-6 text-text-secondary text-lg leading-relaxed max-w-lg">
            <p>You harden the web tier. You probe the model. You scan the network. Each tool sees its own slice — and nothing sees the seams between them.</p>
            <p>But real breaches don't respect tool boundaries. A reflected input becomes a prompt injection, becomes a poisoned retrieval, becomes a hijacked agent, becomes a network pivot.</p>
            <p className="text-text-primary">That cross-layer chain is exactly what ARGUS is built to reason about.</p>
          </Reveal>
        </div>
      </section>

      {/* ── MARQUEE ── */}
      <section className="relative py-9 border-y border-line/10 bg-surface/40">
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

      {/* ── LAYERS (big serif-italic title + grid) ── */}
      <Section id="layers">
        <Reveal>
          <h2 className="font-serif-display text-6xl md:text-[9rem] leading-none text-center">
            <span className="serif-italic">LAYERS</span>
          </h2>
        </Reveal>
        <div className="mt-16 grid grid-cols-2 md:grid-cols-4 gap-4">
          {LAYERS.map((l, i) => (
            <Reveal key={l.id} delay={i * 0.04}>
              <div className="group h-full p-6 rounded-2xl border border-line/15 bg-surface/60 hover:bg-surface transition-colors">
                <div className="flex items-center justify-between mb-10">
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

      {/* ── WHAT SETS US APART (numbered serif rows) ── */}
      <Section id="method">
        <Reveal><p className="text-accent text-xs font-mono uppercase tracking-[0.25em]">What sets ARGUS apart</p></Reveal>
        <div className="mt-12 border-t border-line/10">
          {APART.map((a, i) => (
            <Reveal key={a.n} delay={i * 0.06}>
              <div className="grid md:grid-cols-[1.4fr_1fr] gap-6 md:gap-16 py-10 border-b border-line/10 items-baseline">
                <h3 className="font-serif-display text-3xl md:text-6xl leading-tight">
                  <span className="text-accent">{a.n}</span> {a.title}
                </h3>
                <p className="text-text-secondary leading-relaxed md:text-lg">{a.body}</p>
              </div>
            </Reveal>
          ))}
        </div>
      </Section>

      {/* ── STATS BAND ── */}
      <section className="relative px-6 md:px-10 py-20 border-y border-line/10 bg-surface/30">
        <div className="max-w-[1600px] mx-auto grid grid-cols-2 md:grid-cols-4 gap-10">
          {STATS.map((s, i) => (
            <Reveal key={s.l} delay={i * 0.06} className="text-center">
              <p className="font-serif-display text-6xl md:text-8xl leading-none text-accent">{s.v}</p>
              <p className="text-text-muted text-sm mt-3">{s.l}</p>
            </Reveal>
          ))}
        </div>
      </section>

      {/* ── ATTACK-CHAIN SHOWCASE ── */}
      <Section id="chain">
        <Reveal>
          <p className="text-accent text-xs font-mono uppercase tracking-[0.25em]">The emergent threat</p>
          <h2 className="mt-5 font-serif-display text-4xl md:text-7xl leading-[1.05] max-w-4xl">
            One chain. Five layers.<br /><span className="serif-italic">Zero tools that catch it.</span>
          </h2>
        </Reveal>
        <div className="mt-16 grid md:grid-cols-5 gap-3">
          {CHAIN.map((c, i) => (
            <Reveal key={c.l} delay={i * 0.08}>
              <div className="relative h-full p-6 rounded-2xl border border-line/15 bg-surface/60">
                <div className="w-10 h-10 rounded-xl bg-accent/10 border border-accent/25 flex items-center justify-center mb-6">
                  <c.Icon className="w-5 h-5 text-accent" />
                </div>
                <span className="font-mono text-xs text-accent">{c.l}</span>
                <p className="font-semibold mt-1">{c.t}</p>
                <p className="text-text-muted text-xs mt-2 leading-relaxed">{c.d}</p>
                {i < CHAIN.length - 1 && (
                  <ArrowRight className="hidden md:block absolute top-1/2 -right-2.5 w-4 h-4 text-accent/50 -translate-y-1/2" />
                )}
              </div>
            </Reveal>
          ))}
        </div>
        <Reveal delay={0.1}>
          <div className="mt-8 flex flex-wrap gap-6 font-mono text-sm text-text-muted">
            <span>Exploitability <span className="text-accent">0.89</span></span>
            <span>Impact <span className="text-accent">0.94</span></span>
            <span>Novelty <span className="text-accent">0.81</span></span>
            <span>Priority <span className="text-accent">0.91</span></span>
          </div>
        </Reveal>
      </Section>

      {/* ── COMPARISON ── */}
      <Section id="compare">
        <Reveal>
          <p className="text-accent text-xs font-mono uppercase tracking-[0.25em]">The gap</p>
          <h2 className="mt-5 font-serif-display text-4xl md:text-6xl max-w-3xl">Why siloed tools miss the real risk.</h2>
        </Reveal>
        <Reveal delay={0.1}>
          <div className="mt-12 max-w-4xl border border-line/15 rounded-2xl overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-line/15 text-text-muted font-mono text-xs">
                  <th className="text-left px-5 py-4 font-normal">Tool</th>
                  <th className="px-3 py-4 font-normal">Web</th><th className="px-3 py-4 font-normal">LLM</th>
                  <th className="px-3 py-4 font-normal">Network</th><th className="px-3 py-4 font-normal">Cross-layer</th>
                </tr>
              </thead>
              <tbody>
                {COMPARE.map((r) => (
                  <tr key={r.tool} className={`border-b border-line/10 last:border-0 ${r.me ? "bg-accent/5" : ""}`}>
                    <td className={`px-5 py-4 font-mono ${r.me ? "text-accent font-bold" : "text-text-secondary"}`}>{r.tool}</td>
                    {[r.web, r.llm, r.net, r.chain].map((v, j) => (
                      <td key={j} className="px-3 py-4 text-center">
                        {v ? <Check className="w-4 h-4 text-accent mx-auto" /> : <X className="w-4 h-4 text-text-muted/40 mx-auto" />}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Reveal>
      </Section>

      {/* ── MODES ── */}
      <Section id="modes">
        <Reveal><p className="text-accent text-xs font-mono uppercase tracking-[0.25em]">Choose your depth</p></Reveal>
        <div className="mt-10 grid md:grid-cols-2 gap-5">
          <ModeCard onHover={() => setMode("basic")} onLeave={() => setMode("neutral")} onClick={onEnter}
            accent="255 61 18" Icon={GraduationCap} name="Basic" tag="3 layers · quick assessment"
            points={["Web surface · LLM probe · RAG poisoning", "Top chains + one-page report", "No configuration required"]} ideal="Students, quick assessments" />
          <ModeCard onHover={() => setMode("advanced")} onLeave={() => setMode("neutral")} onClick={onEnter}
            accent="255 61 18" Icon={Crosshair} name="Advanced" tag="8 layers · full red team"
            points={["All 8 layers, configurable", "Sandboxed recon terminal", "STIX 2.1 + PDF export"]} ideal="Red teamers, researchers" />
        </div>
      </Section>

      {/* ── CTA ── */}
      <section className="relative px-6 md:px-10 py-32 text-center border-t border-line/10">
        <Reveal>
          <h2 className="font-serif-display text-5xl md:text-8xl leading-[1.02] mb-10">
            Reason about your<br /><span className="serif-italic">attack surface.</span>
          </h2>
          <button onClick={onEnter}
            className="group inline-flex items-center gap-2 px-10 py-5 rounded-full bg-accent text-[rgb(var(--accent-contrast))] text-lg font-semibold hover:opacity-90 transition-all">
            Launch ARGUS <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
          </button>
          <p className="text-text-muted text-sm mt-8 font-mono">Only test targets you own or are authorized to assess.</p>
        </Reveal>
      </section>

      {/* ── FOOTER ── */}
      <footer className="border-t border-line/10 px-6 md:px-10 py-10">
        <div className="max-w-[1600px] mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
          <span className="font-black tracking-tight text-xl">ARGUS</span>
          <p className="text-text-muted text-xs font-mono text-center">Adversarial Reasoning &amp; Graph-based Unified Security · For authorized testing only</p>
        </div>
      </footer>
    </div>
  );
}

function Section({ children, id }: { children: React.ReactNode; id?: string }) {
  return <section id={id} className="relative px-6 md:px-10 py-24 md:py-32 max-w-[1600px] mx-auto">{children}</section>;
}

function ModeCard({ onHover, onLeave, onClick, accent, Icon, name, tag, points, ideal }: {
  onHover: () => void; onLeave: () => void; onClick: () => void; accent: string;
  Icon: typeof GraduationCap; name: string; tag: string; points: string[]; ideal: string;
}) {
  return (
    <motion.button initial={{ opacity: 0, y: 24 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }}
      onMouseEnter={onHover} onMouseLeave={onLeave} onClick={onClick}
      className="group text-left p-8 rounded-3xl border transition-all duration-500"
      style={{ borderColor: `rgb(${accent} / 0.3)`, background: `rgb(${accent} / 0.05)` }}>
      <div className="flex items-center justify-between mb-8">
        <div className="w-12 h-12 rounded-2xl flex items-center justify-center" style={{ background: `rgb(${accent} / 0.14)`, border: `1px solid rgb(${accent} / 0.3)` }}>
          <Icon className="w-6 h-6" style={{ color: `rgb(${accent})` }} />
        </div>
        <ArrowRight className="w-6 h-6 group-hover:translate-x-1 transition-transform" style={{ color: `rgb(${accent})` }} />
      </div>
      <h3 className="font-serif-display text-4xl mb-1">{name}</h3>
      <p className="font-mono text-sm mb-6" style={{ color: `rgb(${accent})` }}>{tag}</p>
      <ul className="space-y-2.5 mb-6">
        {points.map((p) => (<li key={p} className="flex items-center gap-2.5 text-text-secondary"><Check className="w-4 h-4 shrink-0" style={{ color: `rgb(${accent})` }} /> {p}</li>))}
      </ul>
      <p className="text-xs font-mono text-text-muted">Ideal for: {ideal}</p>
    </motion.button>
  );
}
