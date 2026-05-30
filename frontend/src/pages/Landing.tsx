import { useRef, useState, type CSSProperties } from "react";
import { motion, useScroll, useTransform } from "framer-motion";
import {
  Eye, Globe, Bot, Database, Wrench, Radar, Package, Users, KeyRound,
  ArrowRight, ArrowUpRight, Check, GraduationCap, Crosshair, Network, ShieldAlert,
} from "lucide-react";

// Analogous spectrum: indigo/blue (Basic) → violet → magenta (Advanced).
const ACCENTS = {
  neutral:  { a: "124 58 237",  s: "217 70 239", g: "124 58 237" },
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

// Salo-style "services" — four capability cards.
const SERVICES = [
  { Icon: Network, title: "Cross-layer reasoning", body: "Correlates findings across eight domains into emergent kill-chains no single scanner can detect.", tag: "Engine" },
  { Icon: ShieldAlert, title: "Attack-chain modeling", body: "Models how a web injection feeds an LLM that poisons a RAG corpus that hijacks an agent.", tag: "Graph" },
  { Icon: Bot, title: "AI-native coverage", body: "Purpose-built for LLM, RAG, MCP/agentic and multi-agent threats — not bolted onto a web scanner.", tag: "AI/LLM" },
  { Icon: Crosshair, title: "Authorized recon", body: "A sandboxed, whitelisted terminal to validate findings live — exploit and destructive flags blocked.", tag: "Terminal" },
];

const STEPS = [
  { n: "01", title: "Define the target", desc: "A URL, an LLM endpoint, or a plain-text description. No agents to install." },
  { n: "02", title: "Scan every layer",  desc: "Up to 8 attack layers run in parallel across web, AI, and infrastructure." },
  { n: "03", title: "Reason across them", desc: "Findings are correlated into emergent kill-chains no single tool can see." },
  { n: "04", title: "Get the report",    desc: "Prioritized chains, remediations, and HTML / PDF / STIX 2.1 exports." },
];

const STATS = [
  { v: "8", l: "Attack layers" },
  { v: "24+", l: "OWASP / MITRE IDs" },
  { v: "3", l: "Security domains unified" },
  { v: "0", l: "Agents to install" },
];

// ── Motion helpers ───────────────────────────────────────────────────────────
function Words({ text, className }: { text: string; className?: string }) {
  return (
    <span className={className}>
      {text.split(" ").map((w, i) => (
        <span key={i} className="inline-block overflow-hidden align-bottom">
          <motion.span className="inline-block" initial={{ y: "110%" }} animate={{ y: 0 }}
            transition={{ delay: 0.15 + i * 0.07, duration: 0.7, ease: [0.16, 1, 0.3, 1] }}>
            {w}&nbsp;
          </motion.span>
        </span>
      ))}
    </span>
  );
}

function Reveal({ children, delay = 0, className }: { children: React.ReactNode; delay?: number; className?: string }) {
  return (
    <motion.div className={className} initial={{ opacity: 0, y: 40 }} whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-80px" }} transition={{ duration: 0.7, delay, ease: [0.16, 1, 0.3, 1] }}>
      {children}
    </motion.div>
  );
}

interface Props { onEnter: () => void }

export function Landing({ onEnter }: Props) {
  const [mode, setMode] = useState<keyof typeof ACCENTS>("neutral");
  const acc = ACCENTS[mode];
  const rootStyle = { "--accent": acc.a, "--accent-strong": acc.s, "--glow": acc.g } as CSSProperties;

  const ref = useRef<HTMLDivElement>(null);
  const { scrollYProgress } = useScroll({ target: ref, offset: ["start start", "end start"] });
  const gA = useTransform(scrollYProgress, [0, 1], [0, 240]);
  const gB = useTransform(scrollYProgress, [0, 1], [0, -180]);
  const gFade = useTransform(scrollYProgress, [0, 1], [1, 0.1]);

  return (
    <div ref={ref} className="accent-reactive relative min-h-screen bg-bg text-text-primary overflow-x-hidden" style={rootStyle}>
      {/* ── Aurora background: blue → violet → magenta ── */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden">
        <motion.div style={{ y: gA, opacity: gFade }} className="aurora absolute -top-48 -left-40 w-[760px] h-[760px] rounded-full"
          children={<div className="w-full h-full rounded-full transition-opacity duration-700"
            style={{ background: "radial-gradient(circle, rgba(79,70,229,0.22) 0%, transparent 70%)", opacity: mode === "advanced" ? 0.35 : 1 }} />} />
        <motion.div style={{ y: gB, opacity: gFade }} className="aurora absolute top-0 -right-40 w-[800px] h-[800px] rounded-full"
          children={<div className="w-full h-full rounded-full transition-opacity duration-700"
            style={{ background: "radial-gradient(circle, rgba(217,70,239,0.20) 0%, transparent 70%)", opacity: mode === "basic" ? 0.35 : 1 }} />} />
        <motion.div style={{ opacity: gFade }} className="aurora absolute top-[28%] left-1/3 w-[620px] h-[620px] rounded-full"
          children={<div className="w-full h-full rounded-full" style={{ background: "radial-gradient(circle, rgba(124,58,237,0.16) 0%, transparent 70%)" }} />} />
        <div className="absolute inset-0 grid-bg opacity-40" />
      </div>

      {/* ── NAV ── */}
      <nav className="sticky top-0 z-30 flex items-center justify-between px-6 md:px-10 py-5 border-b border-line/10 bg-bg/70 backdrop-blur-xl">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg border border-accent/40 flex items-center justify-center bg-accent/10">
            <Eye className="w-4 h-4 text-accent" strokeWidth={2.2} />
          </div>
          <span className="font-mono font-bold tracking-[0.22em] text-sm">ARGUS</span>
        </div>
        <div className="hidden md:flex items-center gap-8 text-sm text-text-secondary">
          <a href="#capabilities" className="hover:text-text-primary transition-colors">Capabilities</a>
          <a href="#layers" className="hover:text-text-primary transition-colors">Layers</a>
          <a href="#process" className="hover:text-text-primary transition-colors">Process</a>
          <a href="#modes" className="hover:text-text-primary transition-colors">Modes</a>
        </div>
        <button onClick={onEnter}
          className="group flex items-center gap-1.5 px-4 py-2 rounded-full bg-accent text-[rgb(var(--accent-contrast))] text-sm font-medium hover:opacity-90 transition-all">
          Launch <ArrowUpRight className="w-4 h-4 group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
        </button>
      </nav>

      {/* ── HERO ── */}
      <header className="relative z-10 px-6 md:px-10 pt-24 md:pt-32 pb-16 max-w-[1500px] mx-auto">
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }}
          className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full border border-accent/30 bg-accent/5 text-accent text-xs font-mono mb-10">
          <span className="w-1.5 h-1.5 rounded-full bg-accent animate-pulse" />
          AI Red-Team Reasoning · 8 Cross-Domain Layers
        </motion.div>

        <h1 className="display-tight text-balance font-black text-[14vw] md:text-[9.5rem] leading-[0.86]">
          <Words text="SEES EVERY" />
          <br />
          <span className="gradient-spectrum"><Words text="ATTACK CHAIN" /></span>
        </h1>

        <div className="mt-12 grid md:grid-cols-[1.25fr_1fr] gap-10 items-end">
          <motion.p initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.5 }}
            className="text-text-secondary text-xl md:text-2xl leading-snug max-w-2xl text-balance">
            Security reasoning that feels unified, not bolted together. ARGUS models how a{" "}
            <span className="text-text-primary">web injection</span> feeds an <span className="text-text-primary">LLM</span> that
            poisons a <span className="text-text-primary">RAG corpus</span> that hijacks an{" "}
            <span className="text-text-primary">agent</span> — across eight layers as one campaign.
          </motion.p>
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.6 }}
            className="flex flex-col sm:flex-row md:flex-col gap-3">
            <button onClick={onEnter}
              className="group flex items-center justify-between gap-3 px-6 py-4 rounded-2xl bg-accent text-[rgb(var(--accent-contrast))] font-medium hover:opacity-90 transition-all">
              Start Analysis <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
            </button>
            <button onClick={onEnter}
              className="group flex items-center justify-between gap-3 px-6 py-4 rounded-2xl border border-line/20 hover:border-accent/40 text-text-secondary hover:text-text-primary font-medium transition-all">
              Advanced Mode <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
            </button>
          </motion.div>
        </div>
      </header>

      {/* ── MARQUEE (8 layers) ── */}
      <section className="relative z-10 py-10 border-y border-line/10 bg-surface/40">
        <p className="text-center text-text-muted text-xs font-mono uppercase tracking-[0.25em] mb-6">Eight layers · one coordinated campaign</p>
        <div className="marquee-mask overflow-hidden">
          <div className="marquee-track gap-4">
            {[...LAYERS, ...LAYERS].map((l, i) => (
              <div key={i} className="flex items-center gap-3 px-6 py-3 rounded-xl border border-line/15 bg-surface shrink-0">
                <div className="w-9 h-9 rounded-lg bg-accent/10 border border-accent/20 flex items-center justify-center">
                  <l.Icon className="w-5 h-5 text-accent" />
                </div>
                <div>
                  <p className="text-sm font-semibold whitespace-nowrap">L{l.id} · {l.label}</p>
                  <p className="text-[11px] font-mono text-text-muted whitespace-nowrap">{l.std}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── CAPABILITIES (Salo "services" grid) ── */}
      <Section id="capabilities">
        <Reveal>
          <Eyebrow>What ARGUS does</Eyebrow>
          <h2 className="mt-5 text-4xl md:text-6xl font-bold max-w-3xl text-balance display-tight">
            Reasoning that feels in-house, not stitched from four tools.
          </h2>
        </Reveal>
        <div className="mt-14 grid md:grid-cols-2 gap-5">
          {SERVICES.map((s, i) => (
            <Reveal key={s.title} delay={i * 0.08}>
              <article className="group h-full p-8 rounded-3xl border border-line/15 bg-surface/60 hover:bg-surface transition-colors">
                <div className="flex items-start justify-between mb-10">
                  <div className="w-12 h-12 rounded-2xl bg-accent/10 border border-accent/25 flex items-center justify-center">
                    <s.Icon className="w-6 h-6 text-accent" />
                  </div>
                  <span className="text-xs font-mono uppercase tracking-widest text-text-muted">{s.tag}</span>
                </div>
                <h3 className="text-2xl md:text-3xl font-semibold mb-3 group-hover:text-accent transition-colors">{s.title}</h3>
                <p className="text-text-secondary leading-relaxed md:text-lg max-w-md">{s.body}</p>
              </article>
            </Reveal>
          ))}
        </div>
      </Section>

      {/* ── SHOWCASE (the gap statement) ── */}
      <Section>
        <Reveal>
          <h2 className="display-tight text-balance text-3xl md:text-6xl font-bold max-w-5xl leading-[1.05]">
            Burp sees the web. Garak sees the model. Nessus sees the network.{" "}
            <span className="gradient-spectrum">ARGUS sees the chain between them.</span>
          </h2>
        </Reveal>
        <div className="mt-14 grid md:grid-cols-3 gap-5">
          {LAYERS.slice(0, 3).map((l, i) => (
            <Reveal key={l.id} delay={i * 0.08}>
              <div className="rounded-3xl border border-line/15 bg-surface/60 p-7 h-full">
                <div className="w-11 h-11 rounded-2xl bg-accent/10 border border-accent/25 flex items-center justify-center mb-6">
                  <l.Icon className="w-5 h-5 text-accent" />
                </div>
                <p className="font-mono text-xs text-accent mb-1">L{l.id}</p>
                <p className="text-xl font-semibold mb-2">{l.label}</p>
                <p className="text-text-muted text-sm font-mono">{l.std}</p>
              </div>
            </Reveal>
          ))}
        </div>
      </Section>

      {/* ── STATS ── */}
      <section className="relative z-10 px-6 md:px-10 py-16 border-y border-line/10 bg-surface/30">
        <div className="max-w-[1500px] mx-auto grid grid-cols-2 md:grid-cols-4 gap-8">
          {STATS.map((s, i) => (
            <Reveal key={s.l} delay={i * 0.06} className="text-center">
              <p className="text-5xl md:text-7xl font-black gradient-spectrum display-tight">{s.v}</p>
              <p className="text-text-muted text-sm mt-2">{s.l}</p>
            </Reveal>
          ))}
        </div>
      </section>

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

      {/* ── MODES (interactive, mode-reactive) ── */}
      <Section id="modes">
        <Reveal><Eyebrow>Choose your depth</Eyebrow></Reveal>
        <div className="mt-10 grid md:grid-cols-2 gap-5">
          <ModeCard onHover={() => setMode("basic")} onLeave={() => setMode("neutral")} onClick={onEnter}
            accent="79 70 229" Icon={GraduationCap} name="Basic" tag="3 layers · quick assessment"
            points={["Web surface · LLM probe · RAG poisoning", "Top chains + one-page report", "No configuration required"]}
            ideal="Students, quick assessments" />
          <ModeCard onHover={() => setMode("advanced")} onLeave={() => setMode("neutral")} onClick={onEnter}
            accent="168 85 247" Icon={Crosshair} name="Advanced" tag="8 layers · full red team"
            points={["All 8 layers, configurable", "Sandboxed recon terminal", "STIX 2.1 + PDF export"]}
            ideal="Red teamers, researchers" />
        </div>
      </Section>

      {/* ── CTA ── */}
      <section className="relative z-10 px-6 md:px-10 py-28 text-center">
        <Reveal>
          <h2 className="display-tight text-balance text-5xl md:text-8xl font-black mb-8">
            Reason about<br /><span className="gradient-spectrum">your attack surface.</span>
          </h2>
          <p className="text-text-secondary mb-10">Only test targets you own or are authorized to assess.</p>
          <button onClick={onEnter}
            className="group inline-flex items-center gap-2 px-10 py-5 rounded-2xl bg-accent text-[rgb(var(--accent-contrast))] text-lg font-semibold hover:opacity-90 transition-all">
            Launch ARGUS <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
          </button>
        </Reveal>
      </section>

      {/* ── FOOTER ── */}
      <footer className="relative z-10 border-t border-line/10 px-6 md:px-10 py-10">
        <div className="max-w-[1500px] mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-lg border border-accent/40 flex items-center justify-center bg-accent/10">
              <Eye className="w-4 h-4 text-accent" />
            </div>
            <span className="font-mono font-bold tracking-[0.22em] text-sm">ARGUS</span>
          </div>
          <p className="text-text-muted text-xs font-mono text-center">Adversarial Reasoning &amp; Graph-based Unified Security · For authorized testing only</p>
        </div>
      </footer>
    </div>
  );
}

// ── Layout helpers ───────────────────────────────────────────────────────────
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
      style={{ borderColor: `rgb(${accent} / 0.3)`, background: `rgb(${accent} / 0.05)` }}>
      <div className="flex items-center justify-between mb-8">
        <div className="w-12 h-12 rounded-2xl flex items-center justify-center"
          style={{ background: `rgb(${accent} / 0.14)`, border: `1px solid rgb(${accent} / 0.3)` }}>
          <Icon className="w-6 h-6" style={{ color: `rgb(${accent})` }} />
        </div>
        <ArrowUpRight className="w-6 h-6 text-text-muted group-hover:translate-x-1 group-hover:-translate-y-1 transition-all"
          style={{ color: `rgb(${accent})` }} />
      </div>
      <h3 className="text-3xl font-bold mb-1">{name}</h3>
      <p className="font-mono text-sm mb-6" style={{ color: `rgb(${accent})` }}>{tag}</p>
      <ul className="space-y-2.5 mb-6">
        {points.map((p) => (
          <li key={p} className="flex items-center gap-2.5 text-text-secondary">
            <Check className="w-4 h-4 shrink-0" style={{ color: `rgb(${accent})` }} /> {p}
          </li>
        ))}
      </ul>
      <p className="text-xs font-mono text-text-muted">Ideal for: {ideal}</p>
    </motion.button>
  );
}
