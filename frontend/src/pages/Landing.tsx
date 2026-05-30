import { useRef, useState, type CSSProperties } from "react";
import { motion, useScroll, useTransform } from "framer-motion";
import {
  Eye, Globe, Bot, Database, Wrench, Radar, Package, Users, KeyRound,
  ArrowRight, ArrowUpRight, Check, X, ChevronDown, GraduationCap, Crosshair,
} from "lucide-react";

// Accent palettes (RGB channels) — drive the mode-reactive theme.
// Analogous spectrum: indigo/blue (Basic) → violet/magenta (Advanced).
const ACCENTS = {
  neutral:  { a: "124 58 237",  s: "217 70 239", g: "124 58 237" },  // violet
  basic:    { a: "79 70 229",   s: "37 99 235",  g: "79 70 229"  },  // indigo→blue
  advanced: { a: "168 85 247",  s: "217 70 239", g: "168 85 247" },  // violet→magenta
};

// Staggered word-by-word headline reveal (cinematic).
function Words({ text, className }: { text: string; className?: string }) {
  return (
    <span className={className}>
      {text.split(" ").map((w, i) => (
        <span key={i} className="inline-block overflow-hidden align-bottom">
          <motion.span
            className="inline-block"
            initial={{ y: "110%" }}
            animate={{ y: 0 }}
            transition={{ delay: 0.15 + i * 0.08, duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
          >
            {w}&nbsp;
          </motion.span>
        </span>
      ))}
    </span>
  );
}

// Scroll-reveal wrapper.
function Reveal({ children, delay = 0, className }: { children: React.ReactNode; delay?: number; className?: string }) {
  return (
    <motion.div
      className={className}
      initial={{ opacity: 0, y: 40 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-80px" }}
      transition={{ duration: 0.7, delay, ease: [0.16, 1, 0.3, 1] }}
    >
      {children}
    </motion.div>
  );
}

const LAYERS = [
  { id: 1, Icon: Globe,    label: "Web Surface",       std: "OWASP Web Top 10" },
  { id: 2, Icon: Bot,      label: "LLM Probe",         std: "OWASP LLM01/07:2025" },
  { id: 3, Icon: Database, label: "RAG Poisoning",     std: "OWASP LLM08:2025" },
  { id: 4, Icon: Wrench,   label: "MCP / Agentic",     std: "Agentic Top 10" },
  { id: 5, Icon: Radar,    label: "Network Recon",     std: "MITRE T1046" },
  { id: 6, Icon: Package,  label: "Supply Chain",      std: "OWASP A06:2021" },
  { id: 7, Icon: Users,    label: "Multi-Agent",       std: "MASpi" },
  { id: 8, Icon: KeyRound, label: "Identity / OAuth",  std: "MITRE ATLAS" },
];

const STEPS = [
  { n: "01", title: "Define the target", desc: "A URL, an LLM endpoint, or a plain-text description. No agents to install." },
  { n: "02", title: "Scan every layer",  desc: "Up to 8 attack layers run in parallel across web, AI, and infrastructure." },
  { n: "03", title: "Reason across them", desc: "Findings are correlated into emergent kill-chains no single tool can see." },
  { n: "04", title: "Get the report",    desc: "Prioritized chains, remediations, and HTML / PDF / STIX 2.1 exports." },
];

const COMPARE = [
  { tool: "Burp / ZAP", web: true, llm: false, net: false, chain: false },
  { tool: "Garak / PyRIT", web: false, llm: true, net: false, chain: false },
  { tool: "Nessus / Metasploit", web: false, llm: false, net: true, chain: false },
  { tool: "ARGUS", web: true, llm: true, net: true, chain: true, me: true },
];

const FAQS = [
  { q: "How is this different from Burp, Garak, or Nessus?", a: "Those each scan one domain in isolation. ARGUS runs all eight layers and reasons about how a finding in one enables an attack in the next — surfacing cross-layer kill-chains siloed scanners structurally cannot detect." },
  { q: "Do I need to install anything on the target?", a: "No. ARGUS works from a URL, an LLM endpoint, or a plain-text description of a hypothetical system." },
  { q: "Is it safe to run?", a: "ARGUS is for authorized testing only. The built-in terminal is restricted to read-only recon with exploit and destructive flags blocked." },
  { q: "What can I export?", a: "Any analysis exports to an HTML report, a PDF, or STIX 2.1 structured threat intelligence." },
];

interface Props { onEnter: () => void }

export function Landing({ onEnter }: Props) {
  const [mode, setMode] = useState<keyof typeof ACCENTS>("neutral");
  const [openFaq, setOpenFaq] = useState<number | null>(0);
  const acc = ACCENTS[mode];

  const rootStyle = {
    "--accent": acc.a, "--accent-strong": acc.s, "--glow": acc.g,
  } as CSSProperties;

  // Cinematic parallax: glows drift and fade as you scroll the hero.
  const ref = useRef<HTMLDivElement>(null);
  const { scrollYProgress } = useScroll({ target: ref, offset: ["start start", "end start"] });
  const glowY = useTransform(scrollYProgress, [0, 1], [0, 220]);
  const glowY2 = useTransform(scrollYProgress, [0, 1], [0, -160]);
  const glowFade = useTransform(scrollYProgress, [0, 1], [1, 0.15]);

  const Yes = () => <Check className="w-4 h-4 text-accent mx-auto" />;
  const No = () => <X className="w-4 h-4 text-text-muted/40 mx-auto" />;

  return (
    <div ref={ref} className="accent-reactive relative min-h-screen bg-bg text-text-primary overflow-x-hidden" style={rootStyle}>
      {/* Ambient aurora: blue → violet → magenta */}
      <div className="fixed inset-0 pointer-events-none">
        <motion.div style={{ y: glowY, opacity: glowFade }}
          className="aurora absolute -top-40 -left-40 w-[720px] h-[720px] rounded-full"
          /* indigo-blue, dimmed when Advanced is hovered */
        >
          <div className="w-full h-full rounded-full transition-opacity duration-700"
            style={{ background: "radial-gradient(circle, rgba(79,70,229,0.18) 0%, transparent 70%)", opacity: mode === "advanced" ? 0.3 : 1 }} />
        </motion.div>
        <motion.div style={{ y: glowY2, opacity: glowFade }}
          className="aurora absolute top-10 -right-40 w-[760px] h-[760px] rounded-full">
          <div className="w-full h-full rounded-full transition-opacity duration-700"
            style={{ background: "radial-gradient(circle, rgba(217,70,239,0.18) 0%, transparent 70%)", opacity: mode === "basic" ? 0.3 : 1 }} />
        </motion.div>
        <motion.div style={{ opacity: glowFade }}
          className="aurora absolute top-1/3 left-1/3 w-[560px] h-[560px] rounded-full"
          /* violet centre tie */ >
          <div className="w-full h-full rounded-full"
            style={{ background: "radial-gradient(circle, rgba(124,58,237,0.12) 0%, transparent 70%)" }} />
        </motion.div>
        <div className="absolute inset-0 grid-bg opacity-40" />
      </div>

      {/* ── NAV ─────────────────────────────────────────── */}
      <nav className="sticky top-0 z-30 flex items-center justify-between px-6 md:px-12 py-5 border-b border-line/10 bg-bg/70 backdrop-blur-xl">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg border border-accent/40 flex items-center justify-center bg-accent/10">
            <Eye className="w-4 h-4 text-accent" strokeWidth={2.2} />
          </div>
          <span className="font-mono font-bold tracking-[0.2em] text-sm">ARGUS</span>
        </div>
        <div className="hidden md:flex items-center gap-8 text-sm text-text-secondary">
          <a href="#approach" className="hover:text-text-primary transition-colors">Approach</a>
          <a href="#layers" className="hover:text-text-primary transition-colors">Layers</a>
          <a href="#compare" className="hover:text-text-primary transition-colors">Compare</a>
        </div>
        <button onClick={onEnter}
          className="group flex items-center gap-1.5 px-4 py-2 rounded-full bg-accent text-[rgb(var(--accent-contrast))] text-sm font-medium hover:opacity-90 transition-all">
          Launch <ArrowUpRight className="w-4 h-4 group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
        </button>
      </nav>

      {/* ── HERO ────────────────────────────────────────── */}
      <section className="relative z-10 px-6 md:px-12 pt-24 md:pt-36 pb-20 max-w-[1400px] mx-auto">
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }}
          className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full border border-accent/30 bg-accent/5 text-accent text-xs font-mono mb-10">
          <span className="w-1.5 h-1.5 rounded-full bg-accent animate-pulse" />
          AI Red-Team Reasoning · 8 Cross-Domain Layers
        </motion.div>

        <h1 className="display-tight text-balance font-black text-[15vw] md:text-[10.5rem] leading-[0.86]">
          <Words text="SEES EVERY" />
          <br />
          <span className="gradient-spectrum"><Words text="ATTACK CHAIN" /></span>
        </h1>

        <div className="mt-12 grid md:grid-cols-[1.3fr_1fr] gap-10 items-end">
          <motion.p initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.25 }}
            className="text-text-secondary text-xl md:text-2xl leading-snug max-w-2xl text-balance">
            The only framework that models how a <span className="text-text-primary">web injection</span> feeds an{" "}
            <span className="text-text-primary">LLM</span> that poisons a <span className="text-text-primary">RAG corpus</span> that
            hijacks an <span className="text-text-primary">agent</span> — reasoning across eight layers as one campaign.
          </motion.p>
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.35 }}
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
      </section>

      {/* ── 8-LAYER MARQUEE ─────────────────────────────── */}
      <section className="relative z-10 py-10 border-y border-line/10 bg-surface/30">
        <p className="text-center text-text-muted text-xs font-mono uppercase tracking-[0.25em] mb-6">Eight layers · one coordinated campaign</p>
        <div className="marquee-mask overflow-hidden">
          <div className="marquee-track gap-4">
            {[...LAYERS, ...LAYERS].map((l, i) => (
              <div key={i} className="flex items-center gap-3 px-6 py-3 rounded-xl border border-line/15 bg-surface/50 shrink-0">
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

      {/* ── BIG STATEMENT ───────────────────────────────── */}
      <Section>
        <motion.h2 initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }}
          className="display-tight text-balance text-3xl md:text-6xl font-bold max-w-5xl leading-[1.05]">
          Real breaches don't respect tool boundaries.{" "}
          <span className="text-text-muted">Burp sees the web. Garak sees the model. Nessus sees the network.</span>{" "}
          <span className="text-accent">ARGUS sees the chain between them.</span>
        </motion.h2>
      </Section>

      {/* ── APPROACH / HOW IT WORKS ─────────────────────── */}
      <Section id="approach">
        <Eyebrow>The approach</Eyebrow>
        <div className="mt-10 divide-y divide-line/10 border-t border-line/10">
          {STEPS.map((s, i) => (
            <motion.div key={s.n} initial={{ opacity: 0, y: 16 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }}
              transition={{ delay: i * 0.05 }}
              className="grid md:grid-cols-[auto_1fr_2fr] gap-4 md:gap-10 items-baseline py-8 group">
              <span className="font-mono text-accent text-lg">{s.n}</span>
              <h3 className="text-2xl md:text-3xl font-semibold group-hover:text-accent transition-colors">{s.title}</h3>
              <p className="text-text-secondary md:text-lg leading-relaxed">{s.desc}</p>
            </motion.div>
          ))}
        </div>
      </Section>

      {/* ── INTERACTIVE MODE SELECTOR ───────────────────── */}
      <Section id="layers">
        <Eyebrow>Choose your depth</Eyebrow>
        <div className="mt-10 grid md:grid-cols-2 gap-4">
          <ModeCard
            onHover={() => setMode("basic")} onLeave={() => setMode("neutral")} onClick={onEnter}
            accent="14 165 233" Icon={GraduationCap} name="Basic" tag="3 layers · quick assessment"
            points={["Web surface · LLM probe · RAG poisoning", "Top chains + one-page report", "No configuration required"]}
            ideal="Students, quick assessments" />
          <ModeCard
            onHover={() => setMode("advanced")} onLeave={() => setMode("neutral")} onClick={onEnter}
            accent="255 61 87" Icon={Crosshair} name="Advanced" tag="8 layers · full red team"
            points={["All 8 layers, configurable", "Sandboxed recon terminal", "STIX 2.1 + PDF export"]}
            ideal="Red teamers, researchers" />
        </div>
      </Section>

      {/* ── COMPARE ─────────────────────────────────────── */}
      <Section id="compare">
        <Eyebrow>The gap</Eyebrow>
        <h2 className="mt-6 text-3xl md:text-5xl font-bold max-w-3xl text-balance">Why siloed tools miss the real risk.</h2>
        <div className="mt-10 max-w-3xl border border-line/15 rounded-2xl overflow-hidden bg-surface/40">
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
                  <td className="px-3 py-4 text-center">{r.web ? <Yes /> : <No />}</td>
                  <td className="px-3 py-4 text-center">{r.llm ? <Yes /> : <No />}</td>
                  <td className="px-3 py-4 text-center">{r.net ? <Yes /> : <No />}</td>
                  <td className="px-3 py-4 text-center">{r.chain ? <Yes /> : <No />}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>

      {/* ── FAQ ─────────────────────────────────────────── */}
      <Section>
        <Eyebrow>Questions</Eyebrow>
        <div className="mt-10 max-w-3xl divide-y divide-line/10 border-y border-line/10">
          {FAQS.map((f, i) => (
            <div key={i}>
              <button onClick={() => setOpenFaq(openFaq === i ? null : i)}
                className="w-full flex items-center justify-between gap-4 py-5 text-left">
                <span className="text-lg md:text-xl font-medium">{f.q}</span>
                <ChevronDown className={`w-5 h-5 text-accent shrink-0 transition-transform ${openFaq === i ? "rotate-180" : ""}`} />
              </button>
              {openFaq === i && (
                <motion.p initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }}
                  className="pb-5 text-text-secondary leading-relaxed max-w-2xl">{f.a}</motion.p>
              )}
            </div>
          ))}
        </div>
      </Section>

      {/* ── CTA ─────────────────────────────────────────── */}
      <section className="relative z-10 px-6 md:px-12 py-28 text-center">
        <motion.h2 initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }}
          className="display-tight text-balance text-5xl md:text-8xl font-black mb-8">Reason about<br />your attack surface.</motion.h2>
        <p className="text-text-secondary mb-10">Only test targets you own or are authorized to assess.</p>
        <button onClick={onEnter}
          className="group inline-flex items-center gap-2 px-10 py-5 rounded-2xl bg-accent text-[rgb(var(--accent-contrast))] text-lg font-semibold hover:opacity-90 transition-all">
          Launch ARGUS <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </button>
      </section>

      {/* ── FOOTER ──────────────────────────────────────── */}
      <footer className="relative z-10 border-t border-line/10 px-6 md:px-12 py-10">
        <div className="max-w-[1400px] mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-lg border border-accent/40 flex items-center justify-center bg-accent/10">
              <Eye className="w-4 h-4 text-accent" />
            </div>
            <span className="font-mono font-bold tracking-[0.2em] text-sm">ARGUS</span>
          </div>
          <p className="text-text-muted text-xs font-mono text-center">Adversarial Reasoning &amp; Graph-based Unified Security · For authorized testing only</p>
        </div>
      </footer>
    </div>
  );
}

// ── Helpers ──────────────────────────────────────────────────────────────────
function Section({ children, id }: { children: React.ReactNode; id?: string }) {
  return (
    <section id={id} className="relative z-10 px-6 md:px-12 py-20 md:py-28 max-w-[1400px] mx-auto">
      <Reveal>{children}</Reveal>
    </section>
  );
}

function Eyebrow({ children }: { children: React.ReactNode }) {
  return <p className="text-accent text-xs font-mono uppercase tracking-[0.25em]">{children}</p>;
}

function ModeCard({ onHover, onLeave, onClick, accent, Icon, name, tag, points, ideal }: {
  onHover: () => void; onLeave: () => void; onClick: () => void; accent: string;
  Icon: typeof GraduationCap; name: string; tag: string; points: string[]; ideal: string;
}) {
  return (
    <motion.button
      initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }}
      onMouseEnter={onHover} onMouseLeave={onLeave} onClick={onClick}
      className="group text-left p-8 rounded-3xl border transition-all duration-500"
      style={{ borderColor: `rgb(${accent} / 0.25)`, background: `rgb(${accent} / 0.04)` }}>
      <div className="flex items-center justify-between mb-8">
        <div className="w-12 h-12 rounded-2xl flex items-center justify-center" style={{ background: `rgb(${accent} / 0.12)`, border: `1px solid rgb(${accent} / 0.3)` }}>
          <Icon className="w-6 h-6" style={{ color: `rgb(${accent})` }} />
        </div>
        <ArrowUpRight className="w-6 h-6 text-text-muted group-hover:text-text-primary group-hover:translate-x-1 group-hover:-translate-y-1 transition-all" />
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
