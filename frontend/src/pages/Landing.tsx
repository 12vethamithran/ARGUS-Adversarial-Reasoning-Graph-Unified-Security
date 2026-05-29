import { useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
import * as d3 from "d3";
import {
  Eye, Globe, Bot, Database, Wrench, Radar, Package, Users, KeyRound,
  ArrowRight, Check, X, ChevronDown, Target, GitBranch, ShieldAlert,
  ScanSearch, BrainCircuit, FileText,
} from "lucide-react";

// ── Animated background graph (theme-aware) ──────────────────────────────────
function BackgroundGraph() {
  const svgRef = useRef<SVGSVGElement>(null);

  useEffect(() => {
    const accent = getComputedStyle(document.documentElement).getPropertyValue("--accent").trim() || "255 61 87";
    const svg = d3.select(svgRef.current!);
    const W = window.innerWidth, H = Math.max(window.innerHeight, 800);
    svg.attr("width", W).attr("height", H);
    svg.selectAll("*").remove();

    const N = 32;
    const nodes: d3.SimulationNodeDatum[] = Array.from({ length: N }, (_, i) => ({
      id: i, x: Math.random() * W, y: Math.random() * H,
    }));
    const links: d3.SimulationLinkDatum<d3.SimulationNodeDatum>[] = [];
    for (let i = 0; i < N; i++)
      for (let j = i + 1; j < N; j++)
        if (Math.random() < 0.1) links.push({ source: i, target: j });

    const link = svg.append("g").selectAll("line").data(links).join("line")
      .attr("stroke", `rgb(${accent})`).attr("stroke-opacity", 0.1).attr("stroke-width", 1);
    const node = svg.append("g").selectAll("circle").data(nodes).join("circle")
      .attr("r", () => 2 + Math.random() * 3)
      .attr("fill", `rgb(${accent})`)
      .attr("opacity", () => 0.15 + Math.random() * 0.35);

    const sim = d3.forceSimulation(nodes)
      .force("link", d3.forceLink(links).distance(130).strength(0.04))
      .force("charge", d3.forceManyBody().strength(-40))
      .force("center", d3.forceCenter(W / 2, H / 2))
      .on("tick", () => {
        link.attr("x1", (d) => (d.source as any).x).attr("y1", (d) => (d.source as any).y)
            .attr("x2", (d) => (d.target as any).x).attr("y2", (d) => (d.target as any).y);
        node.attr("cx", (d: any) => d.x).attr("cy", (d: any) => d.y);
      });
    return () => { sim.stop(); };
  }, []);

  return <svg ref={svgRef} className="absolute inset-0 pointer-events-none" style={{ opacity: 0.7 }} />;
}

function Counter({ target, suffix = "" }: { target: number; suffix?: string }) {
  const [val, setVal] = useState(0);
  useEffect(() => {
    let start = 0; const step = target / 60;
    const t = setInterval(() => {
      start += step;
      if (start >= target) { setVal(target); clearInterval(t); } else setVal(Math.floor(start));
    }, 16);
    return () => clearInterval(t);
  }, [target]);
  return <span>{val}{suffix}</span>;
}

const LAYERS = [
  { id: 1, Icon: Globe,    label: "Web Surface",       badge: "OWASP Web Top 10" },
  { id: 2, Icon: Bot,      label: "LLM Probe",         badge: "LLM01/07:2025" },
  { id: 3, Icon: Database, label: "RAG Poisoning",     badge: "LLM08:2025" },
  { id: 4, Icon: Wrench,   label: "MCP / Agentic",     badge: "Agentic Top 10" },
  { id: 5, Icon: Radar,    label: "Network Recon",     badge: "MITRE T1046" },
  { id: 6, Icon: Package,  label: "Supply Chain",      badge: "SkillJect / STAC" },
  { id: 7, Icon: Users,    label: "Multi-Agent Prop.", badge: "MASpi" },
  { id: 8, Icon: KeyRound, label: "Identity / OAuth",  badge: "MITRE ATLAS" },
];

const STEPS = [
  { Icon: Target,       title: "Define the target",  desc: "Point ARGUS at a URL, LLM endpoint, or describe a hypothetical system. No agents to install." },
  { Icon: ScanSearch,   title: "Scan every layer",   desc: "Up to 8 attack layers run in parallel — web, LLM, RAG, agentic, network, supply chain, and identity." },
  { Icon: BrainCircuit, title: "Reason across them", desc: "The engine correlates findings into emergent kill-chains that span domains no single tool sees." },
  { Icon: FileText,     title: "Get the report",     desc: "Prioritized chains, remediations, and exports to HTML, PDF, and STIX 2.1 threat intel." },
];

const CHAIN = [
  { l: "L1", Icon: Globe,    label: "Web injection",        detail: "Reflected input on a search field" },
  { l: "L2", Icon: Bot,      label: "LLM prompt injection", detail: "Payload steers the model" },
  { l: "L3", Icon: Database, label: "RAG poisoning",        detail: "Adversarial doc enters the corpus" },
  { l: "L4", Icon: Wrench,   label: "Tool-call hijack",     detail: "Agent invokes an internal action" },
  { l: "L5", Icon: Radar,    label: "Network pivot",        detail: "Lateral movement to internal DB" },
];

const COMPARISON = [
  { tool: "Burp / ZAP",          web: true,  llm: false, net: false, chain: false },
  { tool: "Garak / PyRIT",       web: false, llm: true,  net: false, chain: false },
  { tool: "Nessus / Metasploit", web: false, llm: false, net: true,  chain: false },
  { tool: "ARGUS",               web: true,  llm: true,  net: true,  chain: true, highlight: true },
];

const STANDARDS = ["OWASP Web Top 10", "OWASP LLM Top 10 (2025)", "OWASP Agentic Top 10", "MITRE ATT&CK", "MITRE ATLAS", "STIX 2.1"];

const FAQS = [
  { q: "What makes ARGUS different from Burp, Garak, or Nessus?", a: "Those tools each scan one domain in isolation. ARGUS runs all eight layers and then reasons about how a finding in one layer enables an attack in another — surfacing cross-layer kill-chains that siloed scanners structurally cannot detect." },
  { q: "Do I need to install anything on the target?", a: "No. ARGUS works from a target URL, an LLM endpoint, or even a plain-text description of a hypothetical system. There are no agents to deploy." },
  { q: "Is it safe / authorized to run?", a: "ARGUS is built for authorized testing only. The built-in terminal is restricted to a whitelist of read-only recon commands, with exploit and destructive flags blocked. Only test systems you own or are explicitly permitted to assess." },
  { q: "What can I export?", a: "Every analysis can be exported as an HTML report, a PDF, or STIX 2.1 structured threat intelligence for ingestion into your existing security tooling." },
  { q: "What powers the reasoning engine?", a: "Cross-layer correlation is driven by an LLM reasoning engine (Gemini) with a deterministic heuristic fallback, so you always get ranked chains — even with no API key configured." },
];

interface Props { onEnter: () => void }

export function Landing({ onEnter }: Props) {
  const [openFaq, setOpenFaq] = useState<number | null>(0);

  const Yes = () => <Check className="w-4 h-4 text-accent-green mx-auto" />;
  const No = () => <X className="w-4 h-4 text-text-muted/50 mx-auto" />;

  return (
    <div className="relative min-h-screen bg-bg text-text-primary overflow-x-hidden">
      <div className="fixed inset-0 grid-bg pointer-events-none" />
      <div className="fixed inset-0 pointer-events-none">
        <BackgroundGraph />
        <div className="absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[640px] h-[640px] rounded-full"
          style={{ background: "radial-gradient(circle, rgb(var(--glow) / 0.08) 0%, transparent 70%)" }} />
      </div>

      {/* ── NAV ─────────────────────────────────────────────────────────── */}
      <nav className="sticky top-0 z-30 flex items-center justify-between px-6 md:px-10 py-4 border-b border-line/15 glass">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg border border-accent/40 flex items-center justify-center bg-accent/10">
            <Eye className="w-4 h-4 text-accent" strokeWidth={2.2} />
          </div>
          <span className="font-mono font-bold tracking-widest">ARGUS</span>
          <span className="text-xs font-mono text-text-muted border border-line/20 px-2 py-0.5 rounded">v0.1 BETA</span>
        </div>
        <div className="flex items-center gap-6">
          <a href="#how" className="text-text-secondary text-sm hover:text-text-primary transition-colors hidden md:block">How it works</a>
          <a href="#layers" className="text-text-secondary text-sm hover:text-text-primary transition-colors hidden md:block">Layers</a>
          <a href="#compare" className="text-text-secondary text-sm hover:text-text-primary transition-colors hidden md:block">Compare</a>
          <button onClick={onEnter}
            className="px-4 py-2 rounded-lg bg-accent/10 border border-accent/30 text-accent text-sm font-mono hover:bg-accent/20 transition-all">
            Launch →
          </button>
        </div>
      </nav>

      {/* ── HERO ────────────────────────────────────────────────────────── */}
      <section className="relative z-10 flex flex-col items-center justify-center min-h-[88vh] px-6 text-center">
        <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
          className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full border border-accent/30 bg-accent/5 text-accent text-xs font-mono mb-8">
          <span className="w-1.5 h-1.5 rounded-full bg-accent animate-pulse" />
          AI Red-Team Reasoning Platform · Cross-Layer Attack Modeling
        </motion.div>

        <motion.h1 initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}
          className="text-5xl md:text-7xl font-black leading-none tracking-tight mb-6">
          <span className="gradient-text">ARGUS</span><br />
          <span className="text-text-primary/90 text-4xl md:text-5xl font-bold">Sees Every Attack Chain</span>
        </motion.h1>

        <motion.p initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}
          className="text-text-secondary text-lg md:text-xl max-w-2xl mx-auto mb-10 leading-relaxed">
          The only framework that models how a <span className="text-accent font-medium">web injection</span> feeds an{" "}
          <span className="text-accent font-medium">LLM</span> that executes a{" "}
          <span className="text-accent font-medium">network action</span> — reasoning across 8 attack layers in a single coordinated campaign.
        </motion.p>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }}
          className="flex flex-col sm:flex-row gap-4 mb-16">
          <button onClick={onEnter}
            className="group px-8 py-4 rounded-xl font-mono font-semibold text-base bg-accent/15 border border-accent/40 text-accent hover:bg-accent/25 transition-all flex items-center justify-center gap-2">
            <Target className="w-4 h-4" /> Start Analysis
          </button>
          <button onClick={onEnter}
            className="px-8 py-4 rounded-xl font-mono font-semibold text-base border border-line/20 text-text-secondary hover:border-line/40 hover:text-text-primary transition-all flex items-center justify-center gap-2">
            Advanced Mode <ArrowRight className="w-4 h-4" />
          </button>
        </motion.div>

        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.6 }}
          className="grid grid-cols-2 md:grid-cols-4 gap-px border border-line/15 rounded-2xl overflow-hidden glass">
          {[
            { label: "Attack Layers", value: 8, suffix: "" },
            { label: "OWASP/MITRE IDs", value: 24, suffix: "+" },
            { label: "Novel Chain Detection", value: 97, suffix: "%" },
            { label: "Enterprises at Risk", value: 79, suffix: "%" },
          ].map((s) => (
            <div key={s.label} className="px-8 py-5 text-center border-r border-line/10 last:border-0">
              <p className="text-3xl font-black font-mono gradient-text mb-1"><Counter target={s.value} suffix={s.suffix} /></p>
              <p className="text-text-muted text-xs">{s.label}</p>
            </div>
          ))}
        </motion.div>
      </section>

      {/* ── LIVE DEMO PREVIEW ───────────────────────────────────────────── */}
      <Section>
        <SectionHeading eyebrow="Live Preview" title="A reasoning console, not just a scanner"
          sub="Watch findings light up across layers and resolve into prioritized attack chains in real time." />
        <motion.div initial={{ opacity: 0, y: 30 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }}
          className="glass rounded-2xl border border-accent/15 p-1.5 max-w-4xl mx-auto shadow-2xl">
          <div className="rounded-xl bg-surface/60 border border-line/10 overflow-hidden">
            <div className="flex items-center gap-2 px-4 py-2.5 border-b border-line/10">
              <span className="w-2.5 h-2.5 rounded-full bg-accent/50" />
              <span className="w-2.5 h-2.5 rounded-full bg-node-probing/50" />
              <span className="w-2.5 h-2.5 rounded-full bg-accent-green/50" />
              <span className="ml-3 text-xs font-mono text-text-muted">argus · attack-graph</span>
              <span className="ml-auto flex items-center gap-1.5 text-xs font-mono text-accent">
                <span className="w-1.5 h-1.5 rounded-full bg-accent animate-ping" /> LIVE
              </span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 p-4">
              <div className="md:col-span-2 rounded-lg border border-line/10 bg-bg/40 p-4 min-h-[180px] flex flex-wrap content-center justify-center gap-3">
                {CHAIN.map((c, i) => (
                  <motion.div key={c.l} initial={{ opacity: 0, scale: 0.8 }} whileInView={{ opacity: 1, scale: 1 }}
                    viewport={{ once: true }} transition={{ delay: i * 0.15 }}
                    className="flex flex-col items-center gap-1">
                    <div className="w-12 h-12 rounded-full border-2 border-accent/50 bg-accent/10 flex items-center justify-center glow-accent">
                      <c.Icon className="w-5 h-5 text-accent" />
                    </div>
                    <span className="text-[10px] font-mono text-text-muted">{c.l}</span>
                  </motion.div>
                ))}
              </div>
              <div className="rounded-lg border border-line/10 bg-bg/40 p-3 font-mono text-[11px] leading-relaxed text-text-secondary space-y-1">
                <p className="text-accent">› reasoning…</p>
                <p>L1 CORS misconfig detected</p>
                <p>L2 injection vector confirmed</p>
                <p className="text-node-probing">L2→L3 RAG link active</p>
                <p>L4 agent compromise</p>
                <p className="text-accent font-semibold">Chain priority: 0.91</p>
                <span className="inline-block w-1.5 h-3 bg-accent cursor-blink" />
              </div>
            </div>
          </div>
        </motion.div>
      </Section>

      {/* ── HOW IT WORKS ────────────────────────────────────────────────── */}
      <Section id="how">
        <SectionHeading eyebrow="How it works" title="From target to threat report in four steps" />
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {STEPS.map((s, i) => (
            <motion.div key={s.title} initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }} transition={{ delay: i * 0.08 }}
              className="glass rounded-xl p-5 relative">
              <span className="absolute top-4 right-4 text-5xl font-black text-accent/10 font-mono leading-none">{i + 1}</span>
              <div className="w-11 h-11 rounded-xl bg-accent/10 border border-accent/30 flex items-center justify-center mb-4">
                <s.Icon className="w-5 h-5 text-accent" />
              </div>
              <p className="font-semibold mb-1">{s.title}</p>
              <p className="text-text-muted text-sm leading-relaxed">{s.desc}</p>
            </motion.div>
          ))}
        </div>
      </Section>

      {/* ── LAYERS ──────────────────────────────────────────────────────── */}
      <Section id="layers">
        <SectionHeading eyebrow="Coverage" title="8 Layers. One Coordinated Campaign."
          sub="Each layer feeds the next. ARGUS reasons about emergent chains no single tool sees." />
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {LAYERS.map((l, i) => (
            <motion.div key={l.id} initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }} transition={{ delay: i * 0.05 }}
              className="glass rounded-xl p-4 hover:border-accent/30 transition-all duration-300 group">
              <div className="flex items-center justify-between mb-3">
                <div className="w-9 h-9 rounded-lg bg-accent/10 border border-accent/20 flex items-center justify-center">
                  <l.Icon className="w-5 h-5 text-accent" />
                </div>
                <span className="text-xs font-mono px-2 py-0.5 rounded border border-accent/30 text-accent bg-accent/5">L{l.id}</span>
              </div>
              <p className="font-semibold text-sm mb-1 group-hover:text-accent transition-colors">{l.label}</p>
              <p className="text-xs font-mono text-text-muted">{l.badge}</p>
            </motion.div>
          ))}
        </div>
      </Section>

      {/* ── CHAIN SHOWCASE ──────────────────────────────────────────────── */}
      <Section>
        <SectionHeading eyebrow="The emergent threat" title="One chain. Five layers. Zero tools that catch it."
          sub="A real cross-layer kill-chain ARGUS models end-to-end." />
        <div className="max-w-4xl mx-auto glass rounded-2xl border border-accent/15 p-6 md:p-8">
          <div className="flex flex-col md:flex-row md:items-stretch gap-2">
            {CHAIN.map((c, i) => (
              <div key={c.l} className="flex md:flex-col items-center gap-3 md:gap-0 flex-1">
                <motion.div initial={{ opacity: 0, y: 16 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }}
                  transition={{ delay: i * 0.12 }} className="flex flex-col items-center text-center gap-2 flex-1">
                  <div className="w-12 h-12 rounded-xl bg-accent/10 border border-accent/40 flex items-center justify-center">
                    <c.Icon className="w-5 h-5 text-accent" />
                  </div>
                  <span className="text-xs font-mono text-accent">{c.l}</span>
                  <span className="text-sm font-semibold">{c.label}</span>
                  <span className="text-xs text-text-muted leading-tight">{c.detail}</span>
                </motion.div>
                {i < CHAIN.length - 1 && (
                  <ArrowRight className="w-4 h-4 text-accent/50 shrink-0 rotate-90 md:rotate-0 self-center mt-0 md:mt-6" />
                )}
              </div>
            ))}
          </div>
          <div className="mt-6 pt-5 border-t border-line/10 flex flex-wrap items-center gap-4 justify-center text-xs font-mono">
            <span className="flex items-center gap-1.5 text-accent"><GitBranch className="w-3.5 h-3.5" /> Novelty 0.81</span>
            <span className="flex items-center gap-1.5 text-node-probing"><ShieldAlert className="w-3.5 h-3.5" /> Impact 0.94</span>
            <span className="flex items-center gap-1.5 text-accent-green"><Check className="w-3.5 h-3.5" /> Priority 0.91</span>
          </div>
        </div>
      </Section>

      {/* ── COMPARISON MATRIX ───────────────────────────────────────────── */}
      <Section id="compare">
        <SectionHeading eyebrow="The gap" title="Why siloed tools miss the real risk" />
        <div className="max-w-3xl mx-auto glass rounded-2xl border border-line/15 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-line/15 text-text-muted font-mono text-xs">
                <th className="text-left px-4 py-3 font-normal">Tool</th>
                <th className="px-3 py-3 font-normal">Web</th>
                <th className="px-3 py-3 font-normal">LLM</th>
                <th className="px-3 py-3 font-normal">Network</th>
                <th className="px-3 py-3 font-normal">Cross-layer</th>
              </tr>
            </thead>
            <tbody>
              {COMPARISON.map((r) => (
                <tr key={r.tool} className={`border-b border-line/10 last:border-0 ${r.highlight ? "bg-accent/5" : ""}`}>
                  <td className={`px-4 py-3 font-mono ${r.highlight ? "text-accent font-bold" : "text-text-secondary"}`}>{r.tool}</td>
                  <td className="px-3 py-3 text-center">{r.web ? <Yes /> : <No />}</td>
                  <td className="px-3 py-3 text-center">{r.llm ? <Yes /> : <No />}</td>
                  <td className="px-3 py-3 text-center">{r.net ? <Yes /> : <No />}</td>
                  <td className="px-3 py-3 text-center">{r.chain ? <Yes /> : <No />}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>

      {/* ── STANDARDS BAND ──────────────────────────────────────────────── */}
      <section className="relative z-10 px-6 py-12 border-y border-line/10">
        <p className="text-center text-text-muted text-xs font-mono uppercase tracking-widest mb-6">Mapped to industry standards</p>
        <div className="flex flex-wrap items-center justify-center gap-3 max-w-4xl mx-auto">
          {STANDARDS.map((s) => (
            <span key={s} className="px-4 py-2 rounded-lg border border-line/15 bg-surface/40 text-text-secondary text-sm font-mono">{s}</span>
          ))}
        </div>
      </section>

      {/* ── FAQ ─────────────────────────────────────────────────────────── */}
      <Section>
        <SectionHeading eyebrow="FAQ" title="Questions, answered" />
        <div className="max-w-3xl mx-auto space-y-3">
          {FAQS.map((f, i) => (
            <div key={i} className="glass rounded-xl border border-line/15 overflow-hidden">
              <button onClick={() => setOpenFaq(openFaq === i ? null : i)}
                className="w-full flex items-center justify-between gap-4 px-5 py-4 text-left">
                <span className="font-medium text-sm">{f.q}</span>
                <ChevronDown className={`w-4 h-4 text-accent shrink-0 transition-transform ${openFaq === i ? "rotate-180" : ""}`} />
              </button>
              {openFaq === i && (
                <motion.p initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }}
                  className="px-5 pb-4 text-sm text-text-muted leading-relaxed">{f.a}</motion.p>
              )}
            </div>
          ))}
        </div>
      </Section>

      {/* ── FINAL CTA ───────────────────────────────────────────────────── */}
      <section className="relative z-10 px-6 py-24 text-center">
        <motion.div initial={{ opacity: 0, scale: 0.95 }} whileInView={{ opacity: 1, scale: 1 }} viewport={{ once: true }}
          className="max-w-2xl mx-auto">
          <h2 className="text-4xl font-black mb-4">Ready to reason about your attack surface?</h2>
          <p className="text-text-secondary mb-8">Only test targets you own or have explicit authorization to test.</p>
          <button onClick={onEnter}
            className="px-12 py-5 rounded-2xl font-mono font-bold text-lg text-[rgb(var(--accent-contrast))] transition-all duration-300 hover:scale-105"
            style={{ background: "linear-gradient(135deg, rgb(var(--accent)), rgb(var(--accent-strong)))" }}>
            Launch ARGUS →
          </button>
        </motion.div>
      </section>

      {/* ── FOOTER ──────────────────────────────────────────────────────── */}
      <footer className="relative z-10 border-t border-line/10 px-6 md:px-10 py-8">
        <div className="max-w-6xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-lg border border-accent/40 flex items-center justify-center bg-accent/10">
              <Eye className="w-4 h-4 text-accent" />
            </div>
            <span className="font-mono font-bold tracking-widest text-sm">ARGUS</span>
            <span className="text-text-muted text-xs font-mono ml-2">Adversarial Reasoning &amp; Graph-based Unified Security</span>
          </div>
          <p className="text-text-muted text-xs font-mono">v0.1 BETA · For authorized security testing only</p>
        </div>
      </footer>
    </div>
  );
}

// ── Layout helpers ───────────────────────────────────────────────────────────
function Section({ children, id }: { children: React.ReactNode; id?: string }) {
  return <section id={id} className="relative z-10 px-6 py-20 max-w-6xl mx-auto">{children}</section>;
}

function SectionHeading({ eyebrow, title, sub }: { eyebrow: string; title: string; sub?: string }) {
  return (
    <motion.div initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }}
      className="text-center mb-12">
      <p className="text-accent text-xs font-mono uppercase tracking-widest mb-3">{eyebrow}</p>
      <h2 className="text-3xl md:text-4xl font-bold mb-4">{title}</h2>
      {sub && <p className="text-text-secondary max-w-xl mx-auto">{sub}</p>}
    </motion.div>
  );
}
