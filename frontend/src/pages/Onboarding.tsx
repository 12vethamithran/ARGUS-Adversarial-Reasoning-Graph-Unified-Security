import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { ArrowLeft, GraduationCap, Crosshair, Check } from "lucide-react";
import { useSessionStore } from "../store/sessionStore";
import { startAnalysisStream } from "../store/eventStream";
import { toast } from "../components/ui/Toast";

const BASIC_LAYERS = [1, 2, 3];
const ADVANCED_LAYERS = [1, 2, 3, 4, 5, 6, 7, 8];

const LAYER_INFO = [
  { id: 1, label: "Web Surface",       desc: "Headers, CORS, CSP, JS secrets",     owasp: "OWASP Web Top 10" },
  { id: 2, label: "LLM Probe",         desc: "Prompt injection, system leakage",    owasp: "LLM01/07:2025" },
  { id: 3, label: "RAG Poisoning",     desc: "Adversarial doc injection",           owasp: "LLM08:2025" },
  { id: 4, label: "MCP/Agentic",       desc: "Tool-call hijack, confused deputy",   owasp: "Agentic Top 10" },
  { id: 5, label: "Network Recon",     desc: "Topology graph, lateral movement",    owasp: "MITRE T1046" },
  { id: 6, label: "Supply Chain",      desc: "pip-audit, typosquat detection",      owasp: "SkillJect/STAC" },
  { id: 7, label: "Multi-Agent Prop.", desc: "Diffusion sim across agent mesh",     owasp: "MASpi" },
  { id: 8, label: "Identity/OAuth",    desc: "MCP session hijack, token intercept", owasp: "MITRE ATLAS" },
];

interface Props { onStart: () => void; onBack: () => void }

export function Onboarding({ onStart, onBack }: Props) {
  const { mode, setMode } = useSessionStore();
  const [url, setUrl] = useState("");
  const [llmEndpoint, setLlmEndpoint] = useState("");
  const [description, setDescription] = useState("");
  const [activeLayers, setActiveLayers] = useState<number[]>(BASIC_LAYERS);
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState<"mode" | "target" | "layers">("mode");

  function selectMode(m: "basic" | "advanced") {
    setMode(m);
    setActiveLayers(m === "basic" ? BASIC_LAYERS : ADVANCED_LAYERS);
    setStep("target");
  }

  function toggleLayer(id: number) {
    if (id <= 3) return;
    setActiveLayers((prev) =>
      prev.includes(id) ? prev.filter((l) => l !== id) : [...prev, id].sort()
    );
  }

  async function handleStart() {
    if (!url && !description) { toast.error("Provide a target URL or description."); return; }
    setLoading(true);
    startAnalysisStream(
      { url: url || undefined, llm_endpoint: llmEndpoint || undefined, description: description || undefined },
      mode,
      activeLayers
    ).catch((e) => toast.error(e.message));
    toast.info("Analysis started — streaming events...");
    onStart();
  }

  const accentClass = mode === "basic"
    ? "border-sky-500/40 text-sky-500 bg-sky-500/10 hover:bg-sky-500/20"
    : "border-rose-500/40 text-rose-400 bg-rose-500/10 hover:bg-rose-500/20";

  return (
    <div className="relative flex flex-col items-center justify-center min-h-screen px-6 py-12">
      <button onClick={onBack}
        className="absolute top-6 left-6 flex items-center gap-1.5 text-text-muted hover:text-text-primary text-sm font-mono transition-colors">
        <ArrowLeft className="w-4 h-4" /> Back
      </button>

      <div className="flex gap-2 mb-10">
        {(["mode", "target", "layers"] as const).map((s, i) => (
          <div key={s} className={`h-1 rounded-full transition-all duration-300 ${
            step === s ? "w-8 bg-accent" :
            (["mode","target","layers"].indexOf(step) > i) ? "w-4 bg-accent/40" : "w-4 bg-line/20"
          }`} />
        ))}
      </div>

      <AnimatePresence mode="wait">
        {step === "mode" && (
          <motion.div key="mode" initial={{ opacity:0, x:40 }} animate={{ opacity:1, x:0 }} exit={{ opacity:0, x:-40 }}
            className="w-full max-w-2xl space-y-6">
            <div className="text-center mb-8">
              <h1 className="text-3xl font-bold text-text-primary mb-2">Choose Analysis Mode</h1>
              <p className="text-text-secondary">Select based on your expertise and goals</p>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <motion.button whileHover={{ scale:1.02 }} whileTap={{ scale:0.98 }}
                onClick={() => selectMode("basic")}
                className="text-left p-6 rounded-2xl border border-sky-500/20 hover:border-sky-500/50 transition-all bg-sky-500/[0.04]">
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-10 h-10 rounded-xl bg-sky-500/10 border border-sky-500/30 flex items-center justify-center text-sky-500">
                    <GraduationCap className="w-5 h-5" />
                  </div>
                  <div>
                    <p className="font-bold text-text-primary">Basic Mode</p>
                    <p className="text-xs text-sky-500 font-mono">3 layers · Quick assessment</p>
                  </div>
                </div>
                <ul className="space-y-2 text-sm text-text-secondary">
                  {["Web surface scan (L1)","LLM probe + injection (L2)","RAG poisoning model (L3)","Top 3 chains + 1-page report","No config required"].map((t) => (
                    <li key={t} className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-sky-500 shrink-0" />{t}</li>
                  ))}
                </ul>
                <p className="mt-4 text-xs font-mono text-text-muted">Ideal for: Students, quick assessments</p>
              </motion.button>

              <motion.button whileHover={{ scale:1.02 }} whileTap={{ scale:0.98 }}
                onClick={() => selectMode("advanced")}
                className="text-left p-6 rounded-2xl border border-rose-500/20 hover:border-rose-500/50 transition-all bg-rose-500/[0.04]">
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-10 h-10 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-500">
                    <Crosshair className="w-5 h-5" />
                  </div>
                  <div>
                    <p className="font-bold text-text-primary">Advanced Mode</p>
                    <p className="text-xs text-rose-500 font-mono">8 layers · Full red team</p>
                  </div>
                </div>
                <ul className="space-y-2 text-sm text-text-secondary">
                  {["All 8 attack layers (configurable)","Sandboxed in-browser terminal","Manual chain hypothesis injection","Multi-agent propagation sim","STIX 2.1 + PDF export"].map((t) => (
                    <li key={t} className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-rose-500 shrink-0" />{t}</li>
                  ))}
                </ul>
                <p className="mt-4 text-xs font-mono text-text-muted">Ideal for: Red teamers, researchers</p>
              </motion.button>
            </div>
          </motion.div>
        )}

        {step === "target" && (
          <motion.div key="target" initial={{ opacity:0, x:40 }} animate={{ opacity:1, x:0 }} exit={{ opacity:0, x:-40 }}
            className="w-full max-w-xl space-y-5">
            <div className="text-center mb-8">
              <div className={`inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-mono mb-3 border ${
                mode === "basic" ? "border-accent/30 text-accent bg-accent/5" : "border-accent/30 text-accent bg-accent/5"
              }`}>
                {mode === "basic" ? "Basic Mode" : "Advanced Mode"}
              </div>
              <h1 className="text-3xl font-bold text-text-primary mb-2">Define Your Target</h1>
              <p className="text-text-secondary text-sm">URL, LLM endpoint, or describe a hypothetical system</p>
            </div>
            <div className="space-y-4">
              <div>
                <label className="text-xs font-mono text-text-secondary block mb-2 uppercase tracking-wider">Target URL</label>
                <input type="url" value={url} onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://target.example.com"
                  className="w-full glass rounded-xl px-4 py-3 text-sm font-mono text-text-primary placeholder-text-muted focus:outline-none border border-line/15 focus:border-accent/50 transition-colors" />
              </div>
              <div>
                <label className="text-xs font-mono text-text-secondary block mb-2 uppercase tracking-wider">LLM Endpoint (optional)</label>
                <input type="url" value={llmEndpoint} onChange={(e) => setLlmEndpoint(e.target.value)}
                  placeholder="https://api.openai.com/v1/chat/completions"
                  className="w-full glass rounded-xl px-4 py-3 text-sm font-mono text-text-primary placeholder-text-muted focus:outline-none border border-line/15 focus:border-accent/50 transition-colors" />
              </div>
              <div>
                <label className="text-xs font-mono text-text-secondary block mb-2 uppercase tracking-wider">Or describe a hypothetical target</label>
                <textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={3}
                  placeholder="e.g. A RAG-powered customer service chatbot with a public web interface..."
                  className="w-full glass rounded-xl px-4 py-3 text-sm font-mono text-text-primary placeholder-text-muted focus:outline-none border border-line/15 focus:border-accent/50 transition-colors resize-none" />
              </div>
            </div>
            <div className="flex gap-3 pt-2">
              <button onClick={() => setStep("mode")}
                className="px-6 py-3 rounded-xl border border-line/20 text-text-secondary text-sm font-mono hover:border-line/30 transition-all">
                Back
              </button>
              <button
                onClick={() => mode === "advanced" ? setStep("layers") : handleStart()}
                disabled={!url && !description}
                className={`flex-1 py-3 rounded-xl font-mono font-semibold text-sm border transition-all disabled:opacity-40 disabled:cursor-not-allowed ${accentClass}`}>
                {loading ? "Starting..." : mode === "basic" ? "Start Analysis" : "Next: Configure Layers"}
              </button>
            </div>
          </motion.div>
        )}

        {step === "layers" && (
          <motion.div key="layers" initial={{ opacity:0, x:40 }} animate={{ opacity:1, x:0 }} exit={{ opacity:0, x:-40 }}
            className="w-full max-w-2xl space-y-5">
            <div className="text-center mb-6">
              <h1 className="text-3xl font-bold text-text-primary mb-2">Configure Attack Layers</h1>
              <p className="text-text-secondary text-sm">{activeLayers.length} of 8 layers active</p>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {LAYER_INFO.map((l) => {
                const active = activeLayers.includes(l.id);
                const locked = l.id <= 3;
                return (
                  <button key={l.id} onClick={() => toggleLayer(l.id)}
                    className={`text-left p-4 rounded-xl border transition-all duration-200 ${
                      active ? "border-accent/40 bg-accent/5" : "border-line/15 opacity-50"
                    } ${locked ? "cursor-default" : "cursor-pointer"}`}>
                    <div className="flex items-center justify-between mb-1">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono text-accent">L{l.id}</span>
                        <span className="text-sm font-semibold text-text-primary">{l.label}</span>
                      </div>
                      <div className={`w-4 h-4 rounded border flex items-center justify-center ${
                        active ? "bg-accent border-accent" : "border-line/30"
                      }`}>
                        {active && <Check className="w-3 h-3 text-[rgb(var(--accent-contrast))]" strokeWidth={3} />}
                      </div>
                    </div>
                    <p className="text-xs text-text-muted ml-5">{l.desc}</p>
                    {locked && <p className="text-xs text-accent/50 ml-5 mt-1 font-mono">always on</p>}
                  </button>
                );
              })}
            </div>
            <div className="flex gap-3 pt-2">
              <button onClick={() => setStep("target")}
                className="px-6 py-3 rounded-xl border border-line/20 text-text-secondary text-sm font-mono hover:border-line/30 transition-all">
                Back
              </button>
              <button onClick={handleStart} disabled={loading || activeLayers.length === 0}
                className="flex-1 py-3 rounded-xl font-mono font-semibold text-sm border border-accent/40 text-accent bg-accent/10 hover:bg-accent/20 transition-all disabled:opacity-40 disabled:cursor-not-allowed">
                {loading ? "Starting..." : `Launch ${activeLayers.length}-Layer Sweep`}
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
      <p className="absolute bottom-6 text-text-muted text-xs font-mono">
        Only test targets you own or have explicit authorization to test.
      </p>
    </div>
  );
}
