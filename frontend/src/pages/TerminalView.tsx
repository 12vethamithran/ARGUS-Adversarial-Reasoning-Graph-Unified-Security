import { TerminalSquare, ShieldCheck, Info } from "lucide-react";
import { useSessionStore } from "../store/sessionStore";
import { TerminalPanel } from "../components/terminal/TerminalPanel";
import { WorkspaceBackdrop } from "../components/motion/ArgusMotion";

const EXAMPLES = [
  { cmd: "curl -I https://target", note: "inspect security headers / CORS" },
  { cmd: "dig target.com", note: "DNS records" },
  { cmd: "whois target.com", note: "ownership / registrar" },
  { cmd: "nmap -sV -Pn --open target", note: "open services (safe scan)" },
  { cmd: "openssl s_client -connect t:443", note: "TLS certificate chain" },
  { cmd: "whatweb -a 1 https://target", note: "tech fingerprint" },
];

export function TerminalView() {
  const { mode, isRunning } = useSessionStore();

  if (mode !== "advanced") {
    return (
      <div className="flex flex-col items-center justify-center h-full text-center gap-3 p-8 bg-bg">
        <TerminalSquare className="w-10 h-10 text-text-muted opacity-30" />
        <p className="text-text-secondary font-mono text-sm">The sandboxed terminal is available in Advanced mode.</p>
        <p className="text-text-muted text-xs">Start an Advanced analysis to validate findings against the live target.</p>
      </div>
    );
  }

  return (
    <div className="relative flex flex-col h-full bg-bg overflow-hidden">
      <WorkspaceBackdrop active={isRunning} />
      {/* Header */}
      <div className="relative z-10 flex items-center gap-3 px-5 py-3 border-b border-line/15 shrink-0 bg-bg/75 backdrop-blur-sm">
        <div className="w-8 h-8 rounded-lg bg-accent/10 border border-accent/30 flex items-center justify-center">
          <TerminalSquare className="w-4 h-4 text-accent" />
        </div>
        <div>
          <h1 className="text-sm font-semibold text-text-primary">Recon Terminal</h1>
          <p className="text-[11px] text-text-muted font-mono">Sandboxed · whitelisted read-only commands</p>
        </div>
        <span className="ml-auto flex items-center gap-1.5 text-[11px] font-mono text-accent-green">
          <ShieldCheck className="w-3.5 h-3.5" /> exploit &amp; destructive flags blocked
        </span>
      </div>

      {/* Body: terminal + cheatsheet */}
      <div className="relative z-10 flex flex-1 min-h-0 gap-3 p-3 overflow-hidden">
        <div className="flex-1 min-w-0">
          <TerminalPanel />
        </div>

        <aside className="w-72 shrink-0 hidden lg:flex flex-col gap-3 overflow-y-auto">
          <div className="argus-panel-shell glass rounded-lg border border-line/15 p-4">
            <p className="flex items-center gap-1.5 text-xs font-mono text-text-muted uppercase tracking-widest mb-3">
              <Info className="w-3.5 h-3.5 text-accent" /> Validate findings
            </p>
            <p className="text-[11px] text-text-secondary leading-relaxed mb-3">
              Reproduce what the scanner reported — confirm a header is missing, a port is open,
              or a certificate is weak — directly against the target.
            </p>
            <div className="space-y-2">
              {EXAMPLES.map((e) => (
                <div key={e.cmd} className="rounded-md bg-bg/50 border border-line/10 p-2">
                  <code className="text-[11px] font-mono text-accent break-all">{e.cmd}</code>
                  <p className="text-[10px] text-text-muted mt-0.5">{e.note}</p>
                </div>
              ))}
            </div>
          </div>
          <div className="argus-panel-shell glass rounded-lg border border-line/15 p-4">
            <p className="text-xs font-mono text-text-muted uppercase tracking-widest mb-2">Built-ins</p>
            <p className="text-[11px] text-text-secondary font-mono">help · clear</p>
            <p className="text-[10px] text-text-muted mt-2 leading-relaxed">
              Allowed binaries: nmap · curl · dig · whois · traceroute · openssl · nikto · whatweb · ping · netstat
            </p>
          </div>
        </aside>
      </div>
    </div>
  );
}
