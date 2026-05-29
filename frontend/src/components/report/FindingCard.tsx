import { useState } from "react";
import { ChevronDown, CircleAlert, ShieldCheck } from "lucide-react";
import type { Finding } from "../../lib/types";
import { describeFinding, evidenceEntries } from "../../lib/findingKb";

const SEV_STYLES: Record<string, string> = {
  info: "bg-severity-info/10 text-severity-info border-severity-info/30",
  low: "bg-severity-low/10 text-severity-low border-severity-low/30",
  medium: "bg-severity-medium/10 text-severity-medium border-severity-medium/30",
  high: "bg-severity-high/10 text-severity-high border-severity-high/30",
  critical: "bg-severity-critical/10 text-severity-critical border-severity-critical/30",
};

export function FindingCard({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  const d = describeFinding(finding);
  const evidence = evidenceEntries(finding);

  return (
    <div className="bg-raised rounded-lg border border-line/10 overflow-hidden">
      <button onClick={() => setOpen((o) => !o)} className="w-full text-left p-4 hover:bg-accent/5 transition-colors">
        <div className="flex items-start gap-3">
          <span className={`shrink-0 text-xs font-mono px-2 py-0.5 rounded border ${SEV_STYLES[finding.severity] ?? ""} uppercase`}>
            {finding.severity}
          </span>
          <div className="flex-1 min-w-0">
            <p className="text-text-primary text-sm font-medium leading-snug">{finding.title}</p>
            <p className="text-text-muted text-[11px] font-mono mt-0.5">L{finding.layer} · {d.layerName}</p>
          </div>
          <ChevronDown className={`w-4 h-4 text-text-muted shrink-0 transition-transform ${open ? "rotate-180" : ""}`} />
        </div>

        <div className="flex flex-wrap items-center gap-2 mt-2 text-xs font-mono text-text-muted">
          {finding.exploitable ? (
            <span className="flex items-center gap-1 text-severity-critical"><CircleAlert className="w-3 h-3" /> exploitable</span>
          ) : (
            <span className="flex items-center gap-1 text-accent-green"><ShieldCheck className="w-3 h-3" /> not exploitable</span>
          )}
          {d.refs.map((r) => (
            <span key={r} className="bg-overlay/60 px-2 py-0.5 rounded border border-line/10">{r}</span>
          ))}
          <span className="ml-auto">conf {(finding.confidence * 100).toFixed(0)}%</span>
        </div>
      </button>

      {open && (
        <div className="px-4 pb-4 pt-1 space-y-2 border-t border-line/10">
          <Field label="What it is" text={d.description} />
          <Field label="Impact" text={d.impact} />
          <Field label="Remediation" text={d.remediation} />
          {evidence.length > 0 && (
            <div>
              <p className="text-[10px] font-mono uppercase tracking-widest text-text-muted mb-1 mt-2">Evidence</p>
              <div className="rounded-md bg-bg/60 border border-line/10 p-2 space-y-1">
                {evidence.map(([k, v]) => (
                  <div key={k} className="text-[10px] font-mono flex gap-2">
                    <span className="text-accent shrink-0">{k}</span>
                    <span className="text-text-secondary break-all">{v}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Field({ label, text }: { label: string; text: string }) {
  return (
    <div>
      <p className="text-[10px] font-mono uppercase tracking-widest text-text-muted mb-0.5 mt-2">{label}</p>
      <p className="text-[11px] text-text-secondary leading-relaxed">{text}</p>
    </div>
  );
}
