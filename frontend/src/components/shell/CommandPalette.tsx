// ============================================================
// ARGUS — Cmd+K Command Palette
// ============================================================
import { useEffect, useRef, useState, useCallback } from "react";
import { useSessionStore } from "../../store/sessionStore";
import { openHtmlReport, downloadPdfReport, downloadStixReport } from "../../lib/api";

interface Command {
  id: string;
  label: string;
  description: string;
  shortcut?: string;
  action: () => void;
  keywords?: string[];
}

interface CommandPaletteProps {
  onNavigate?: (page: string) => void;
}

export function CommandPalette({ onNavigate }: CommandPaletteProps) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const { mode, setMode, reset, session } = useSessionStore();

  const commands: Command[] = [
    {
      id: "goto-dashboard",
      label: "Go to Dashboard",
      description: "Open the main analysis dashboard",
      shortcut: "G D",
      action: () => onNavigate?.("dashboard"),
      keywords: ["home", "main"],
    },
    {
      id: "goto-terminal",
      label: "Open Terminal",
      description: "Open the sandboxed recon terminal (Advanced mode)",
      shortcut: "G T",
      action: () => onNavigate?.("terminal"),
      keywords: ["terminal", "shell", "console", "recon", "command"],
    },
    {
      id: "toggle-mode",
      label: `Switch to ${mode === "basic" ? "Advanced" : "Basic"} Mode`,
      description: mode === "basic"
        ? "Enable terminal, all 8 layers, and chain replay"
        : "Switch to basic 3-layer mode",
      action: () => setMode(mode === "basic" ? "advanced" : "basic"),
      keywords: ["mode", "advanced", "basic"],
    },
    {
      id: "reset-session",
      label: "Reset Session",
      description: "Clear all findings and start fresh",
      action: () => { reset(); onNavigate?.("dashboard"); },
      keywords: ["clear", "new", "fresh"],
    },
    {
      id: "export-html",
      label: "Export HTML Report",
      description: "Open the full threat report in a new tab",
      shortcut: "E H",
      action: () => session && openHtmlReport(session.id),
      keywords: ["report", "export", "html"],
    },
    {
      id: "export-pdf",
      label: "Export PDF Report",
      description: "Download the threat report as PDF",
      shortcut: "E P",
      action: () => session && downloadPdfReport(session.id),
      keywords: ["report", "pdf", "download"],
    },
    {
      id: "export-stix",
      label: "Export STIX 2.1",
      description: "Download structured threat intel as STIX JSON",
      shortcut: "E S",
      action: () => session && downloadStixReport(session.id),
      keywords: ["stix", "threat intel", "json", "export"],
    },
  ];

  const filtered = query
    ? commands.filter((c) => {
        const q = query.toLowerCase();
        return (
          c.label.toLowerCase().includes(q) ||
          c.description.toLowerCase().includes(q) ||
          c.keywords?.some((k) => k.includes(q))
        );
      })
    : commands;

  const close = useCallback(() => {
    setOpen(false);
    setQuery("");
    setSelected(0);
  }, []);

  const run = useCallback(
    (cmd: Command) => {
      cmd.action();
      close();
    },
    [close],
  );

  // Keyboard shortcut: Cmd+K / Ctrl+K
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setOpen((v) => !v);
      }
      if (e.key === "Escape") close();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [close]);

  // Arrow navigation
  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === "ArrowDown") {
        e.preventDefault();
        setSelected((s) => Math.min(s + 1, filtered.length - 1));
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setSelected((s) => Math.max(s - 1, 0));
      } else if (e.key === "Enter") {
        e.preventDefault();
        if (filtered[selected]) run(filtered[selected]);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [open, filtered, selected, run]);

  useEffect(() => {
    if (open) setTimeout(() => inputRef.current?.focus(), 50);
  }, [open]);

  useEffect(() => setSelected(0), [query]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-24"
      onClick={close}
    >
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />

      {/* Panel */}
      <div
        className="relative w-full max-w-xl bg-[#161b22] border border-[#30363d] rounded-xl shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Search input */}
        <div className="flex items-center gap-3 px-4 py-3 border-b border-[#30363d]">
          <svg className="w-4 h-4 text-[#8b949e] flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search commands..."
            className="flex-1 bg-transparent text-[#e6edf3] placeholder-[#8b949e] outline-none text-sm font-mono"
          />
          <kbd className="text-[10px] text-[#8b949e] bg-[#0d1117] border border-[#30363d] rounded px-1.5 py-0.5">ESC</kbd>
        </div>

        {/* Results */}
        <div className="max-h-80 overflow-y-auto py-1">
          {filtered.length === 0 ? (
            <div className="px-4 py-6 text-center text-sm text-[#8b949e]">No commands found</div>
          ) : (
            filtered.map((cmd, i) => (
              <button
                key={cmd.id}
                className={`w-full text-left px-4 py-2.5 flex items-center justify-between transition-colors ${
                  i === selected ? "bg-[#00d4ff]/10 text-[#00d4ff]" : "text-[#e6edf3] hover:bg-[#21262d]"
                }`}
                onMouseEnter={() => setSelected(i)}
                onClick={() => run(cmd)}
              >
                <div>
                  <div className="text-sm font-medium">{cmd.label}</div>
                  <div className="text-xs text-[#8b949e] mt-0.5">{cmd.description}</div>
                </div>
                {cmd.shortcut && (
                  <kbd className="text-[10px] text-[#8b949e] bg-[#0d1117] border border-[#30363d] rounded px-1.5 py-0.5 font-mono flex-shrink-0 ml-4">
                    {cmd.shortcut}
                  </kbd>
                )}
              </button>
            ))
          )}
        </div>

        {/* Footer */}
        <div className="px-4 py-2 border-t border-[#30363d] flex items-center gap-4 text-[10px] text-[#8b949e]">
          <span>↑↓ navigate</span>
          <span>↵ select</span>
          <span>esc close</span>
          <span className="ml-auto font-mono text-[#00d4ff]">⌘K</span>
        </div>
      </div>
    </div>
  );
}
