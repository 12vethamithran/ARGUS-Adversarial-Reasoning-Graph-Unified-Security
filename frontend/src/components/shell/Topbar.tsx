import { Eye, Plus, LayoutDashboard, TerminalSquare } from "lucide-react";
import { useSessionStore } from "../../store/sessionStore";
import type { View } from "../../lib/view";

interface Props {
  view: View;
  onNavigate: (v: View) => void;
  onNewAnalysis: () => void;
  onHome: () => void;
}

export function Topbar({ view, onNavigate, onNewAnalysis, onHome }: Props) {
  const { mode, isRunning, session } = useSessionStore();

  const tab = (active: boolean) =>
    `flex items-center gap-1.5 text-xs font-mono px-3 py-1.5 rounded-lg border transition-all ${
      active
        ? "border-accent/40 text-accent bg-accent/10"
        : "border-transparent text-text-secondary hover:text-text-primary hover:border-line/20"
    }`;

  return (
    <header className="h-12 flex items-center justify-between px-4 border-b border-line/15 bg-surface/90 backdrop-blur-sm shrink-0 z-40">
      {/* Logo */}
      <button onClick={onHome} className="flex items-center gap-2.5 hover:opacity-80 transition-opacity">
        <div className="relative w-7 h-7 rounded-lg border border-accent/40 flex items-center justify-center bg-accent/10">
          <Eye className="w-4 h-4 text-accent" strokeWidth={2.2} />
          {isRunning && (
            <span className="absolute -top-0.5 -right-0.5 w-2 h-2 bg-accent rounded-full animate-ping" />
          )}
        </div>
        <span className="font-mono font-bold text-text-primary tracking-widest text-sm hidden sm:block">ARGUS</span>
      </button>

      {/* Center: workspace tabs */}
      <nav className="flex items-center gap-1.5">
        <button className={tab(view === "dashboard")} onClick={() => onNavigate("dashboard")}>
          <LayoutDashboard className="w-3.5 h-3.5" /> Dashboard
        </button>
        {mode === "advanced" && (
          <button className={tab(view === "terminal")} onClick={() => onNavigate("terminal")}>
            <TerminalSquare className="w-3.5 h-3.5" /> Terminal
          </button>
        )}
      </nav>

      {/* Right */}
      <div className="flex items-center gap-3">
        <div className="text-xs font-mono px-3 py-1 rounded-full border border-accent/25 text-accent/80 bg-accent/5 hidden md:block">
          {mode === "basic" ? "Basic · 3 Layers" : "Advanced · 8 Layers"}
        </div>
        {!isRunning && session && (
          <button
            onClick={onNewAnalysis}
            className="flex items-center gap-1 text-xs font-mono px-3 py-1.5 rounded-lg border border-line/20 text-text-secondary hover:text-text-primary hover:border-accent/40 transition-all"
          >
            <Plus className="w-3.5 h-3.5" /> New
          </button>
        )}
      </div>
    </header>
  );
}
