import { useEffect, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Landing } from "./pages/Landing";
import { Onboarding } from "./pages/Onboarding";
import { Dashboard } from "./pages/Dashboard";
import { TerminalView } from "./pages/TerminalView";
import { Topbar } from "./components/shell/Topbar";
import { Sidebar } from "./components/shell/Sidebar";
import { ToastContainer } from "./components/ui/Toast";
import { CommandPalette } from "./components/shell/CommandPalette";
import { useSessionStore } from "./store/sessionStore";
import type { View } from "./lib/view";

const PAGE_VARIANTS = {
  initial: { opacity: 0, y: 10 },
  animate: { opacity: 1, y: 0 },
  exit:    { opacity: 0, y: -10 },
};

export default function App() {
  const [view, setView] = useState<View>("landing");
  const { reset, mode } = useSessionStore();

  // Landing is always presented in the branded landing theme; once the user is
  // in onboarding/dashboard the theme follows the selected scan mode. Both modes
  // currently share the Furo black + orange-red palette (see index.css tokens).
  useEffect(() => {
    const theme = view === "landing" ? "landing" : mode;
    document.documentElement.dataset.theme = theme;
  }, [view, mode]);

  function goTo(v: View) { setView(v); }

  function handleNewAnalysis() {
    reset();
    setView("onboarding");
  }

  const inWorkspace = view === "dashboard" || view === "terminal";

  return (
    <div className="flex flex-col h-screen bg-bg text-text-primary overflow-hidden">
      <ToastContainer />
      <CommandPalette onNavigate={(p) => goTo(p as View)} />
      {inWorkspace && (
        <Topbar view={view} onNavigate={goTo} onNewAnalysis={handleNewAnalysis} onHome={() => goTo("landing")} />
      )}
      <AnimatePresence mode="wait">
        {view === "landing" && (
          <motion.div key="landing" {...PAGE_VARIANTS} transition={{ duration: 0.3 }} className="landing-scroll-container flex-1 overflow-x-hidden overflow-y-auto">
            <Landing onEnter={() => goTo("onboarding")} />
          </motion.div>
        )}
        {view === "onboarding" && (
          <motion.div key="onboarding" {...PAGE_VARIANTS} transition={{ duration: 0.25 }} className="flex-1 overflow-y-auto bg-bg">
            <div className="grid-bg min-h-full">
              <Onboarding onStart={() => goTo("dashboard")} onBack={() => goTo("landing")} />
            </div>
          </motion.div>
        )}
        {inWorkspace && (
          <motion.div key="workspace" {...PAGE_VARIANTS} transition={{ duration: 0.2 }} className="flex flex-1 min-h-0 overflow-hidden">
            <Sidebar />
            <main className="flex-1 min-w-0 overflow-hidden">
              {view === "dashboard" ? <Dashboard /> : <TerminalView />}
            </main>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
