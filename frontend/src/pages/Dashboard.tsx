import { motion } from "framer-motion";
import { useSessionStore } from "../store/sessionStore";
import { AttackGraph } from "../components/graph/AttackGraph";
import { ReasoningConsole } from "../components/reasoning/ReasoningConsole";
import { ExploitHeatmap } from "../components/heatmap/ExploitHeatmap";
import { ReportStudio } from "../components/report/ReportStudio";
import { ChainReplay } from "../components/timeline/ChainReplay";
import { LayerStatusBar } from "../components/shell/LayerStatusBar";

const fade = {
  initial: { opacity: 0, y: 12 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { once: true, margin: "-40px" },
};

export function Dashboard() {
  const { mode } = useSessionStore();

  return (
    <div className="flex flex-col h-full overflow-hidden bg-bg">
      <LayerStatusBar />

      {/* Scrollable workspace */}
      <div className="flex-1 overflow-y-auto">
        <div className="p-3 space-y-3 max-w-[1600px] mx-auto">
          {mode === "basic" ? (
            <>
              <motion.section {...fade} className="h-[460px]"><AttackGraph /></motion.section>
              <div className="flex flex-col lg:flex-row gap-3">
                <motion.section {...fade} className="flex-1 min-w-0 h-[340px]"><ReasoningConsole /></motion.section>
                <motion.section {...fade} className="flex-1 min-w-0 h-[340px]"><ExploitHeatmap /></motion.section>
              </div>
              <motion.section {...fade} className="h-[600px]"><ReportStudio /></motion.section>
            </>
          ) : (
            <>
              <div className="flex flex-col lg:flex-row gap-3">
                <motion.section {...fade} className="flex-1 min-w-0 h-[520px]"><AttackGraph /></motion.section>
                <motion.section {...fade} className="w-full lg:w-[380px] shrink-0 h-[520px]"><ReasoningConsole /></motion.section>
              </div>
              <div className="flex flex-col lg:flex-row gap-3">
                <motion.section {...fade} className="flex-1 min-w-0 h-[440px]"><ChainReplay /></motion.section>
                <motion.section {...fade} className="w-full lg:w-[380px] shrink-0 h-[440px]"><ExploitHeatmap /></motion.section>
              </div>
              <motion.section {...fade} className="h-[640px]"><ReportStudio /></motion.section>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
