import { useSessionStore } from "../store/sessionStore";
import { AttackGraph } from "../components/graph/AttackGraph";
import { ReasoningConsole } from "../components/reasoning/ReasoningConsole";
import { ExploitHeatmap } from "../components/heatmap/ExploitHeatmap";
import { ReportStudio } from "../components/report/ReportStudio";
import { ChainReplay } from "../components/timeline/ChainReplay";
import { LayerStatusBar } from "../components/shell/LayerStatusBar";
import { MotionPanel, WorkspaceBackdrop } from "../components/motion/ArgusMotion";

export function Dashboard() {
  const { mode, isRunning } = useSessionStore();

  return (
    <div className="relative flex flex-col h-full overflow-hidden bg-bg">
      <WorkspaceBackdrop active={isRunning} />
      <LayerStatusBar />

      {/* Scrollable workspace */}
      <div className="relative z-10 flex-1 overflow-y-auto">
        <div className="p-3 space-y-3 max-w-[1600px] mx-auto">
          {mode === "basic" ? (
            <>
              <MotionPanel className="h-[460px]"><AttackGraph /></MotionPanel>
              <div className="flex flex-col lg:flex-row gap-3">
                <MotionPanel delay={0.08} className="flex-1 min-w-0 h-[340px]"><ReasoningConsole /></MotionPanel>
                <MotionPanel delay={0.14} className="flex-1 min-w-0 h-[340px]"><ExploitHeatmap /></MotionPanel>
              </div>
              <MotionPanel delay={0.18} className="h-[600px]"><ReportStudio /></MotionPanel>
            </>
          ) : (
            <>
              <div className="flex flex-col lg:flex-row gap-3">
                <MotionPanel className="flex-1 min-w-0 h-[520px]"><AttackGraph /></MotionPanel>
                <MotionPanel delay={0.08} className="w-full lg:w-[380px] shrink-0 h-[520px]"><ReasoningConsole /></MotionPanel>
              </div>
              <div className="flex flex-col lg:flex-row gap-3">
                <MotionPanel delay={0.12} className="flex-1 min-w-0 h-[440px]"><ChainReplay /></MotionPanel>
                <MotionPanel delay={0.16} className="w-full lg:w-[380px] shrink-0 h-[440px]"><ExploitHeatmap /></MotionPanel>
              </div>
              <MotionPanel delay={0.2} className="h-[640px]"><ReportStudio /></MotionPanel>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
