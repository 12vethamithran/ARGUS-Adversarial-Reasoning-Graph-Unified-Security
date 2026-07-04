import type { ReactNode } from "react";
import { motion, type Variants } from "framer-motion";
import { clsx } from "clsx";

const PANEL_VARIANTS: Variants = {
  hidden: { opacity: 0, y: 18, filter: "blur(5px)" },
  show: { opacity: 1, y: 0, filter: "blur(0px)" },
};

interface MotionPanelProps {
  children: ReactNode;
  className?: string;
  delay?: number;
}

export function MotionPanel({ children, className, delay = 0 }: MotionPanelProps) {
  return (
    <motion.section
      initial="hidden"
      whileInView="show"
      viewport={{ once: true, margin: "-48px" }}
      variants={PANEL_VARIANTS}
      transition={{ duration: 0.62, delay, ease: [0.16, 1, 0.3, 1] }}
      whileHover={{ y: -2 }}
      className={clsx("relative", className)}
    >
      {children}
    </motion.section>
  );
}

export function WorkspaceBackdrop({ active }: { active: boolean }) {
  const traces = [
    { top: "12%", delay: 0, duration: 8.5 },
    { top: "36%", delay: 1.8, duration: 10 },
    { top: "68%", delay: 3.2, duration: 9.4 },
    { top: "86%", delay: 5.1, duration: 11 },
  ];

  return (
    <div aria-hidden className="pointer-events-none absolute inset-0 overflow-hidden">
      <div className="argus-workspace-grid absolute inset-0" />
      <div className="absolute inset-0 bg-[linear-gradient(180deg,rgb(var(--accent)/0.08),transparent_38%)]" />
      {traces.map((trace) => (
        <motion.span
          key={trace.top}
          className="absolute h-px w-2/3 bg-gradient-to-r from-transparent via-accent/35 to-transparent"
          style={{ top: trace.top }}
          animate={{ x: ["-75%", "145%"], opacity: [0, active ? 0.85 : 0.35, 0] }}
          transition={{
            duration: trace.duration,
            delay: trace.delay,
            repeat: Infinity,
            ease: "linear",
          }}
        />
      ))}
      {active && (
        <motion.span
          className="absolute left-0 right-0 top-0 h-px bg-accent/50 shadow-[0_0_18px_rgb(var(--accent)/0.45)]"
          animate={{ opacity: [0.15, 0.8, 0.15] }}
          transition={{ duration: 2.2, repeat: Infinity, ease: "easeInOut" }}
        />
      )}
    </div>
  );
}

export function LiveDot({ active }: { active: boolean }) {
  return (
    <span className="relative flex h-2 w-2 items-center justify-center">
      {active && <span className="absolute inline-flex h-full w-full rounded-full bg-accent opacity-70 animate-ping" />}
      <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-accent" />
    </span>
  );
}
