import { useEffect, useState } from "react";
import { create } from "zustand";

type ToastType = "success" | "error" | "info" | "warning";

interface Toast {
  id: string;
  message: string;
  type: ToastType;
  exiting?: boolean;
}

interface ToastStore {
  toasts: Toast[];
  add: (message: string, type?: ToastType) => void;
  remove: (id: string) => void;
}

export const useToastStore = create<ToastStore>((set) => ({
  toasts: [],
  add: (message, type = "info") => {
    const id = Math.random().toString(36).slice(2);
    set((s) => ({ toasts: [...s.toasts, { id, message, type }] }));
    setTimeout(() => {
      set((s) => ({
        toasts: s.toasts.map((t) => t.id === id ? { ...t, exiting: true } : t),
      }));
      setTimeout(() => {
        set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) }));
      }, 300);
    }, 3500);
  },
  remove: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),
}));

export const toast = {
  success: (msg: string) => useToastStore.getState().add(msg, "success"),
  error: (msg: string) => useToastStore.getState().add(msg, "error"),
  info: (msg: string) => useToastStore.getState().add(msg, "info"),
  warning: (msg: string) => useToastStore.getState().add(msg, "warning"),
};

const ICONS: Record<ToastType, string> = {
  success: "✓", error: "✕", info: "ℹ", warning: "⚠",
};
const COLORS: Record<ToastType, string> = {
  success: "border-green-500/30 bg-green-500/10 text-green-400",
  error:   "border-red-500/30   bg-red-500/10   text-red-400",
  info:    "border-cyan-500/30  bg-cyan-500/10  text-cyan-400",
  warning: "border-amber-500/30 bg-amber-500/10 text-amber-400",
};

export function ToastContainer() {
  const { toasts } = useToastStore();
  return (
    <div className="fixed top-4 right-4 z-[100] flex flex-col gap-2 pointer-events-none">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={`${t.exiting ? "toast-exit" : "toast-enter"} pointer-events-auto flex items-center gap-3 px-4 py-3 rounded-xl border glass font-mono text-sm ${COLORS[t.type]} max-w-sm`}
        >
          <span className="font-bold shrink-0">{ICONS[t.type]}</span>
          <span className="text-text-primary text-xs">{t.message}</span>
        </div>
      ))}
    </div>
  );
}
