import { useEffect, useRef } from "react";
import "@xterm/xterm/css/xterm.css";
import { useSessionStore } from "../../store/sessionStore";

const WS_BASE = import.meta.env.VITE_WS_URL ?? "";

export function TerminalPanel() {
  const { mode, session } = useSessionStore();
  const containerRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<any>(null);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    if (mode !== "advanced" || !containerRef.current) return;

    let term: any;
    let ws: WebSocket;

    (async () => {
      const { Terminal } = await import("@xterm/xterm");
      const { FitAddon } = await import("@xterm/addon-fit");
      const { WebLinksAddon } = await import("@xterm/addon-web-links");

      term = new Terminal({
        theme: {
          background: "#050505", foreground: "#f5f5f5",
          cursor: "#ff3d12", cursorAccent: "#050505",
          selectionBackground: "rgba(255,61,18,0.22)",
          black: "#050505", brightBlack: "#3a3a3a",
          cyan: "#a8a8a8", brightCyan: "#f5f5f5",
          green: "#00e676", yellow: "#ffb300",
          red: "#ff3d57", white: "#e2e8f0",
        },
        fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
        fontSize: 12,
        lineHeight: 1.4,
        cursorBlink: true,
        cursorStyle: "block",
        scrollback: 1000,
      });

      const fitAddon = new FitAddon();
      term.loadAddon(fitAddon);
      term.loadAddon(new WebLinksAddon());
      term.open(containerRef.current!);
      fitAddon.fit();

      termRef.current = term;

      const sessionId = session?.id ?? "argus-terminal";
      ws = new WebSocket(`${WS_BASE}/ws/terminal/${sessionId}`);
      wsRef.current = ws;

      ws.onopen = () => term.focus();
      ws.onmessage = (e) => term.write(e.data);
      ws.onclose = () => term.write("\r\n\x1b[33m[disconnected]\x1b[0m\r\n");
      ws.onerror = () => term.write("\r\n\x1b[31m[WebSocket error — is backend running?]\x1b[0m\r\n");

      term.onData((data: string) => {
        if (ws.readyState === WebSocket.OPEN) ws.send(data);
      });

      const ro = new ResizeObserver(() => fitAddon.fit());
      ro.observe(containerRef.current!);

      return () => ro.disconnect();
    })();

    return () => {
      term?.dispose();
      ws?.close();
    };
  }, [mode, session?.id]);

  if (mode !== "advanced") return null;

  return (
    <div className="argus-panel-shell flex flex-col h-full glass rounded-lg border border-line/15 overflow-hidden">
      <div className="relative flex items-center gap-3 px-4 py-2 border-b border-line/15 bg-bg/90 shrink-0 overflow-hidden">
        <span className="absolute inset-x-0 bottom-0 h-px argus-live-pill bg-accent/20" />
        <div className="flex gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-red-500/60" />
          <span className="w-2.5 h-2.5 rounded-full bg-amber-500/60" />
          <span className="w-2.5 h-2.5 rounded-full bg-green-500/60" />
        </div>
        <span className="text-xs font-mono text-text-secondary">argus@target:~$</span>
        <span className="ml-auto text-xs font-mono text-text-muted hidden md:block">
          Whitelisted: nmap · curl · dig · whois · traceroute · openssl · nikto · whatweb
        </span>
      </div>
      <div ref={containerRef} className="flex-1 p-1 overflow-hidden" />
    </div>
  );
}
