// ============================================================
// ARGUS — useTerminal hook (xterm.js + WebSocket bridge)
// ============================================================
import { useEffect, useRef, useCallback } from "react";
import type { Terminal } from "@xterm/xterm";
import { connectTerminal } from "../../lib/ws";

const PROMPT = "\r\n\x1b[36margus@target\x1b[0m:\x1b[33m~\x1b[0m$ ";

export interface UseTerminalOptions {
  sessionId: string | null;
  enabled: boolean;
}

export function useTerminal(
  containerRef: React.RefObject<HTMLDivElement>,
  { sessionId, enabled }: UseTerminalOptions,
) {
  const termRef = useRef<Terminal | null>(null);
  const wsRef = useRef<ReturnType<typeof connectTerminal> | null>(null);
  const fitAddonRef = useRef<import("@xterm/addon-fit").FitAddon | null>(null);

  const writeOutput = useCallback((text: string) => {
    termRef.current?.write(text);
  }, []);

  // Init terminal
  useEffect(() => {
    if (!enabled || !containerRef.current) return;

    let term: Terminal;

    (async () => {
      const { Terminal: XTerm } = await import("@xterm/xterm");
      const { FitAddon } = await import("@xterm/addon-fit");
      const { WebLinksAddon } = await import("@xterm/addon-web-links");

      term = new XTerm({
        cursorBlink: true,
        fontFamily: '"JetBrains Mono", "Fira Code", monospace',
        fontSize: 13,
        lineHeight: 1.4,
        theme: {
          background: "#0d1117",
          foreground: "#e6edf3",
          cursor: "#00d4ff",
          selectionBackground: "#264f78",
          black: "#0d1117",
          brightBlack: "#6e7681",
          red: "#ff7b72",
          brightRed: "#ffa198",
          green: "#3fb950",
          brightGreen: "#56d364",
          yellow: "#d29922",
          brightYellow: "#e3b341",
          blue: "#58a6ff",
          brightBlue: "#79c0ff",
          magenta: "#bc8cff",
          brightMagenta: "#d2a8ff",
          cyan: "#39c5cf",
          brightCyan: "#56d4dd",
          white: "#b1bac4",
          brightWhite: "#cdd9e5",
        },
        scrollback: 2000,
        convertEol: true,
      });

      const fitAddon = new FitAddon();
      fitAddonRef.current = fitAddon;
      term.loadAddon(fitAddon);
      term.loadAddon(new WebLinksAddon());
      term.open(containerRef.current!);
      fitAddon.fit();
      termRef.current = term;

      term.writeln("\x1b[36m╔══════════════════════════════════════╗\x1b[0m");
      term.writeln("\x1b[36m║  ARGUS Terminal — Advanced Mode      ║\x1b[0m");
      term.writeln("\x1b[36m║  Whitelisted commands only           ║\x1b[0m");
      term.writeln("\x1b[36m╚══════════════════════════════════════╝\x1b[0m");

      if (sessionId) {
        wsRef.current = connectTerminal(
          sessionId,
          (msg) => {
            if (msg.type === "output") {
              term.write(msg.data);
            } else if (msg.type === "error") {
              term.writeln(`\r\n\x1b[31m[ERROR] ${msg.message}\x1b[0m`);
            } else if (msg.type === "closed") {
              term.writeln(`\r\n\x1b[33m[Connection closed]\x1b[0m`);
              term.write(PROMPT);
            }
          },
          () => {
            term.write(PROMPT);
          },
        );

        term.onData((data) => {
          wsRef.current?.send(data);
        });
      } else {
        // Demo mode — echo locally
        term.write(PROMPT);
        let line = "";
        term.onData((data) => {
          if (data === "\r") {
            term.write("\r\n");
            if (line.trim()) {
              term.writeln(
                `\x1b[33m[DEMO] Connect a session to run real commands\x1b[0m`,
              );
            }
            line = "";
            term.write(PROMPT);
          } else if (data === "\x7f") {
            if (line.length > 0) {
              line = line.slice(0, -1);
              term.write("\b \b");
            }
          } else {
            line += data;
            term.write(data);
          }
        });
      }
    })();

    const ro = new ResizeObserver(() => {
      fitAddonRef.current?.fit();
      const dims = fitAddonRef.current?.proposeDimensions();
      if (dims) wsRef.current?.resize(dims.cols, dims.rows);
    });
    if (containerRef.current) ro.observe(containerRef.current);

    return () => {
      ro.disconnect();
      term?.dispose();
      wsRef.current?.close();
      termRef.current = null;
      wsRef.current = null;
    };
  }, [enabled, sessionId]);

  return { writeOutput };
}
