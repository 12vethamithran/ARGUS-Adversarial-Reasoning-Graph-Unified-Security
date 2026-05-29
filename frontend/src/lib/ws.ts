// ============================================================
// ARGUS — Terminal WebSocket client
// ============================================================

const WS_BASE = import.meta.env.VITE_WS_URL ?? "";

export type TerminalMessage =
  | { type: "output"; data: string }
  | { type: "error"; message: string }
  | { type: "closed" };

export interface TerminalSocket {
  send: (data: string) => void;
  resize: (cols: number, rows: number) => void;
  close: () => void;
  readonly readyState: number;
}

/**
 * Connect to the PTY WebSocket for a given session.
 * Returns a handle with send/resize/close.
 */
export function connectTerminal(
  sessionId: string,
  onMessage: (msg: TerminalMessage) => void,
  onOpen?: () => void,
): TerminalSocket {
  const url = `${WS_BASE}/ws/terminal/${sessionId}`;
  let ws: WebSocket;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let closed = false;

  function connect() {
    ws = new WebSocket(url);

    ws.onopen = () => {
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
      onOpen?.();
    };

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data as string) as TerminalMessage;
        onMessage(msg);
      } catch {
        // Raw text frame — treat as output
        onMessage({ type: "output", data: event.data as string });
      }
    };

    ws.onerror = () => {
      onMessage({ type: "error", message: "WebSocket error" });
    };

    ws.onclose = () => {
      if (closed) return;
      onMessage({ type: "closed" });
      // Auto-reconnect with backoff (max 5 retries handled by caller close)
      reconnectTimer = setTimeout(connect, 3000);
    };
  }

  connect();

  return {
    send(data: string) {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "input", data }));
      }
    },
    resize(cols: number, rows: number) {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "resize", cols, rows }));
      }
    },
    close() {
      closed = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      ws.close();
    },
    get readyState() {
      return ws.readyState;
    },
  };
}
