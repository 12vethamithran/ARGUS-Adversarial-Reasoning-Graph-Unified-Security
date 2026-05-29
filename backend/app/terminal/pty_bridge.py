"""PTY WebSocket bridge — ptyprocess + whitelist + rate limiting."""
from __future__ import annotations
import asyncio
import queue as _queue
import shutil
import subprocess
import threading
import time
from collections import deque

# When a whitelisted tool isn't installed, fall back to a platform-native
# equivalent so the common recon commands work out of the box (esp. on Windows).
NATIVE_FALLBACK = {
    "dig": "nslookup",
    "host": "nslookup",
    "traceroute": "tracert",
}


def _resolve_cmd(cmd: list[str]) -> tuple[list[str], str | None]:
    """Return (command, note). If the binary is missing but a native fallback
    exists, substitute it and return an explanatory note."""
    binary = cmd[0]
    if shutil.which(binary):
        return cmd, None
    fb = NATIVE_FALLBACK.get(binary)
    if fb and shutil.which(fb):
        return [fb, *cmd[1:]], f"'{binary}' not installed — using native '{fb}' instead"
    return cmd, None  # missing & no fallback → will raise FileNotFoundError

# resource module is Unix-only
try:
    import resource as _resource
    HAS_RESOURCE = True
except ImportError:
    HAS_RESOURCE = False  # Windows

from app.terminal.whitelist import check_command
from app.terminal.auditor import log_command

IDLE_TIMEOUT = 300   # 5 min
RATE_LIMIT   = 10    # commands per minute

# Kali-style two-line prompt:  ┌──(argus㉿argus)-[~]
#                              └─$
PROMPT = (
    "\r\n\033[1;34m┌──(\033[1;31margus㉿argus\033[1;34m)-[\033[0;37m~\033[1;34m]"
    "\r\n\033[1;34m└─\033[1;31m$\033[0m "
)

BANNER = (
    "\r\n\033[1;31m"
    "  ┌─────────────────────────────────────────────┐\r\n"
    "  │   ARGUS // Whitelisted Recon Shell  v0.1      │\r\n"
    "  └─────────────────────────────────────────────┘\033[0m\r\n"
    "\033[33m  Allowed:\033[0m nmap · curl · dig · whois · traceroute · host\r\n"
    "           openssl · nikto · whatweb · ping · netstat\r\n"
    "\033[90m  Built-ins: help · clear   ·   exploit/destructive flags blocked\033[0m\r\n"
)

HELP_TEXT = (
    "\r\n\033[36mARGUS Terminal — verify findings against the live target\033[0m\r\n"
    "\033[33mRecon / validation examples:\033[0m\r\n"
    "  curl -I https://target.example.com         \033[90m# check security headers / CORS\033[0m\r\n"
    "  curl -s -H 'X: <inject>' https://target/    \033[90m# probe header reflection\033[0m\r\n"
    "  dig target.example.com                      \033[90m# DNS records\033[0m\r\n"
    "  whois target.example.com                    \033[90m# ownership / registrar\033[0m\r\n"
    "  nmap -sV -Pn --open target.example.com      \033[90m# open services (safe scan)\033[0m\r\n"
    "  openssl s_client -connect target:443        \033[90m# TLS cert / chain\033[0m\r\n"
    "  whatweb -a 1 https://target.example.com     \033[90m# tech fingerprint\033[0m\r\n"
    "  ping -c 2 target.example.com                \033[90m# reachability (-n 2 on Windows)\033[0m\r\n"
    "\033[90m  Built-ins: help · clear. Destructive/exploit flags are blocked.\033[0m\r\n"
)


class PTYSession:
    def __init__(self, session_id: str):
        self.session_id = session_id
        self._cmd_times: deque = deque(maxlen=RATE_LIMIT)
        self._last_activity = time.time()
        self._buf = ""

    def _rate_ok(self) -> bool:
        now = time.time()
        self._cmd_times = deque(
            [t for t in self._cmd_times if now - t < 60], maxlen=RATE_LIMIT
        )
        if len(self._cmd_times) >= RATE_LIMIT:
            return False
        self._cmd_times.append(now)
        return True

    async def handle_input(self, data: str, send: callable) -> None:
        self._last_activity = time.time()

        # Handle backspace/delete before buffering so line editing works.
        if data in ("\x7f", "\b"):
            if self._buf:
                self._buf = self._buf[:-1]
                await send("\b \b")  # erase last glyph on the client
            return

        self._buf += data

        if "\r" not in self._buf and "\n" not in self._buf:
            await send(data)  # echo partial
            return

        line = self._buf.replace("\r", "").replace("\n", "").strip()
        self._buf = ""

        await send(f"\r\n")

        if not line:
            await send(PROMPT)
            return

        # Built-in helpers (no subprocess, no rate limit).
        low = line.lower()
        if low in ("help", "?"):
            await send(HELP_TEXT)
            await send(PROMPT)
            return
        if low == "clear" or low == "cls":
            await send("\033[2J\033[H")  # clear screen, cursor home
            await send(PROMPT)
            return

        if not self._rate_ok():
            await send("\033[31m[ARGUS] Rate limit exceeded (10 cmd/min)\033[0m")
            await send(PROMPT)
            await log_command(self.session_id, line, "RATE_LIMITED")
            return

        verdict = check_command(line)

        if not verdict.allowed:
            await send(f"\033[31m[BLOCKED] {verdict.reason}\033[0m")
            await log_command(self.session_id, line, "BLOCKED", verdict.reason)
            await send(PROMPT)
            return

        await log_command(self.session_id, line, "ALLOWED")

        # Cross-platform execution: PTY on Unix (for tools that need a tty),
        # asyncio subprocess everywhere else (incl. Windows).
        try:
            if HAS_RESOURCE and _ptyprocess_available():
                await _run_pty(verdict.sanitized, send)
            else:
                await _run_subprocess(verdict.sanitized, send)
        except FileNotFoundError:
            await send(f"\033[31m[ARGUS] '{verdict.sanitized[0]}' is not installed on this host\033[0m")
        except Exception as exc:  # never let a command kill the session
            await send(f"\033[31m[ARGUS] Execution error: {type(exc).__name__}: {exc}\033[0m")

        await send(PROMPT)

    def is_idle(self) -> bool:
        return time.time() - self._last_activity > IDLE_TIMEOUT


def _ptyprocess_available() -> bool:
    try:
        import ptyprocess  # noqa: F401
        return True
    except Exception:
        return False


async def _run_subprocess(cmd: list[str], send: callable, timeout: int = 30) -> None:
    """Cross-platform executor — runs the command in a worker thread and streams
    its merged stdout/stderr back over the websocket.

    We deliberately avoid ``asyncio.create_subprocess_exec`` because it raises
    ``NotImplementedError`` on the Windows Selector event loop that uvicorn uses,
    which silently broke every command. ``subprocess.Popen`` in a thread + a queue
    works on every platform and event loop.
    """
    loop = asyncio.get_event_loop()
    q: "_queue.Queue[tuple[str, object]]" = _queue.Queue()
    DONE = "__done__"

    def worker() -> None:
        run_cmd, note = _resolve_cmd(cmd)
        if note:
            q.put(("note", note))
        try:
            proc = subprocess.Popen(
                run_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            q.put(("err", f"'{cmd[0]}' is not installed on this host"))
            q.put((DONE, None)); return
        except Exception as e:  # noqa: BLE001
            q.put(("err", f"{type(e).__name__}: {e}"))
            q.put((DONE, None)); return

        timed_out = {"v": False}

        def _kill() -> None:
            timed_out["v"] = True
            try: proc.kill()
            except Exception: pass

        watchdog = threading.Timer(timeout, _kill)
        watchdog.daemon = True
        watchdog.start()
        try:
            assert proc.stdout is not None
            for chunk in iter(lambda: proc.stdout.read(512), b""):
                q.put(("out", chunk))
        finally:
            watchdog.cancel()
            try: proc.stdout and proc.stdout.close()
            except Exception: pass
            try: proc.wait(timeout=2)
            except Exception:
                try: proc.kill()
                except Exception: pass
            if timed_out["v"]:
                q.put(("err", f"Command timed out ({timeout}s)"))
            q.put((DONE, None))

    threading.Thread(target=worker, daemon=True).start()

    while True:
        kind, payload = await loop.run_in_executor(None, q.get)
        if kind == DONE:
            break
        if kind == "out":
            # xterm expects CRLF; normalize bare LFs from the child process.
            text = payload.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\n", "\r\n")
            await send(text)
        elif kind == "note":
            await send(f"\033[33m[ARGUS] {payload}\033[0m\r\n")
        else:  # err
            await send(f"\r\n\033[31m[ARGUS] {payload}\033[0m")


async def _run_pty(cmd: list[str], send: callable, timeout: int = 30) -> None:
    """Run command in a restricted PTY and stream output."""
    import ptyprocess

    def _set_limits():
        if HAS_RESOURCE:
            _resource.setrlimit(_resource.RLIMIT_NPROC, (64, 64))
            _resource.setrlimit(_resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))

    proc = ptyprocess.PtyProcess.spawn(cmd, preexec_fn=_set_limits, dimensions=(40, 200))
    loop = asyncio.get_event_loop()
    deadline = time.time() + timeout

    while proc.isalive() and time.time() < deadline:
        try:
            chunk = await loop.run_in_executor(None, lambda: proc.read(1024))
            if chunk:
                await send(chunk.decode("utf-8", errors="replace"))
        except EOFError:
            break
        await asyncio.sleep(0.05)

    if proc.isalive():
        proc.terminate(force=True)
        await send("\r\n\033[33m[ARGUS] Command timed out\033[0m")
