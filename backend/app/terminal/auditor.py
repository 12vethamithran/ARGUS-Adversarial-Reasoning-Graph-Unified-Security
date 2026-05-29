"""Append-only JSONL audit log for terminal commands."""
from __future__ import annotations
import asyncio
import json
import time
from pathlib import Path
from app.config import settings


async def log_command(session_id: str, command: str, status: str, verdict_reason: str = "") -> None:
    log_dir = Path(settings.data_dir) / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    entry = {
        "ts": time.time(),
        "session_id": session_id,
        "command": command,
        "status": status,
        "reason": verdict_reason,
    }
    log_path = log_dir / f"{session_id}_audit.jsonl"
    line = json.dumps(entry) + "\n"
    # Atomic append
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, lambda: log_path.open("a").write(line))
