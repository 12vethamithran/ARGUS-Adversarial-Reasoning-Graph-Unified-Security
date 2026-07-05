"""Append-only JSONL audit log for terminal commands."""
from __future__ import annotations

from app.storage import session_store


async def log_command(session_id: str, command: str, status: str, verdict_reason: str = "") -> None:
    entry = {
        "session_id": session_id,
        "command": command,
        "status": status,
        "reason": verdict_reason,
    }
    try:
        await session_store.append_audit(session_id, entry)
    except ValueError:
        return
