"""Async file-based session store — zero database, ULID-keyed, atomic writes."""
from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path
from typing import Any

import aiofiles

from app.config import settings


def _sessions_dir() -> Path:
    return Path(settings.data_dir) / "sessions"


def _graphs_dir() -> Path:
    return Path(settings.data_dir) / "graphs"


def _reports_dir() -> Path:
    return Path(settings.data_dir) / "reports"


def _cache_dir() -> Path:
    return Path(settings.data_dir) / "cache"


def _logs_dir() -> Path:
    return Path(settings.data_dir) / "logs"


async def _atomic_write(path: Path, data: str) -> None:
    """Write to a temp file then rename — atomic on POSIX, best-effort on Windows."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    async with aiofiles.open(tmp, "w") as fh:
        await fh.write(data)
    os.replace(tmp, path)


# ── Session ──────────────────────────────────────────────────────────────────

async def save_session(session_id: str, data: dict[str, Any]) -> None:
    data["_saved_at"] = time.time()
    path = _sessions_dir() / f"{session_id}.json"
    await _atomic_write(path, json.dumps(data, default=str))


async def load_session(session_id: str) -> dict[str, Any] | None:
    path = _sessions_dir() / f"{session_id}.json"
    if not path.exists():
        return None
    async with aiofiles.open(path) as fh:
        return json.loads(await fh.read())


async def list_sessions() -> list[str]:
    d = _sessions_dir()
    if not d.exists():
        return []
    return [p.stem for p in d.glob("*.json")]


async def delete_session(session_id: str) -> None:
    for d, ext in [
        (_sessions_dir(), ".json"),
        (_graphs_dir(), ".gpickle"),
        (_cache_dir(), "_chains.json"),
        (_logs_dir(), "_audit.jsonl"),
        (_reports_dir(), "_report.html"),
        (_reports_dir(), "_report.pdf"),
    ]:
        p = d / f"{session_id}{ext}"
        if p.exists():
            p.unlink()


# ── Chain cache ───────────────────────────────────────────────────────────────

async def save_chains(session_id: str, chains: list[dict]) -> None:
    path = _cache_dir() / f"{session_id}_chains.json"
    await _atomic_write(path, json.dumps(chains, default=str))


async def load_chains(session_id: str) -> list[dict] | None:
    path = _cache_dir() / f"{session_id}_chains.json"
    if not path.exists():
        return None
    async with aiofiles.open(path) as fh:
        return json.loads(await fh.read())


# ── Audit log ─────────────────────────────────────────────────────────────────

async def append_audit(session_id: str, entry: dict[str, Any]) -> None:
    path = _logs_dir() / f"{session_id}_audit.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps({**entry, "ts": time.time()}, default=str) + "\n"
    async with aiofiles.open(path, "a") as fh:
        await fh.write(line)


async def load_audit(session_id: str) -> list[dict]:
    path = _logs_dir() / f"{session_id}_audit.jsonl"
    if not path.exists():
        return []
    entries = []
    async with aiofiles.open(path) as fh:
        async for line in fh:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return entries


# ── TTL janitor ───────────────────────────────────────────────────────────────

SESSION_TTL_SECONDS = 60 * 60 * 24  # 24 hours


async def ttl_janitor() -> int:
    """Delete sessions older than TTL. Returns count of deleted sessions."""
    deleted = 0
    cutoff = time.time() - SESSION_TTL_SECONDS
    d = _sessions_dir()
    if not d.exists():
        return 0
    for path in d.glob("*.json"):
        try:
            if path.stat().st_mtime < cutoff:
                sid = path.stem
                await delete_session(sid)
                deleted += 1
        except OSError:
            pass
    return deleted


async def run_janitor_loop(interval_seconds: int = 3600) -> None:
    """Run janitor on a loop (call as background task)."""
    while True:
        await asyncio.sleep(interval_seconds)
        try:
            n = await ttl_janitor()
            if n:
                import structlog
                structlog.get_logger().info("janitor_cleaned", count=n)
        except Exception:
            pass
