"""TTL janitor: expired sessions are reaped, fresh ones survive."""
import os
import time

import pytest

from app.storage import session_store


@pytest.mark.asyncio
async def test_ttl_janitor_reaps_only_expired(tmp_path, monkeypatch):
    monkeypatch.setattr("app.config.settings.data_dir", str(tmp_path))
    monkeypatch.setattr("app.config.settings.session_ttl_hours", 24)

    await session_store.save_session("old", {"id": "old"})
    await session_store.save_session("fresh", {"id": "fresh"})

    # Age "old" past the 24h TTL by backdating its mtime.
    old_path = tmp_path / "sessions" / "old.json"
    stale = time.time() - 25 * 3600
    os.utime(old_path, (stale, stale))

    deleted = await session_store.ttl_janitor()

    assert deleted == 1
    assert await session_store.load_session("old") is None
    assert await session_store.load_session("fresh") is not None


@pytest.mark.asyncio
async def test_ttl_respects_configured_hours(tmp_path, monkeypatch):
    monkeypatch.setattr("app.config.settings.data_dir", str(tmp_path))
    monkeypatch.setattr("app.config.settings.session_ttl_hours", 1)  # tight TTL

    await session_store.save_session("s", {"id": "s"})
    p = tmp_path / "sessions" / "s.json"
    stale = time.time() - 2 * 3600  # 2h old > 1h TTL
    os.utime(p, (stale, stale))

    assert await session_store.ttl_janitor() == 1
