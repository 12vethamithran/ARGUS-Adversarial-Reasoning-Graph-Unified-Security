"""Terminal WebSocket route - PTY bridge with whitelist enforcement."""
from __future__ import annotations

import re

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.config import settings
from app.storage.session_store import validate_session_id
from app.terminal.pty_bridge import BANNER, PROMPT, PTYSession

router = APIRouter()
_sessions: dict[str, PTYSession] = {}
_DEV_ORIGIN_RE = re.compile(r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$")


def _origin_allowed(origin: str | None) -> bool:
    allowed = settings.get_allowed_origins()
    if allowed == ["*"]:
        return True
    if not origin:
        return False
    return origin in allowed or bool(_DEV_ORIGIN_RE.fullmatch(origin))


@router.websocket("/terminal/{session_id}")
async def terminal_ws(websocket: WebSocket, session_id: str):
    try:
        session_id = validate_session_id(session_id)
    except ValueError:
        await websocket.close(code=1008)
        return

    if not _origin_allowed(websocket.headers.get("origin")):
        await websocket.close(code=1008)
        return

    await websocket.accept()
    session = PTYSession(session_id)
    _sessions[session_id] = session

    await websocket.send_text(BANNER)
    await websocket.send_text(PROMPT)

    try:
        while True:
            if session.is_idle():
                await websocket.send_text("\r\n\033[33m[ARGUS] Session timed out (idle)\033[0m\r\n")
                break
            data = await websocket.receive_text()
            await session.handle_input(data, websocket.send_text)
    except WebSocketDisconnect:
        pass
    finally:
        _sessions.pop(session_id, None)
