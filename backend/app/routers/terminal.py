"""Terminal WebSocket route — PTY bridge with whitelist enforcement."""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.terminal.pty_bridge import PTYSession, BANNER, PROMPT

router = APIRouter()
_sessions: dict[str, PTYSession] = {}


@router.websocket("/terminal/{session_id}")
async def terminal_ws(websocket: WebSocket, session_id: str):
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
