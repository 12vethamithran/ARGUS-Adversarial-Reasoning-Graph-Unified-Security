from fastapi import APIRouter, HTTPException
from app.models import Session
from app.models.session import AnalysisTarget, AnalysisMode
from pydantic import BaseModel

router = APIRouter()

# In-memory store for now (replaced by storage/ in Step 3+)
_sessions: dict[str, Session] = {}


class CreateSessionBody(BaseModel):
    mode: AnalysisMode = "basic"
    target: AnalysisTarget
    layers: list[int] | None = None


@router.post("/", response_model=Session)
async def create_session(body: CreateSessionBody):
    session = Session(
        mode=body.mode,
        target=body.target,
        active_layers=body.layers or ([1, 2, 3] if body.mode == "basic" else list(range(1, 9))),
    )
    _sessions[session.id] = session
    return session


@router.get("/{session_id}", response_model=Session)
async def get_session(session_id: str):
    if session_id not in _sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    return _sessions[session_id]


@router.get("/", response_model=list[Session])
async def list_sessions():
    return list(_sessions.values())
