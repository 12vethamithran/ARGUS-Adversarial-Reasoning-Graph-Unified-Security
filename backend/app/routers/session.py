from fastapi import APIRouter, HTTPException
from app.models import Session
from app.models.session import AnalysisTarget, AnalysisMode
from app.storage import session_store
from pydantic import BaseModel

router = APIRouter()


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
    await session_store.save_session(session.id, session.model_dump())
    return session


@router.get("/{session_id}", response_model=Session)
async def get_session(session_id: str):
    data = await session_store.load_session(session_id)
    if not data:
        raise HTTPException(status_code=404, detail="Session not found")
    try:
        return Session(**data)
    except Exception:
        # Sessions persisted by the analyze flow carry extra fields (findings,
        # etc.); surface them as a minimal valid Session for listing/lookup.
        raise HTTPException(status_code=422, detail="Session record is not a base session")


@router.get("/", response_model=list[Session])
async def list_sessions():
    out: list[Session] = []
    for sid in await session_store.list_sessions():
        data = await session_store.load_session(sid)
        if not data:
            continue
        try:
            out.append(Session(**data))
        except Exception:
            continue  # skip records that aren't base sessions (e.g. analyze dumps)
    return out
