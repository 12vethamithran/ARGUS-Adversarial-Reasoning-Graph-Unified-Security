from __future__ import annotations

import time
from typing import Any, Literal
from pydantic import BaseModel, Field


EventType = Literal[
    "node_state",
    "reasoning_token",
    "chain_found",
    "layer_done",
    "error",
    "complete",
]


class NodeState(BaseModel):
    finding_id: str
    state: Literal["discovered", "probing", "exploitable", "chained"]


class StreamEvent(BaseModel):
    """SSE payload pushed from astream_events to the frontend."""

    type: EventType
    payload: dict[str, Any] = Field(default_factory=dict)
    ts: float = Field(default_factory=time.time)

    @classmethod
    def node_state(cls, finding_id: str, state: str) -> "StreamEvent":
        return cls(type="node_state", payload={"finding_id": finding_id, "state": state})

    @classmethod
    def reasoning_token(cls, token: str) -> "StreamEvent":
        return cls(type="reasoning_token", payload={"token": token})

    @classmethod
    def chain_found(cls, chain: dict) -> "StreamEvent":
        return cls(type="chain_found", payload=chain)

    @classmethod
    def layer_done(cls, layer: int, finding_count: int) -> "StreamEvent":
        return cls(type="layer_done", payload={"layer": layer, "finding_count": finding_count})

    @classmethod
    def error(cls, message: str) -> "StreamEvent":
        return cls(type="error", payload={"message": message})

    @classmethod
    def complete(cls, session_id: str) -> "StreamEvent":
        return cls(type="complete", payload={"session_id": session_id})
