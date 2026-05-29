from __future__ import annotations
from typing import Any, Literal
from pydantic import BaseModel, Field
from app.models.finding import Finding
from app.models.chain import Chain


class ArgusState(BaseModel):
    session_id: str
    mode: Literal["basic", "advanced"] = "basic"
    target: dict[str, Any] = Field(default_factory=dict)
    active_layers: list[int] = Field(default_factory=lambda: [1, 2, 3])

    # Accumulated findings keyed by id
    findings: dict[str, Finding] = Field(default_factory=dict)
    chains: list[Chain] = Field(default_factory=list)

    # Reasoning log tokens
    reasoning_log: list[str] = Field(default_factory=list)

    # Which layers have completed
    completed_layers: list[int] = Field(default_factory=list)

    # Iteration guard
    iteration: int = 0
    max_iterations: int = 20

    error: str | None = None

    model_config = {"arbitrary_types_allowed": True}
