from __future__ import annotations

import time
from typing import Literal
from pydantic import BaseModel, Field
from ulid import ULID


SessionStatus = Literal["pending", "running", "complete", "error"]
AnalysisMode = Literal["basic", "advanced"]


class AnalysisTarget(BaseModel):
    url: str | None = None
    llm_endpoint: str | None = None
    description: str | None = None  # hypothetical target description
    manifest: str | None = None    # requirements.txt / package.json contents for real L6 scan


class Session(BaseModel):
    """Top-level session — the unit of storage."""

    id: str = Field(default_factory=lambda: str(ULID()))
    mode: AnalysisMode = "basic"
    target: AnalysisTarget
    status: SessionStatus = "pending"
    active_layers: list[int] = Field(
        default_factory=lambda: [1, 2, 3],
        description="Basic=1-3, Advanced=1-8 (configurable)"
    )
    finding_ids: list[str] = Field(default_factory=list)
    chain_ids: list[str] = Field(default_factory=list)
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)
    error: str | None = None

    def touch(self) -> None:
        self.updated_at = time.time()
