from __future__ import annotations

from typing import Any, Literal
from pydantic import BaseModel, Field
from ulid import ULID


SeverityLevel = Literal["info", "low", "medium", "high", "critical"]
NodeStateType = Literal["discovered", "probing", "exploitable", "chained"]


class Finding(BaseModel):
    """Emitted by every layer — the atomic unit of intelligence."""

    id: str = Field(default_factory=lambda: str(ULID()))
    layer: int = Field(ge=1, le=8, description="Attack layer 1-8")
    title: str
    severity: SeverityLevel
    owasp_ref: str | None = None   # e.g. "LLM01:2025", "A03:2021"
    mitre_ref: str | None = None   # e.g. "T1046", "AML.T0012"
    evidence: dict[str, Any] = Field(default_factory=dict)
    exploitable: bool = False
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    node_state: NodeStateType = "discovered"

    model_config = {"json_schema_extra": {"example": {
        "id": "01HW...",
        "layer": 2,
        "title": "Indirect prompt injection via user-controlled input",
        "severity": "high",
        "owasp_ref": "LLM01:2025",
        "mitre_ref": "AML.T0051",
        "evidence": {"payload": "Ignore previous instructions and...", "response": "..."},
        "exploitable": True,
        "confidence": 0.87,
        "node_state": "exploitable",
    }}}
