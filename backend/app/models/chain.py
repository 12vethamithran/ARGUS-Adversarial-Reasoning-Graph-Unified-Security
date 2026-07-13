from __future__ import annotations

from pydantic import BaseModel, Field
from ulid import ULID


class Remediation(BaseModel):
    layer: int = Field(ge=1, le=8)
    action: str
    ref: str  # OWASP or MITRE ID


class Chain(BaseModel):
    """Cross-layer attack chain produced by the reasoning engine."""

    id: str = Field(default_factory=lambda: str(ULID()))
    steps: list[str] = Field(description="Ordered list of Finding IDs")
    narrative: str = Field(description="Human-readable attack story")
    layer_path: list[int] = Field(default_factory=list, description="Ordered layer IDs represented by steps")
    reasoning: list[str] = Field(default_factory=list, description="Short reasoning trace for why the chain matters")
    exploitability: float = Field(ge=0.0, le=1.0)
    impact: float = Field(ge=0.0, le=1.0)
    novelty: float = Field(
        ge=0.0, le=1.0,
        description="High = technique not in published KB"
    )
    priority: float = Field(ge=0.0, le=1.0, description="Composite score")
    remediations: list[Remediation] = Field(default_factory=list)

    model_config = {"json_schema_extra": {"example": {
        "id": "01HW...",
        "steps": ["01HW_finding_1", "01HW_finding_2"],
        "narrative": "Attacker injects prompt via L1 web form -> LLM executes L5 network call",
        "layer_path": [1, 2, 5],
        "reasoning": ["Initial access reaches model context", "Agent action creates internal network impact"],
        "exploitability": 0.82,
        "impact": 0.91,
        "novelty": 0.74,
        "priority": 0.85,
        "remediations": [
            {"layer": 1, "action": "Sanitize all user inputs before passing to LLM", "ref": "A03:2021"},
            {"layer": 2, "action": "Implement output filtering and allow-listing", "ref": "LLM01:2025"},
        ],
    }}}
