"""Shared cross-layer finding queries.

Layers consume each other's results to build a grounded attack chain. These
helpers centralise the "does an upstream layer provide vector X?" lookups so the
predicates stay consistent and auditable in one place.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.engine.state import ArgusState
    from app.models.finding import Finding


def _l4_agent_compromise(state: "ArgusState") -> list["Finding"]:
    """Exploitable L4 findings proving an agent issues attacker-controlled actions."""
    kws = ("hijack", "confused deputy", "tool call", "tool-call", "compromis", "steers agent")
    out = []
    for f in state.findings.values():
        if f.layer != 4 or not f.exploitable:
            continue
        if (f.owasp_ref or "").startswith("OWASP-AGT") or any(k in f.title.lower() for k in kws):
            out.append(f)
    return out
