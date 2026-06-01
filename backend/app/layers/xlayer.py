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


def _l1_injection(state: "ArgusState") -> list["Finding"]:
    """Exploitable L1 injection findings (SQLi/SSTI/cmdi/XSS/traversal).

    These are attacker-controlled input sinks that downstream layers can treat
    as confirmed entry points (e.g. an injectable param feeding an LLM context).
    """
    inj_families = {"sqli", "ssti", "cmdi", "xss", "traversal"}
    return [
        f for f in state.findings.values()
        if f.layer == 1 and f.exploitable
        and (f.evidence or {}).get("family") in inj_families
    ]


def _l1_ssrf(state: "ArgusState") -> list["Finding"]:
    """Exploitable L1 SSRF findings — a server-side fetch reaching internal hosts."""
    return [
        f for f in state.findings.values()
        if f.layer == 1 and f.exploitable
        and ((f.evidence or {}).get("family") == "ssrf")
    ]


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
