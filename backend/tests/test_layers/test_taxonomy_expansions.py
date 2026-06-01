"""Regression tests for the expanded L2-L8 attack taxonomies.

These assert the new payload/scenario families are present, well-formed, and
(where deterministic) surfaced by the layer — guarding against accidental
removal during future edits.
"""
import pytest

from app.layers.llm_probe import INJECTION_PAYLOADS
from app.layers.mcp_agent import MCPAgentLayer, ATTACK_SCENARIOS
from app.layers.identity import OAUTH_CHECKS
from app.layers.rag_poison import ADVERSARIAL_DOCS
from app.layers.network import _ALL_ROLES, _PORTS_MAP
from app.engine.state import ArgusState


def test_l2_payload_families_expanded():
    fams = {p["family"] for p in INJECTION_PAYLOADS}
    for expected in ("jailbreak", "obfuscation", "splitting", "tool-exfil",
                     "output-handling", "multi-turn"):
        assert expected in fams, f"missing L2 family {expected}"
    ids = [p["id"] for p in INJECTION_PAYLOADS]
    assert len(ids) == len(set(ids)), "duplicate L2 payload ids"
    # Output-handling payload maps to LLM02 and carries a proof token.
    oh = next(p for p in INJECTION_PAYLOADS if p["family"] == "output-handling")
    assert oh["owasp"] == "LLM02:2025" and oh["proof"]


def test_l4_scenarios_well_formed():
    ids = [s["id"] for s in ATTACK_SCENARIOS]
    assert {"MCP-005", "MCP-006", "MCP-007"} <= set(ids)
    assert len(ids) == len(set(ids))
    for s in ATTACK_SCENARIOS:
        assert s["owasp"].startswith("OWASP-AGT")
        assert s["severity"] in ("info", "low", "medium", "high", "critical")


@pytest.mark.asyncio
async def test_l4_surfaces_new_scenarios():
    target = {"description": "an autonomous agent with MCP tools"}
    state = ArgusState(session_id="t", mode="advanced", target=target, active_layers=[4])
    results = await MCPAgentLayer().run(target, state)
    titles = " ".join(r.title for r in results)
    assert "MCP-006" in titles  # argument injection scenario emitted


def test_l8_checks_expanded():
    ids = [c["id"] for c in OAUTH_CHECKS]
    assert {"ID-006", "ID-007", "ID-008"} <= set(ids)
    for c in OAUTH_CHECKS:
        assert c["owasp_ref"]
        assert 0.0 <= c["confidence"] <= 1.0


def test_l3_docs_expanded():
    ids = [d["id"] for d in ADVERSARIAL_DOCS]
    assert {"ADV-004", "ADV-005", "ADV-006"} <= set(ids)
    techniques = {d["technique"] for d in ADVERSARIAL_DOCS}
    assert any("keyword" in t.lower() for t in techniques)


def test_l5_estate_expanded():
    for role in ("cache", "message-queue", "secrets-vault", "container-orchestrator"):
        assert role in _ALL_ROLES
        assert role in _PORTS_MAP and _PORTS_MAP[role]
