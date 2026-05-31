"""L4 -> L7 (mesh seed) and L4 -> L8 (identity escalation) cross-layer wiring."""
import pytest

from app.layers.multi_agent import MultiAgentLayer
from app.layers.identity import IdentityLayer
from app.layers.xlayer import _l4_agent_compromise
from app.engine.state import ArgusState
from app.models.finding import Finding


def _state():
    return ArgusState(session_id="t", mode="advanced", target={"description": "agent mesh"},
                      active_layers=[4, 7, 8])


def _l4_compromise() -> Finding:
    return Finding(
        layer=4, title="Poisoned RAG context steers agent into unsafe tool call (injection -> tool-call hijack)",
        severity="critical", owasp_ref="OWASP-AGT-01", exploitable=True, confidence=0.88,
        evidence={"sink_tools": ["execute_shell"]},
    )


def test_l4_compromise_predicate():
    state = _state()
    f = _l4_compromise()
    state.findings[f.id] = f
    assert _l4_agent_compromise(state) == [f]
    # Non-exploitable L4 finding is not a compromise.
    g = Finding(layer=4, title="tool enumerated", severity="low", exploitable=False, confidence=0.5)
    state.findings[g.id] = g
    assert g not in _l4_agent_compromise(state)


@pytest.mark.asyncio
async def test_l7_seeds_from_l4_compromise():
    layer = MultiAgentLayer()
    state = _state()
    f = _l4_compromise()
    state.findings[f.id] = f
    results = await layer.run(state.target, state)
    seed = [r for r in results if "seeds prompt-infection" in r.title.lower()]
    assert seed and seed[0].exploitable and seed[0].layer == 7
    assert f.id in seed[0].evidence["source_findings"]


@pytest.mark.asyncio
async def test_l7_no_seed_without_l4():
    layer = MultiAgentLayer()
    results = await layer.run({"description": "agent mesh"}, _state())
    assert not any("seeds prompt-infection" in r.title.lower() for r in results)


@pytest.mark.asyncio
async def test_l8_escalation_from_l4_compromise():
    layer = IdentityLayer()
    state = _state()
    f = _l4_compromise()
    state.findings[f.id] = f
    results = await layer.run(state.target, state)
    esc = [r for r in results if "durable re-entry" in r.title.lower()]
    assert esc and esc[0].exploitable and esc[0].layer == 8
    assert f.id in esc[0].evidence["source_findings"]


@pytest.mark.asyncio
async def test_l8_no_escalation_without_l4():
    layer = IdentityLayer()
    results = await layer.run({"description": "agent mesh"}, _state())
    assert not any("durable re-entry" in r.title.lower() for r in results)
