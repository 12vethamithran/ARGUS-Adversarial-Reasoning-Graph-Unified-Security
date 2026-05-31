"""L4 MCP/Agentic — L3 -> L4 poisoned-context -> tool-call hijack wiring."""
import pytest

from app.layers.mcp_agent import MCPAgentLayer
from app.engine.state import ArgusState
from app.models.finding import Finding


def _state(target):
    return ArgusState(session_id="t", mode="advanced", target=target, active_layers=[3, 4])


def _l3_poison() -> Finding:
    return Finding(
        layer=3, title="Retrieval displacement confirmed: 2/3 adversarial docs rank above benign",
        severity="critical", owasp_ref="LLM08:2025", exploitable=True, confidence=0.89,
        evidence={"doc_id": "ADV-001"},
    )


HIJACK = "poisoned rag context steers agent"


@pytest.mark.asyncio
async def test_l3_poison_drives_tool_call():
    layer = MCPAgentLayer()
    target = {"description": "an autonomous agent with MCP tools"}
    state = _state(target)
    f = _l3_poison()
    state.findings[f.id] = f

    results = await layer.run(target, state)
    hij = [r for r in results if HIJACK in r.title.lower()]
    assert hij, "expected an L3->L4 tool-call hijack finding"
    h = hij[0]
    assert h.layer == 4 and h.exploitable
    assert f.id in h.evidence["source_findings"]
    # Sinks are dangerous, unvalidated tools (read_file is read-only -> excluded).
    assert "execute_shell" in h.evidence["sink_tools"]
    assert "read_file" not in h.evidence["sink_tools"]


@pytest.mark.asyncio
async def test_no_hijack_without_l3_poison():
    layer = MCPAgentLayer()
    target = {"description": "an autonomous agent with MCP tools"}
    results = await layer.run(target, _state(target))
    assert not any(HIJACK in r.title.lower() for r in results)


@pytest.mark.asyncio
async def test_no_agent_surface_short_circuits():
    layer = MCPAgentLayer()
    target = {"description": "a plain static website"}
    state = _state(target)
    f = _l3_poison()
    state.findings[f.id] = f
    # L3 poison title mentions neither agent/tool/mcp, so no agent surface -> bail.
    results = await layer.run(target, state)
    assert not any(HIJACK in r.title.lower() for r in results)
