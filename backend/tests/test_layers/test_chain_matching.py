"""Verify new L1 attacks (SQLi etc.) flow into the L1->L2 bridge and into chains.

Confirms the reasoning/chain engine correctly incorporates the expanded L1
findings and that cross-layer wiring references the real upstream finding.
"""
import pytest
from unittest.mock import AsyncMock, patch

from app.layers.llm_probe import LLMProbeLayer
from app.engine.state import ArgusState
from app.engine.reasoner import _heuristic_chains
from app.engine.graph_builder import build_graph
from app.models.finding import Finding


def _sqli_finding() -> Finding:
    return Finding(
        layer=1, title="EXPLOITED: Single-quote error probe [SQLI-E1] via 'id'",
        severity="critical", owasp_ref="A03:2021", mitre_ref="T1190",
        exploitable=True, confidence=0.85,
        evidence={"param": "id", "url": "http://shop.example/item?id=1",
                  "family": "sqli", "technique": "error-based", "payload_id": "SQLI-E1"},
    )


@pytest.mark.asyncio
async def test_l1_sqli_feeds_l2_indirect_injection():
    """A confirmed L1 SQLi param becomes a high-confidence L2 injection channel."""
    target = {"description": "a customer-support chatbot powered by an LLM",
              "url": "http://shop.example/item?id=1"}
    state = ArgusState(session_id="t", mode="basic", target=target, active_layers=[1, 2])
    sqli = _sqli_finding()
    state.findings[sqli.id] = sqli

    # L2 verification re-requests the channel; keep it offline.
    with patch("httpx.AsyncClient.get", AsyncMock(side_effect=RuntimeError("offline"))), \
         patch.object(LLMProbeLayer, "_discover_endpoint",
                      AsyncMock(return_value=(None, None, None))):
        results = await LLMProbeLayer().run(target, state)

    bridges = [f for f in results
               if f.layer == 2 and "id" in (f.evidence or {}).get("param", "")
               and f.evidence.get("source_layer") == 1]
    assert bridges, "expected an L1->L2 indirect-injection bridge from the SQLi param"
    b = bridges[0]
    assert b.exploitable and b.owasp_ref == "LLM01:2025"
    # Confirmed-injection channel gets the high-confidence base (~0.9 +/- jitter).
    assert b.confidence >= 0.82


@pytest.mark.asyncio
async def test_chain_includes_l1_attack_and_bridge():
    """The heuristic chain builder forms a cross-layer chain over the new findings."""
    sqli = _sqli_finding()
    bridge = Finding(
        layer=2, title="Indirect prompt-injection channel: L1 reflected param 'id' reaches LLM context",
        severity="critical", owasp_ref="LLM01:2025", mitre_ref="AML.T0051",
        exploitable=True, confidence=0.9,
        evidence={"param": "id", "source_layer": 1},
    )
    findings = [sqli, bridge]
    chains = _heuristic_chains(findings, lambda t: None)
    assert chains, "expected at least one chain"
    primary = chains[0]
    assert sqli.id in primary.steps and bridge.id in primary.steps
    # Remediations cite the real OWASP refs of the chained attacks.
    refs = {r.ref for r in primary.remediations}
    assert "A03:2021" in refs and "LLM01:2025" in refs

    # Graph wires the chain steps as edges.
    G = build_graph(findings, chains)
    assert G.number_of_nodes() == 2 and G.number_of_edges() >= 1
