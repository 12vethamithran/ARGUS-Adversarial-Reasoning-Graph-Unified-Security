"""Tests for the unified orchestrator generator + conditional dependency gating.

These lock in the behaviour that the live SSE path now relies on: the
orchestrator is the single event source, and a layer is skipped when its
prerequisite layers produced nothing exploitable.
"""
import pytest

from app.engine import orchestrator as orch
from app.engine.state import ArgusState
from app.models.finding import Finding


class _StubLayer:
    """Returns a fixed finding list, mimicking BaseLayer.run."""
    def __init__(self, layer_id: int, exploitable: bool):
        self.layer_id = layer_id
        self._exploitable = exploitable

    async def run(self, target, state):
        return [Finding(
            layer=self.layer_id, title=f"L{self.layer_id} stub",
            severity="high" if self._exploitable else "info",
            exploitable=self._exploitable, confidence=0.8,
        )]


class _WeakExploitLayer:
    """Emits an exploitable raw finding that should be downgraded by calibration."""
    def __init__(self, layer_id: int):
        self.layer_id = layer_id

    async def run(self, target, state):
        return [Finding(
            layer=self.layer_id,
            title="Weak SQLi",
            severity="critical",
            exploitable=True,
            confidence=0.85,
            evidence={"family": "sqli", "verdict": "suspicious"},
        )]


def _collect(events):
    tokens = "".join(
        (e.payload or {}).get("token", "") for e in events if e.type == "reasoning_token"
    )
    layers_done = [e.payload["layer"] for e in events if e.type == "layer_done"]
    return tokens, layers_done


async def _drive(state):
    return [ev async for ev in orch.run_orchestrator(state)]


@pytest.mark.asyncio
async def test_terminates_with_complete(monkeypatch):
    monkeypatch.setattr(orch, "_import_layer", lambda lid: _StubLayer(lid, False))
    state = ArgusState(session_id="t", mode="basic", target={}, active_layers=[1])
    events = await _drive(state)
    assert events[-1].type == "complete"


@pytest.mark.asyncio
async def test_invalid_layers_emit_error_and_complete():
    state = ArgusState(session_id="t", mode="advanced", target={}, active_layers=[99, 99])
    events = await _drive(state)

    assert events[0].type == "error"
    assert events[0].payload["message"] == "No valid layers selected."
    assert events[-1].type == "complete"


@pytest.mark.asyncio
async def test_skips_layer_when_prereq_not_exploitable(monkeypatch):
    # L2 yields nothing exploitable -> L3 and L4 must skip (and L7/L8 transitively).
    monkeypatch.setattr(orch, "_import_layer", lambda lid: _StubLayer(lid, exploitable=False))
    state = ArgusState(session_id="t", mode="advanced", target={},
                       active_layers=[1, 2, 3, 4, 7, 8])
    events = await _drive(state)
    tokens, layers_done = _collect(events)

    assert "L3 (RAG Poisoning) skipped" in tokens
    assert "L4 (MCP/Agentic) skipped" in tokens
    assert "L7 (Multi-Agent) skipped" in tokens
    assert "L8 (Identity/OAuth) skipped" in tokens
    # Skipped layers still emit layer_done so the frontend progress advances.
    assert set(layers_done) == {1, 2, 3, 4, 7, 8}


@pytest.mark.asyncio
async def test_runs_dependent_layer_when_prereq_exploitable(monkeypatch):
    # L2 exploitable -> L3/L4 run; L4 exploitable -> L7/L8 run.
    monkeypatch.setattr(orch, "_import_layer", lambda lid: _StubLayer(lid, exploitable=True))
    state = ArgusState(session_id="t", mode="advanced", target={},
                       active_layers=[1, 2, 3, 4, 7, 8])
    events = await _drive(state)
    tokens, _ = _collect(events)

    assert "skipped" not in tokens
    # Every active layer ran and recorded completion.
    assert state.completed_layers == [1, 2, 3, 4, 7, 8]
    assert "Summary:" in tokens


@pytest.mark.asyncio
async def test_calibration_prevents_weak_findings_unlocking_deps(monkeypatch):
    monkeypatch.setattr(orch, "_import_layer", lambda lid: _WeakExploitLayer(lid))
    state = ArgusState(session_id="t", mode="advanced", target={},
                       active_layers=[2, 3])
    events = await _drive(state)
    tokens, _ = _collect(events)

    assert "L3 (RAG Poisoning) skipped" in tokens
    l2_findings = [f for f in state.findings.values() if f.layer == 2]
    assert l2_findings and not l2_findings[0].exploitable
    assert l2_findings[0].evidence["decision"]["adjusted"]
