"""L3 RAG poisoning — L2 -> L3 injection-persistence cross-layer wiring."""
import pytest

from app.layers.rag_poison import RAGPoisonLayer
from app.engine.state import ArgusState
from app.models.finding import Finding


def _state(target):
    return ArgusState(session_id="t", mode="advanced", target=target, active_layers=[2, 3])


def _l2_injection() -> Finding:
    return Finding(
        layer=2, title="Indirect prompt-injection channel: L1 reflected param 'q' reaches LLM context",
        severity="critical", owasp_ref="LLM01:2025", exploitable=True, confidence=0.84,
        evidence={"param": "q", "source_layer": 1},
    )


PERSIST = "injection persistence"


@pytest.mark.asyncio
async def test_persistence_when_rag_and_l2_injection():
    layer = RAGPoisonLayer()
    target = {"description": "support bot with a RAG knowledge base"}
    state = _state(target)
    f = _l2_injection()
    state.findings[f.id] = f

    results = await layer.run(target, state)
    persist = [r for r in results if PERSIST in r.title.lower()]
    assert persist, "expected an L2->L3 persistence finding"
    p = persist[0]
    assert p.layer == 3 and p.exploitable
    assert f.id in p.evidence["source_findings"]
    assert p.evidence["channels"] == ["q"]


@pytest.mark.asyncio
async def test_no_persistence_without_l2_injection():
    layer = RAGPoisonLayer()
    target = {"description": "support bot with a RAG knowledge base"}
    results = await layer.run(target, _state(target))
    assert not any(PERSIST in r.title.lower() for r in results)


@pytest.mark.asyncio
async def test_no_persistence_without_corpus():
    # No RAG signal -> no corpus to poison -> L3 bails before persistence logic.
    layer = RAGPoisonLayer()
    target = {"description": "a plain static website"}
    state = _state(target)
    f = _l2_injection()
    state.findings[f.id] = f
    results = await layer.run(target, state)
    assert not any(PERSIST in r.title.lower() for r in results)
