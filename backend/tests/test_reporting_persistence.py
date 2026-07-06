"""Regression: analysis results persist in the shape the report layer expects.

Before this, /api/analyze never wrote to session_store, so every /api/reports/*
call 404'd. The router (_persist) writes the dict shape asserted here; this test
locks in the store -> load -> build_report_context round-trip without importing
the FastAPI routers (not available in the test venv).
"""
import pytest

from app.storage import session_store
from app.storage.report_writer import build_report_context, write_pdf_report
from app.models.finding import Finding
from app.models.chain import Chain, Remediation


def _session_dict(sid, findings, chains):
    """Mirror of routers.analyze._persist's persisted shape."""
    return {
        "id": sid, "mode": "advanced", "status": "complete",
        "target": {"description": "agent app"},
        "findings": {f.id: f.model_dump() for f in findings},
        "chain_ids": [c.id for c in chains],
    }


@pytest.mark.asyncio
async def test_persist_then_build_report_context(tmp_path, monkeypatch):
    monkeypatch.setattr("app.config.settings.data_dir", str(tmp_path))

    f1 = Finding(layer=2, title="Indirect prompt injection", severity="critical",
                 owasp_ref="LLM01:2025", exploitable=True, confidence=0.9)
    f2 = Finding(layer=4, title="Tool-call hijack", severity="critical",
                 owasp_ref="OWASP-AGT-01", exploitable=True, confidence=0.88)
    chain = Chain(steps=[f1.id, f2.id], narrative="L2 -> L4",
                  exploitability=0.85, impact=0.9, novelty=0.8, priority=0.86,
                  remediations=[Remediation(layer=2, action="filter output", ref="LLM01:2025")])

    sid = "01TESTSESSION0000000000000"
    await session_store.save_session(sid, _session_dict(sid, [f1, f2], [chain]))
    await session_store.save_chains(sid, [chain.model_dump()])

    # Reload exactly as routers.report._load_context does.
    session = await session_store.load_session(sid)
    assert session is not None
    chains_data = await session_store.load_chains(sid) or []
    findings = list(session.get("findings", {}).values())

    ctx = build_report_context(
        session_id=sid, target=session["target"],
        findings=findings, chains=chains_data, audit_log=[],
    )
    assert ctx["session_id"] == sid
    assert "Tool-call hijack" in [f["title"] for f in ctx["findings"]]
    assert ctx["counts"]["critical"] == 2
    assert ctx["top_chain"]["priority"] == 0.86
    assert ctx["risk_score"] >= 80
    assert ctx["risk_rating"] == "CRITICAL"
    assert ctx["chains"][0]["step_findings"][0]["title"] == "Indirect prompt injection"
    assert ctx["findings"][0]["confidence_pct"] == 90
    assert ctx["layer_summary"][1]["name"] == "LLM Probe"


@pytest.mark.asyncio
async def test_write_pdf_report_creates_downloadable_pdf(tmp_path, monkeypatch):
    monkeypatch.setattr("app.config.settings.data_dir", str(tmp_path))

    finding = Finding(layer=2, title="Indirect prompt injection", severity="critical",
                      owasp_ref="LLM01:2025", exploitable=True, confidence=0.91)
    chain = Chain(steps=[finding.id], narrative="L2 prompt injection",
                  exploitability=0.9, impact=0.85, novelty=0.5, priority=0.88,
                  remediations=[Remediation(layer=2, action="filter retrieved content", ref="LLM01:2025")])
    sid = "01PDFTESTSESSION000000000"
    ctx = build_report_context(
        session_id=sid,
        target={"description": "https://example.test", "mode": "advanced"},
        findings=[finding.model_dump()],
        chains=[chain.model_dump()],
        audit_log=[],
    )

    path = await write_pdf_report(sid, ctx)

    assert path.exists()
    assert path.suffix == ".pdf"
    assert path.read_bytes().startswith(b"%PDF-")
    assert path.stat().st_size > 1000


@pytest.mark.asyncio
async def test_missing_session_loads_none(tmp_path, monkeypatch):
    monkeypatch.setattr("app.config.settings.data_dir", str(tmp_path))
    assert await session_store.load_session("nope") is None
    assert await session_store.load_chains("nope") is None
