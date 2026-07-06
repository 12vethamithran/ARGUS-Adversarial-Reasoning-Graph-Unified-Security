"""Report routes — HTML, PDF (weasyprint), STIX 2.1 export."""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse

from app.config import settings
from app.storage import session_store
from app.storage.report_writer import (
    build_report_context,
    write_html_report,
    write_pdf_report,
    build_stix_bundle,
)

router = APIRouter()


async def _load_context(session_id: str) -> dict:
    """Load session data and build report context; raises 404 if not found."""
    session = await session_store.load_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")

    chains_data = await session_store.load_chains(session_id) or []
    audit_log = await session_store.load_audit(session_id)

    target = {**session.get("target", {}), "mode": session.get("mode")}
    findings = list(session.get("findings", {}).values())
    if findings and hasattr(findings[0], "model_dump"):
        findings = [f.model_dump() for f in findings]

    return build_report_context(
        session_id=session_id,
        target=target,
        findings=findings,
        chains=chains_data,
        audit_log=audit_log,
    )


@router.get("/{session_id}/html", response_class=HTMLResponse)
async def get_html_report(session_id: str):
    """Return rendered HTML threat report."""
    context = await _load_context(session_id)
    cached = Path(settings.data_dir) / "reports" / f"{session_id}_report.html"
    await write_html_report(session_id, context)
    import aiofiles
    async with aiofiles.open(cached) as fh:
        html = await fh.read()
    return HTMLResponse(content=html)


@router.get("/{session_id}/pdf")
async def get_pdf_report(session_id: str):
    """Return the downloadable analyst PDF threat report."""
    context = await _load_context(session_id)
    cached = Path(settings.data_dir) / "reports" / f"{session_id}_report.pdf"
    try:
        await write_pdf_report(session_id, context)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")
    return FileResponse(
        path=str(cached),
        media_type="application/pdf",
        filename=f"argus-analyst-report-{session_id[:8]}.pdf",
    )


@router.get("/{session_id}/stix")
async def get_stix_report(session_id: str):
    """Return STIX 2.1 JSON bundle."""
    session = await session_store.load_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    chains_data = await session_store.load_chains(session_id) or []
    target = {**session.get("target", {}), "mode": session.get("mode")}
    findings = list(session.get("findings", {}).values())
    if findings and hasattr(findings[0], "model_dump"):
        findings = [f.model_dump() for f in findings]
    bundle = build_stix_bundle(
        session_id=session_id,
        target=target,
        findings=findings,
        chains=chains_data,
    )
    return JSONResponse(
        content=bundle,
        headers={"Content-Disposition": f'attachment; filename="argus-stix-{session_id[:8]}.json"'},
    )


@router.post("/{session_id}/generate")
async def generate_reports(session_id: str):
    """Pre-generate and cache HTML + PDF for a completed session."""
    context = await _load_context(session_id)
    results: dict = {}
    try:
        path = await write_html_report(session_id, context)
        results["html"] = str(path)
    except Exception as e:
        results["html_error"] = str(e)
    try:
        path = await write_pdf_report(session_id, context)
        results["pdf"] = str(path)
    except Exception as e:
        results["pdf_error"] = str(e)
    return {"session_id": session_id, "generated": results}
