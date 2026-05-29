"""Generate HTML + PDF reports from session data using Jinja2 + weasyprint."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import aiofiles

from app.config import settings

_TEMPLATE_DIR = Path(__file__).parent.parent / "templates"
_REPORTS_DIR_FUNC = lambda: Path(settings.data_dir) / "reports"


def _render_html(context: dict[str, Any]) -> str:
    """Render the Jinja2 report template."""
    from jinja2 import Environment, FileSystemLoader, select_autoescape

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html.j2")
    return template.render(**context)


async def write_html_report(session_id: str, context: dict[str, Any]) -> Path:
    """Render and persist HTML report. Returns path."""
    html = _render_html(context)
    out = _REPORTS_DIR_FUNC() / f"{session_id}_report.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    async with aiofiles.open(out, "w") as fh:
        await fh.write(html)
    return out


async def write_pdf_report(session_id: str, context: dict[str, Any]) -> Path:
    """Render HTML and convert to PDF via weasyprint. Returns path."""
    try:
        from weasyprint import HTML as WPHtml
    except ImportError:
        raise RuntimeError("weasyprint not installed — run: pip install weasyprint")

    html = _render_html(context)
    out = _REPORTS_DIR_FUNC() / f"{session_id}_report.pdf"
    out.parent.mkdir(parents=True, exist_ok=True)
    WPHtml(string=html, base_url=str(_TEMPLATE_DIR)).write_pdf(str(out))
    return out


def build_report_context(
    session_id: str,
    target: dict[str, Any],
    findings: list[dict],
    chains: list[dict],
    audit_log: list[dict],
) -> dict[str, Any]:
    """Build the Jinja2 context dict for the report template."""
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "info"), 5))

    counts = {s: sum(1 for f in findings if f.get("severity") == s)
              for s in ["critical", "high", "medium", "low", "info"]}

    top_chain = max(chains, key=lambda c: c.get("priority", 0), default=None) if chains else None

    return {
        "session_id": session_id,
        "generated_at": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
        "target": target,
        "findings": sorted_findings,
        "chains": chains,
        "top_chain": top_chain,
        "audit_log": audit_log,
        "counts": counts,
        "total_findings": len(findings),
        "exploitable_count": sum(1 for f in findings if f.get("exploitable")),
    }


# ── STIX 2.1 export ──────────────────────────────────────────────────────────

def build_stix_bundle(
    session_id: str,
    target: dict[str, Any],
    findings: list[dict],
    chains: list[dict],
) -> dict[str, Any]:
    """
    Build a minimal STIX 2.1 bundle.
    Each finding -> Indicator; each chain -> Attack-Pattern + Relationship.
    """
    objects: list[dict] = []
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    # Identity object for ARGUS
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": f"identity--argus-{session_id[:8]}",
        "created": now,
        "modified": now,
        "name": "ARGUS Reasoning Engine",
        "identity_class": "system",
    }
    objects.append(identity)

    # Findings -> Indicators
    finding_stix_ids: dict[str, str] = {}
    for f in findings:
        stix_id = f"indicator--{f['id']}"
        finding_stix_ids[f["id"]] = stix_id
        refs = []
        if f.get("owasp_ref"):
            refs.append(f"OWASP: {f['owasp_ref']}")
        if f.get("mitre_ref"):
            refs.append(f"MITRE: {f['mitre_ref']}")
        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": stix_id,
            "created": now,
            "modified": now,
            "name": f["title"],
            "description": f"Layer {f['layer']} finding. Severity: {f['severity']}. "
                           + (f"References: {', '.join(refs)}." if refs else ""),
            "pattern": f"[argus:finding_id = '{f['id']}']",
            "pattern_type": "stix",
            "valid_from": now,
            "labels": [f["severity"], f"layer-{f['layer']}"],
            "confidence": int(f.get("confidence", 0.5) * 100),
        }
        objects.append(indicator)

    # Chains -> Attack Patterns + Relationships
    for chain in chains:
        ap_id = f"attack-pattern--{chain['id']}"
        ap = {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": ap_id,
            "created": now,
            "modified": now,
            "name": f"ARGUS Chain {chain['id'][:8]}",
            "description": chain.get("narrative", ""),
            "x_argus_exploitability": chain.get("exploitability"),
            "x_argus_impact": chain.get("impact"),
            "x_argus_novelty": chain.get("novelty"),
            "x_argus_priority": chain.get("priority"),
        }
        objects.append(ap)

        for fid in chain.get("steps", []):
            stix_fid = finding_stix_ids.get(fid)
            if stix_fid:
                rel = {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": f"relationship--{fid}-{chain['id'][:8]}",
                    "created": now,
                    "modified": now,
                    "relationship_type": "indicates",
                    "source_ref": stix_fid,
                    "target_ref": ap_id,
                }
                objects.append(rel)

    return {
        "type": "bundle",
        "id": f"bundle--argus-{session_id}",
        "spec_version": "2.1",
        "objects": objects,
    }
