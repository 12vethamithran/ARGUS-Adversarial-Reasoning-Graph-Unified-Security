"""Generate HTML + PDF reports from session data using Jinja2 + weasyprint."""
from __future__ import annotations

import json
import time
from html import escape
from pathlib import Path
from typing import Any

import aiofiles

from app.config import settings
from app.storage.session_store import validate_session_id

_TEMPLATE_DIR = Path(__file__).parent.parent / "templates"
_REPORTS_DIR_FUNC = lambda: Path(settings.data_dir) / "reports"

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEVERITY_WEIGHT = {"critical": 1.0, "high": 0.78, "medium": 0.55, "low": 0.3, "info": 0.1}
_LAYER_NAMES = {
    1: "Web Surface",
    2: "LLM Probe",
    3: "RAG Poisoning",
    4: "MCP / Agentic",
    5: "Network Recon",
    6: "Supply Chain",
    7: "Multi-Agent Propagation",
    8: "Identity / OAuth",
}
_LAYER_DOMAINS = {
    1: "Web",
    2: "AI / LLM",
    3: "AI / LLM",
    4: "AI / LLM",
    5: "Infrastructure",
    6: "Infrastructure",
    7: "AI / LLM",
    8: "Identity",
}


def _pct(value: Any) -> int:
    try:
        return max(0, min(100, round(float(value) * 100)))
    except Exception:
        return 0


def _risk_score(findings: list[dict]) -> int:
    if not findings:
        return 0
    max_sev = max(_SEVERITY_WEIGHT.get(f.get("severity", "info"), 0.1) for f in findings)
    exploitable = sum(1 for f in findings if f.get("exploitable"))
    breadth = len({f.get("layer") for f in findings if f.get("layer")})
    score = max_sev * 60 + min(exploitable * 8, 24) + min(breadth * 3, 16)
    return min(100, round(score))


def _risk_rating(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MODERATE"
    if score > 0:
        return "LOW"
    return "INFORMATIONAL"


def _chain_rating(priority: float) -> str:
    if priority >= 0.85:
        return "Critical chain"
    if priority >= 0.70:
        return "High-priority chain"
    if priority >= 0.50:
        return "Moderate chain"
    return "Low-priority chain"


def _severity_rationale(finding: dict) -> str:
    severity = finding.get("severity", "info")
    confidence = _pct(finding.get("confidence", 0))
    exploitable = "confirmed exploitable" if finding.get("exploitable") else "not directly exploitable"
    return f"{severity.upper()} severity with {confidence}% confidence; {exploitable}."


def _short_evidence(evidence: dict[str, Any], limit: int = 6) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for key, value in (evidence or {}).items():
        if key == "mock":
            continue
        if isinstance(value, (dict, list)):
            rendered = json.dumps(value, default=str)[:260]
        else:
            rendered = str(value)[:260]
        out.append({"key": key, "value": rendered})
        if len(out) >= limit:
            break
    return out


def _enrich_findings(findings: list[dict]) -> list[dict]:
    enriched = []
    for finding in findings:
        f = dict(finding)
        layer = int(f.get("layer") or 0)
        f["layer_name"] = _LAYER_NAMES.get(layer, f"Layer {layer}")
        f["layer_domain"] = _LAYER_DOMAINS.get(layer, "Unknown")
        f["confidence_pct"] = _pct(f.get("confidence", 0))
        f["severity_rank"] = _SEVERITY_ORDER.get(f.get("severity", "info"), 5)
        f["severity_rationale"] = _severity_rationale(f)
        f["evidence_items"] = _short_evidence(f.get("evidence") or {})
        decision = (f.get("evidence") or {}).get("decision") or {}
        f["decision_reason"] = decision.get("reason", "")
        f["decision_strength"] = decision.get("strength", "")
        enriched.append(f)
    return enriched


def _enrich_chains(chains: list[dict], finding_by_id: dict[str, dict]) -> list[dict]:
    enriched = []
    for index, chain in enumerate(chains, start=1):
        c = dict(chain)
        c["index"] = index
        c["priority_pct"] = _pct(c.get("priority", 0))
        c["exploitability_pct"] = _pct(c.get("exploitability", 0))
        c["impact_pct"] = _pct(c.get("impact", 0))
        c["novelty_pct"] = _pct(c.get("novelty", 0))
        c["rating"] = _chain_rating(float(c.get("priority", 0) or 0))
        c["step_findings"] = [
            finding_by_id[fid] for fid in c.get("steps", []) if fid in finding_by_id
        ]
        c["affected_layers"] = sorted({f["layer"] for f in c["step_findings"]})
        c["affected_domains"] = sorted({f["layer_domain"] for f in c["step_findings"]})
        enriched.append(c)
    return sorted(enriched, key=lambda c: c.get("priority", 0), reverse=True)


def _layer_summary(findings: list[dict]) -> list[dict]:
    rows = []
    for layer in range(1, 9):
        fs = [f for f in findings if f.get("layer") == layer]
        rows.append({
            "layer": layer,
            "name": _LAYER_NAMES[layer],
            "domain": _LAYER_DOMAINS[layer],
            "count": len(fs),
            "exploitable": sum(1 for f in fs if f.get("exploitable")),
            "max_severity": min((f.get("severity_rank", 5) for f in fs), default=5),
            "highest": next(iter(sorted(fs, key=lambda f: f.get("severity_rank", 5))), None),
        })
    return rows


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
    session_id = validate_session_id(session_id)
    html = _render_html(context)
    out = _REPORTS_DIR_FUNC() / f"{session_id}_report.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    async with aiofiles.open(out, "w") as fh:
        await fh.write(html)
    return out


def _safe_text(value: Any) -> str:
    if value is None or value == "":
        return "Not available"
    return escape(str(value))


def _build_reportlab_pdf(out: Path, context: dict[str, Any], renderer_note: str = "") -> None:
    """Build the analyst PDF with ReportLab."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:
        raise RuntimeError("reportlab is not installed") from exc

    def p(value: Any, style: Any) -> Any:
        text = _safe_text(value).replace("\n", "<br/>")
        return Paragraph(text, style)

    def footer(canvas: Any, doc: Any) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.drawString(18 * mm, 10 * mm, "ARGUS Analyst Report")
        canvas.drawRightString(192 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="CoverTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=24,
        leading=28,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=14,
    ))
    styles.add(ParagraphStyle(
        name="Section",
        parent=styles["Heading2"],
        fontSize=15,
        leading=18,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=12,
        spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name="Small",
        parent=styles["BodyText"],
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#475569"),
    ))
    styles.add(ParagraphStyle(
        name="Cell",
        parent=styles["BodyText"],
        fontSize=8,
        leading=10,
    ))
    styles.add(ParagraphStyle(
        name="HeaderCell",
        parent=styles["Cell"],
        textColor=colors.white,
    ))

    story: list[Any] = []
    target = context.get("target") or {}
    findings = context.get("findings") or []
    chains = context.get("chains") or []
    layer_summary = context.get("layer_summary") or []
    counts = context.get("counts") or {}

    story.append(p("ARGUS Analyst Attack Report", styles["CoverTitle"]))
    story.append(p(target.get("description", "Unknown target"), styles["Heading2"]))
    story.append(p(context.get("analyst_verdict", ""), styles["BodyText"]))
    story.append(Spacer(1, 8))
    story.append(Table(
        [
            [p("Risk rating", styles["Cell"]), p(context.get("risk_rating"), styles["Cell"])],
            [p("Risk score", styles["Cell"]), p(f"{context.get('risk_score', 0)}/100", styles["Cell"])],
            [p("Findings", styles["Cell"]), p(context.get("total_findings"), styles["Cell"])],
            [p("Exploitable", styles["Cell"]), p(context.get("exploitable_count"), styles["Cell"])],
            [p("Attack chains", styles["Cell"]), p(len(chains), styles["Cell"])],
            [p("Generated", styles["Cell"]), p(context.get("generated_at"), styles["Cell"])],
        ],
        colWidths=[44 * mm, 110 * mm],
    ))
    story[-1].setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef2ff")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    if renderer_note:
        story.append(Spacer(1, 8))
        story.append(p(f"Renderer note: {renderer_note}", styles["Small"]))

    story.append(PageBreak())
    story.append(p("Executive Overview", styles["Section"]))
    severity_rows = [[p("Severity", styles["HeaderCell"]), p("Count", styles["HeaderCell"])]]
    for severity in ["critical", "high", "medium", "low", "info"]:
        severity_rows.append([p(severity.upper(), styles["Cell"]), p(counts.get(severity, 0), styles["Cell"])])
    story.append(Table(severity_rows, colWidths=[80 * mm, 40 * mm]))
    story[-1].setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))

    story.append(p("Layer Coverage", styles["Section"]))
    layer_rows = [[
        p("Layer", styles["HeaderCell"]),
        p("Domain", styles["HeaderCell"]),
        p("Findings", styles["HeaderCell"]),
        p("Highest signal", styles["HeaderCell"]),
    ]]
    for layer in layer_summary:
        highest = layer.get("highest") or {}
        layer_rows.append([
            p(f"L{layer.get('layer')} - {layer.get('name')}", styles["Cell"]),
            p(layer.get("domain"), styles["Cell"]),
            p(f"{layer.get('count', 0)} ({layer.get('exploitable', 0)} exploitable)", styles["Cell"]),
            p(highest.get("title", "None"), styles["Cell"]),
        ])
    story.append(Table(layer_rows, colWidths=[45 * mm, 33 * mm, 32 * mm, 55 * mm], repeatRows=1))
    story[-1].setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))

    story.append(p("Attack Chain Walkthrough", styles["Section"]))
    if not chains:
        story.append(p("No cross-layer attack chain was produced for this session.", styles["BodyText"]))
    for chain in chains:
        story.append(p(
            f"Chain {chain.get('index')}: {chain.get('rating')} - priority {chain.get('priority_pct')}%",
            styles["Heading3"],
        ))
        story.append(p(chain.get("narrative"), styles["BodyText"]))
        story.append(p(
            f"Exploitability {chain.get('exploitability_pct')}% | Impact {chain.get('impact_pct')}% | Novelty {chain.get('novelty_pct')}%",
            styles["Small"],
        ))
        for step in chain.get("step_findings") or []:
            story.append(p(
                f"L{step.get('layer')} {step.get('layer_name')}: {step.get('title')} "
                f"({str(step.get('severity', '')).upper()}, confidence {step.get('confidence_pct')}%)",
                styles["Cell"],
            ))
        if chain.get("remediations"):
            for remediation in chain.get("remediations"):
                story.append(p(
                    f"Remediate L{remediation.get('layer')}: {remediation.get('action')} [{remediation.get('ref')}]",
                    styles["Small"],
                ))
        story.append(Spacer(1, 5))

    story.append(PageBreak())
    story.append(p("Finding Detail and Analyst Rating", styles["Section"]))
    for finding in findings:
        story.append(p(
            f"{finding.get('title')} - {str(finding.get('severity', '')).upper()}",
            styles["Heading3"],
        ))
        story.append(p(
            f"L{finding.get('layer')} {finding.get('layer_name')} | {finding.get('layer_domain')} | "
            f"Confidence {finding.get('confidence_pct')}% | Exploitable: {finding.get('exploitable')}",
            styles["Small"],
        ))
        story.append(p(finding.get("severity_rationale"), styles["BodyText"]))
        if finding.get("decision_reason"):
            story.append(p(
                f"Decision: {finding.get('decision_reason')} ({finding.get('decision_strength') or 'unspecified'} strength)",
                styles["BodyText"],
            ))
        for item in finding.get("evidence_items") or []:
            story.append(p(f"{item.get('key')}: {item.get('value')}", styles["Small"]))
        story.append(Spacer(1, 6))

    story.append(p("Terminal Validation Audit", styles["Section"]))
    audit = context.get("audit_log") or []
    if not audit:
        story.append(p("No terminal validation commands were recorded for this session.", styles["BodyText"]))
    else:
        for entry in audit[-20:]:
            story.append(p(
                f"{entry.get('timestamp', '')} | {entry.get('status', '')} | {entry.get('command', entry)}",
                styles["Small"],
            ))

    doc = SimpleDocTemplate(
        str(out),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=16 * mm,
        title="ARGUS Analyst Attack Report",
    )
    doc.build(story, onFirstPage=footer, onLaterPages=footer)


def _pdf_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _wrap_line(value: Any, width: int = 92) -> list[str]:
    words = str(value or "Not available").replace("\n", " ").split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) > width and current:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    return lines or ["Not available"]


def _build_plain_pdf(out: Path, context: dict[str, Any], renderer_note: str) -> None:
    """Last-resort PDF writer with no third-party runtime dependencies."""
    target = context.get("target") or {}
    findings = context.get("findings") or []
    chains = context.get("chains") or []
    layer_summary = context.get("layer_summary") or []
    counts = context.get("counts") or {}

    lines = [
        "ARGUS Analyst Attack Report",
        f"Target: {target.get('description') or target.get('url') or 'Unknown target'}",
        f"Generated: {context.get('generated_at')}",
        f"Overall rating: {context.get('risk_rating')} ({context.get('risk_score', 0)}/100)",
        str(context.get("analyst_verdict") or ""),
        f"Renderer note: {renderer_note}",
        "",
        "Severity Distribution",
    ]
    lines.extend(f"- {severity.upper()}: {counts.get(severity, 0)}" for severity in ["critical", "high", "medium", "low", "info"])
    lines.extend(["", "Layer Coverage"])
    for row in layer_summary:
        highest = (row.get("highest") or {}).get("title", "None")
        lines.append(
            f"- L{row.get('layer')} {row.get('name')}: {row.get('count', 0)} finding(s), "
            f"{row.get('exploitable', 0)} exploitable, highest: {highest}"
        )
    lines.extend(["", "Attack Chain Walkthrough"])
    if not chains:
        lines.append("No cross-layer attack chain was produced for this session.")
    for chain in chains:
        lines.append(f"Chain {chain.get('index')}: {chain.get('rating')} - priority {chain.get('priority_pct')}%")
        lines.extend(_wrap_line(chain.get("narrative"), 92))
        lines.append(
            f"Exploitability {chain.get('exploitability_pct')}% | "
            f"Impact {chain.get('impact_pct')}% | Novelty {chain.get('novelty_pct')}%"
        )
        for step in chain.get("step_findings") or []:
            lines.append(
                f"  Step: L{step.get('layer')} {step.get('layer_name')} - {step.get('title')} "
                f"({str(step.get('severity', '')).upper()}, confidence {step.get('confidence_pct')}%)"
            )
        for remediation in chain.get("remediations") or []:
            lines.extend(_wrap_line(
                f"  Remediate L{remediation.get('layer')}: {remediation.get('action')} [{remediation.get('ref')}]",
                88,
            ))
        lines.append("")
    lines.extend(["Finding Detail and Analyst Rating"])
    for finding in findings:
        lines.append(f"- {finding.get('title')} - {str(finding.get('severity', '')).upper()}")
        lines.append(
            f"  L{finding.get('layer')} {finding.get('layer_name')} | "
            f"Confidence {finding.get('confidence_pct')}% | Exploitable: {finding.get('exploitable')}"
        )
        lines.extend(_wrap_line(f"  {finding.get('severity_rationale')}", 88))
        if finding.get("decision_reason"):
            lines.extend(_wrap_line(f"  Decision: {finding.get('decision_reason')}", 88))
    lines.extend(["", "Terminal Validation Audit"])
    audit = context.get("audit_log") or []
    if not audit:
        lines.append("No terminal validation commands were recorded for this session.")
    else:
        for entry in audit[-20:]:
            lines.extend(_wrap_line(f"{entry.get('timestamp', '')} | {entry.get('status', '')} | {entry.get('command', entry)}", 92))

    wrapped_lines = [part for line in lines for part in (_wrap_line(line, 96) if len(line) > 96 else [line])]
    page_lines = [wrapped_lines[i:i + 48] for i in range(0, len(wrapped_lines), 48)] or [["ARGUS Analyst Attack Report"]]

    objects: list[bytes] = []

    def add_object(payload: bytes) -> int:
        objects.append(payload)
        return len(objects)

    font_id = add_object(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    page_ids: list[int] = []
    content_ids: list[int] = []
    for index, page in enumerate(page_lines, start=1):
        y = 790
        stream_lines = ["BT", "/F1 10 Tf", "50 790 Td"]
        for line in page:
            safe = _pdf_escape(line).encode("latin-1", "replace").decode("latin-1")
            stream_lines.append(f"({safe}) Tj")
            stream_lines.append("0 -14 Td")
            y -= 14
            if y < 60:
                break
        stream_lines.extend(["ET", f"BT /F1 8 Tf 50 28 Td (ARGUS Analyst Report - Page {index}) Tj ET"])
        stream = "\n".join(stream_lines).encode("latin-1", "replace")
        content_ids.append(add_object(b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream"))
        page_ids.append(add_object(b""))

    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids).encode()
    pages_id = add_object(b"<< /Type /Pages /Kids [" + kids + b"] /Count " + str(len(page_ids)).encode() + b" >>")
    catalog_id = add_object(b"<< /Type /Catalog /Pages " + str(pages_id).encode() + b" 0 R >>")
    for i, page_id in enumerate(page_ids):
        objects[page_id - 1] = (
            b"<< /Type /Page /Parent " + str(pages_id).encode() +
            b" 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 " +
            str(font_id).encode() + b" 0 R >> >> /Contents " +
            str(content_ids[i]).encode() + b" 0 R >>"
        )

    data = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, payload in enumerate(objects, start=1):
        offsets.append(len(data))
        data.extend(f"{index} 0 obj\n".encode())
        data.extend(payload)
        data.extend(b"\nendobj\n")
    xref = len(data)
    data.extend(f"xref\n0 {len(objects) + 1}\n".encode())
    data.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        data.extend(f"{offset:010d} 00000 n \n".encode())
    data.extend(
        b"trailer\n<< /Size " + str(len(objects) + 1).encode() +
        b" /Root " + str(catalog_id).encode() + b" 0 R >>\nstartxref\n" +
        str(xref).encode() + b"\n%%EOF\n"
    )
    out.write_bytes(bytes(data))


async def write_pdf_report(session_id: str, context: dict[str, Any]) -> Path:
    """Render and persist a PDF report. Returns path."""
    session_id = validate_session_id(session_id)
    out = _REPORTS_DIR_FUNC() / f"{session_id}_report.pdf"
    out.parent.mkdir(parents=True, exist_ok=True)
    try:
        _build_reportlab_pdf(out, context)
    except Exception as exc:
        _build_plain_pdf(out, context, f"ReportLab renderer unavailable; generated with emergency PDF renderer. Detail: {exc}")
    return out


def build_report_context(
    session_id: str,
    target: dict[str, Any],
    findings: list[dict],
    chains: list[dict],
    audit_log: list[dict],
) -> dict[str, Any]:
    """Build the Jinja2 context dict for the report template."""
    enriched_findings = _enrich_findings(findings)
    sorted_findings = sorted(
        enriched_findings,
        key=lambda f: (f.get("severity_rank", 5), -float(f.get("confidence", 0) or 0)),
    )

    counts = {s: sum(1 for f in findings if f.get("severity") == s)
              for s in ["critical", "high", "medium", "low", "info"]}

    finding_by_id = {f["id"]: f for f in sorted_findings if f.get("id")}
    enriched_chains = _enrich_chains(chains, finding_by_id)
    top_chain = enriched_chains[0] if enriched_chains else None
    risk_score = _risk_score(enriched_findings)
    exploitable_count = sum(1 for f in findings if f.get("exploitable"))

    return {
        "session_id": session_id,
        "generated_at": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
        "target": target,
        "findings": sorted_findings,
        "chains": enriched_chains,
        "top_chain": top_chain,
        "audit_log": audit_log,
        "counts": counts,
        "total_findings": len(findings),
        "exploitable_count": exploitable_count,
        "risk_score": risk_score,
        "risk_rating": _risk_rating(risk_score),
        "layer_summary": _layer_summary(sorted_findings),
        "domains_hit": sorted({f["layer_domain"] for f in sorted_findings}),
        "analyst_verdict": (
            f"{_risk_rating(risk_score)} risk: {exploitable_count} exploitable finding(s), "
            f"{len(enriched_chains)} attack chain(s), and {len({f.get('layer') for f in findings})} layer(s) affected."
        ),
    }


# STIX 2.1 export

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
