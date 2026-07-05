"""Finding calibration and exploitability decisions.

Layers collect raw signals. This module applies a consistent evidence gate before
those signals drive dependent layers or attack-chain reasoning.
"""
from __future__ import annotations

from app.models.finding import Finding

_MIN_EXPLOITABLE_CONFIDENCE = 0.60
_SEVERITY_DOWNGRADE = {
    "critical": "high",
    "high": "medium",
    "medium": "low",
    "low": "info",
    "info": "info",
}


def _decision(reason: str, strength: str, adjusted: bool) -> dict:
    return {"reason": reason, "strength": strength, "adjusted": adjusted}


def _downgrade(finding: Finding, reason: str, strength: str = "weak") -> Finding:
    finding.exploitable = False
    finding.severity = _SEVERITY_DOWNGRADE.get(finding.severity, "info")
    finding.confidence = min(finding.confidence, 0.59)
    finding.evidence["decision"] = _decision(reason, strength, adjusted=True)
    return finding


def calibrate_finding(finding: Finding) -> Finding:
    """Return a calibrated copy of a finding with exploitability normalized."""
    f = finding.model_copy(deep=True)
    ev = f.evidence or {}
    original = {
        "exploitable": f.exploitable,
        "severity": f.severity,
        "confidence": f.confidence,
    }

    if not f.exploitable:
        f.evidence["decision"] = {
            **_decision("finding is informational or not directly exploitable", "informational", False),
            "original": original,
        }
        return f

    family = ev.get("family")
    verdict = ev.get("verdict")
    signal = ev.get("signal")

    if f.confidence < _MIN_EXPLOITABLE_CONFIDENCE:
        f = _downgrade(f, "confidence below exploitable threshold")
    elif family in {"sqli", "cmdi", "ssti", "traversal"}:
        if verdict != "exploited" or not signal:
            f = _downgrade(f, f"{family} finding lacks an exploitation signal")
        else:
            f.evidence["decision"] = _decision("confirmed exploit signature", "strong", False)
    elif family == "xss":
        if verdict != "exploited" or signal != "payload reflected unescaped":
            f = _downgrade(f, "XSS requires unescaped payload reflection")
        else:
            f.evidence["decision"] = _decision("unescaped reflection confirmed", "strong", False)
    elif family == "open_redirect":
        if verdict != "exploited" or not ev.get("location") or ev.get("status") not in {301, 302, 303, 307, 308}:
            f = _downgrade(f, "open redirect requires a 3xx Location to an external marker")
        else:
            f.evidence["decision"] = _decision("external redirect confirmed", "strong", False)
    elif family == "ssrf":
        if verdict != "exploited" or not (signal or ev.get("snippet")):
            f = _downgrade(f, "SSRF requires response-side proof from the fetched resource")
        else:
            f.evidence["decision"] = _decision("SSRF proof signal confirmed", "moderate", False)
    elif family == "csrf":
        if ev.get("method") != "POST" or not ev.get("inputs"):
            f = _downgrade(f, "CSRF finding requires a state-changing form with inputs")
        else:
            f.evidence["decision"] = _decision("state-changing form lacks CSRF token", "moderate", False)
    else:
        f.evidence["decision"] = _decision("accepted by generic confidence gate", "moderate", False)

    f.evidence.setdefault("decision", {})["original"] = original
    return f


def calibrate_findings(findings: list[Finding]) -> list[Finding]:
    """Calibrate a list while preserving order."""
    return [calibrate_finding(f) for f in findings]
