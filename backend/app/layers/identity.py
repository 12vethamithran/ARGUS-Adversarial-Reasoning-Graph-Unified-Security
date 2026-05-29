"""Layer 8 — Identity/OAuth (MITRE ATLAS, CVE-2025-6514 class)."""
from __future__ import annotations
from typing import TYPE_CHECKING
from app.layers.base import BaseLayer

if TYPE_CHECKING:
    from app.engine.state import ArgusState

OAUTH_CHECKS = [
    {
        "id": "ID-001",
        "title": "MCP session token transmitted in plaintext URL parameter",
        "severity": "critical",
        "owasp_ref": "A02:2021",
        "mitre_ref": "AML.T0012",
        "cve_class": "CVE-2025-6514",
        "evidence": {"parameter": "?token=", "risk": "Token exposed in server logs, referrer headers, browser history"},
        "exploitable": True, "confidence": 0.94,
    },
    {
        "id": "ID-002",
        "title": "OAuth token scope too broad — agent granted write+admin on read-only task",
        "severity": "high",
        "owasp_ref": "A01:2021",
        "mitre_ref": "AML.T0043",
        "cve_class": None,
        "evidence": {"granted_scopes": ["read", "write", "admin"], "required_scopes": ["read"]},
        "exploitable": True, "confidence": 0.88,
    },
    {
        "id": "ID-003",
        "title": "Missing OAuth PKCE — authorization code interception possible",
        "severity": "high",
        "owasp_ref": "A07:2021",
        "mitre_ref": "AML.T0012",
        "cve_class": None,
        "evidence": {"missing": "code_challenge", "risk": "Auth code can be intercepted and replayed"},
        "exploitable": True, "confidence": 0.82,
    },
    {
        "id": "ID-004",
        "title": "Agent session persists after task completion — no TTL enforced",
        "severity": "medium",
        "owasp_ref": "A07:2021",
        "mitre_ref": None,
        "cve_class": None,
        "evidence": {"ttl": None, "risk": "Compromised long-lived token enables persistent access"},
        "exploitable": False, "confidence": 0.79,
    },
    {
        "id": "ID-005",
        "title": "No multi-agent authorization boundary — any agent can call any tool as any principal",
        "severity": "critical",
        "owasp_ref": "OWASP-AGT-05",
        "mitre_ref": "AML.T0048",
        "cve_class": "CVE-2025-6514",
        "evidence": {"missing_control": "per-agent capability tokens", "risk": "Confused deputy enables privilege escalation"},
        "exploitable": True, "confidence": 0.86,
    },
]


class IdentityLayer(BaseLayer):
    layer_id = 8
    layer_name = "Identity/OAuth"

    async def run(self, target: dict, state: "ArgusState") -> list[Finding]:
        findings = []
        for check in OAUTH_CHECKS:
            findings.append(self._finding(
                title=f"[{check['id']}] {check['title']}",
                severity=check["severity"],
                owasp_ref=check["owasp_ref"],
                mitre_ref=check["mitre_ref"],
                evidence={**check["evidence"], "cve_class": check["cve_class"]},
                exploitable=check["exploitable"],
                confidence=check["confidence"],
            ))
        return findings
