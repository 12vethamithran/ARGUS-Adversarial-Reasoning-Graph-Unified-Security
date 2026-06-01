"""Layer 8 — Identity/OAuth (MITRE ATLAS, CVE-2025-6514 class)."""
from __future__ import annotations
from typing import TYPE_CHECKING
from app.layers.base import BaseLayer
from app.layers.xlayer import _l4_agent_compromise
from app.engine.target_profile import jitter, gate

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
    {
        "id": "ID-006",
        "title": "Refresh token replay — long-lived refresh token not rotated on use",
        "severity": "high",
        "owasp_ref": "A07:2021",
        "mitre_ref": "AML.T0012",
        "cve_class": None,
        "evidence": {"missing": "refresh-token rotation", "risk": "A stolen refresh token mints new access tokens indefinitely"},
        "exploitable": True, "confidence": 0.83,
    },
    {
        "id": "ID-007",
        "title": "Session fixation — session identifier not regenerated after authentication",
        "severity": "high",
        "owasp_ref": "A07:2021",
        "mitre_ref": "AML.T0012",
        "cve_class": None,
        "evidence": {"missing": "session ID regeneration on login", "risk": "Attacker-fixed session ID is elevated to the victim's authenticated session"},
        "exploitable": True, "confidence": 0.8,
    },
    {
        "id": "ID-008",
        "title": "JWT algorithm confusion — server accepts 'alg: none' / HS256 with public key",
        "severity": "critical",
        "owasp_ref": "A02:2021",
        "mitre_ref": "AML.T0012",
        "cve_class": None,
        "evidence": {"weakness": "unverified JWT alg header", "risk": "Attacker forges tokens by downgrading the signature algorithm"},
        "exploitable": True, "confidence": 0.81,
    },
]


class IdentityLayer(BaseLayer):
    layer_id = 8
    layer_name = "Identity/OAuth"

    async def run(self, target: dict, state: "ArgusState") -> list[Finding]:
        findings = []
        # Each OAuth/identity weakness is surfaced per-target rather than asserted
        # for everyone, with target-derived confidence — so different targets get a
        # different identity-risk profile (and therefore different chain scores).
        for check in OAUTH_CHECKS:
            if not gate(target, f"l8-{check['id']}", 0.6):
                continue
            findings.append(self._finding(
                title=f"[{check['id']}] {check['title']}",
                severity=check["severity"],
                owasp_ref=check["owasp_ref"],
                mitre_ref=check["mitre_ref"],
                evidence={**check["evidence"], "cve_class": check["cve_class"]},
                exploitable=check["exploitable"],
                confidence=jitter(target, f"l8-{check['id']}-conf", check["confidence"], 0.08),
            ))

        # ── Cross-layer L4 → L8: compromised agent escalates / persists ──────────
        # A hijacked agent (L4) plus a weak identity boundary means the foothold
        # becomes durable: over-broad / leaked tokens give attacker re-entry that
        # survives a single-session cleanup.
        compromise = _l4_agent_compromise(state)
        if compromise:
            id_weaknesses = [f for f in findings
                             if f.exploitable and f.layer == 8]
            findings.append(self._finding(
                title="Compromised agent escalates via weak identity boundary — durable re-entry",
                severity="critical",
                owasp_ref="A01:2021", mitre_ref="AML.T0048",
                evidence={
                    "source_layer": 4,
                    "source_findings": [f.id for f in compromise],
                    "identity_weaknesses": [f.id for f in id_weaknesses],
                    "rationale": "The L4-hijacked agent reuses over-broad or leaked credentials, so "
                                 "the attacker retains access beyond the initial session.",
                },
                exploitable=True,
                confidence=jitter(target, "l8-from-l4", 0.85, 0.07),
            ))

        if not findings:
            findings.append(self._finding(
                title="No high-confidence identity/OAuth weaknesses surfaced for this target",
                severity="info", owasp_ref="A07:2021",
                evidence={"note": "Heuristic scan — validate against the real auth flow"},
                exploitable=False, confidence=0.6,
            ))
        return findings
