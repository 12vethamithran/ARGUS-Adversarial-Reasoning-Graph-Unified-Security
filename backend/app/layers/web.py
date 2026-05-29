"""Layer 1 — Web Surface Scanner (OWASP Web Top 10)."""
from __future__ import annotations
import asyncio
import math
import re
from typing import TYPE_CHECKING

import httpx

from app.layers.base import BaseLayer
from app.models.finding import Finding

if TYPE_CHECKING:
    from app.engine.state import ArgusState

# Entropy for secret detection
def _shannon(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((f / len(s)) * math.log2(f / len(s)) for f in freq.values())

SECRET_RE = re.compile(
    r'(?i)(api[_-]?key|secret|token|password|auth|bearer|private[_-]?key)\s*[=:]\s*["\']?([A-Za-z0-9+/=_\-]{16,})',
)

SECURITY_HEADERS = [
    ("Content-Security-Policy", "Missing CSP header", "medium", "A05:2021"),
    ("X-Frame-Options",         "Missing X-Frame-Options (clickjacking)", "low", "A05:2021"),
    ("X-Content-Type-Options",  "Missing X-Content-Type-Options", "low", "A05:2021"),
    ("Strict-Transport-Security","Missing HSTS header", "medium", "A05:2021"),
    ("Referrer-Policy",         "Missing Referrer-Policy", "info", "A05:2021"),
    ("Permissions-Policy",      "Missing Permissions-Policy", "info", "A05:2021"),
]


class WebLayer(BaseLayer):
    layer_id = 1
    layer_name = "Web Surface"

    async def run(self, target: dict, state: "ArgusState") -> list[Finding]:
        url: str | None = target.get("url")
        if not url:
            return [self._finding(
                title="No URL provided — web scan skipped",
                severity="info", evidence={}, exploitable=False, confidence=1.0,
            )]

        findings: list[Finding] = []

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(connect=5.0, read=8.0, write=5.0, pool=5.0),
                follow_redirects=True,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0 (ARGUS-Scanner/0.1)"},
            ) as client:
                resp = await client.get(url)
        except httpx.TimeoutException:
            return [self._finding(
                title=f"Web layer: connection timed out for {url}",
                severity="info", evidence={"url": url, "error": "timeout"},
                exploitable=False, confidence=0.8,
            )]
        except Exception as e:
            return [self._finding(
                title=f"Web layer: could not reach {url}",
                severity="info", evidence={"error": type(e).__name__},
                exploitable=False, confidence=0.8,
            )]

        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.text[:8000]

        # ── Security headers ─────────────────────────────────────────────
        for hdr, title, sev, owasp in SECURITY_HEADERS:
            if hdr.lower() not in headers:
                findings.append(self._finding(
                    title=title, severity=sev, owasp_ref=owasp,
                    evidence={"url": url, "status": resp.status_code},
                    exploitable=False, confidence=0.95,
                ))

        # ── CORS wildcard ────────────────────────────────────────────────
        acao = headers.get("access-control-allow-origin", "")
        if acao == "*":
            findings.append(self._finding(
                title="CORS wildcard (*) allows any origin",
                severity="high", owasp_ref="A05:2021",
                evidence={"header": "Access-Control-Allow-Origin: *", "url": url},
                exploitable=True, confidence=0.92,
            ))
        elif acao:
            findings.append(self._finding(
                title=f"CORS allows origin: {acao}",
                severity="info", owasp_ref="A05:2021",
                evidence={"header": f"Access-Control-Allow-Origin: {acao}"},
                exploitable=False, confidence=0.8,
            ))

        # ── Server version disclosure ─────────────────────────────────────
        server = headers.get("server", "")
        if server and any(c.isdigit() for c in server):
            findings.append(self._finding(
                title=f"Server version disclosed: {server}",
                severity="low", owasp_ref="A05:2021",
                evidence={"server_header": server},
                exploitable=False, confidence=0.85,
            ))

        # ── JS secret entropy scan ───────────────────────────────────────
        for match in SECRET_RE.finditer(body):
            key_name, value = match.group(1), match.group(2)
            entropy = _shannon(value)
            if entropy > 3.5:
                findings.append(self._finding(
                    title=f"High-entropy secret in response: {key_name}",
                    severity="critical", owasp_ref="A02:2021",
                    evidence={"key": key_name, "entropy": round(entropy, 2), "sample": value[:8] + "..."},
                    exploitable=True, confidence=0.78,
                ))

        # ── HTTP methods ─────────────────────────────────────────────────
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(5.0), verify=False) as client:
                opts = await client.options(url)
            allow = opts.headers.get("allow", "")
            if "DELETE" in allow or "PUT" in allow:
                findings.append(self._finding(
                    title=f"Dangerous HTTP methods enabled: {allow}",
                    severity="medium", owasp_ref="A05:2021",
                    evidence={"allow": allow},
                    exploitable=True, confidence=0.7,
                ))
        except Exception:
            pass

        if not findings:
            findings.append(self._finding(
                title="No critical web surface issues found",
                severity="info", evidence={"url": url, "status": resp.status_code},
                exploitable=False, confidence=0.9,
            ))

        return findings
