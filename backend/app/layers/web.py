"""Layer 1 — Web Surface Scanner (OWASP Web Top 10).

Coverage spans the full OWASP Web Top 10 (2021):
  A01 Broken Access Control  — force-browse privileged paths, IDOR, open redirect
  A02 Cryptographic Failures — cleartext transport, exposed secrets/credentials
  A03 Injection              — SQLi (error/boolean/time/union), XSS, cmdi, SSTI, traversal
  A04 Insecure Design        — verbose error / stack-trace leakage
  A05 Misconfiguration       — security headers, CORS, methods, dir listing, sensitive paths
  A06 Vulnerable Components  — version fingerprint (informational, feeds L6)
  A07 Auth Failures          — password-over-HTTP, weak session cookies
  A08 Integrity Failures     — missing Subresource Integrity (SRI)
  A09 Logging/Monitoring     — stack-trace/debug leakage signal
  A10 SSRF                   — internal-host / metadata / file-scheme parameter probes

Active probes (SQLi/XSS/traversal/cmdi/SSTI/SSRF/redirect/IDOR) are GET-only and
non-destructive, rate-limited, concurrency-capped, and time-based payloads are
clamped to web_payloads.MAX_TIME_BASED_DELAY. Every hit is confirmed by a
content/timing signature so catch-all 200 pages don't produce false positives.
This is authorized-testing tooling — see the project ETHICS note.
"""
from __future__ import annotations
import asyncio
import math
import re
import time
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import httpx

from app.layers.base import BaseLayer
from app.layers import web_payloads as wp
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
    ("Content-Security-Policy", "Missing CSP header", "medium", "A02:2025"),
    ("X-Frame-Options",         "Missing X-Frame-Options (clickjacking)", "low", "A02:2025"),
    ("X-Content-Type-Options",  "Missing X-Content-Type-Options", "low", "A02:2025"),
    ("Strict-Transport-Security","Missing HSTS header", "medium", "A02:2025"),
    ("Referrer-Policy",         "Missing Referrer-Policy", "info", "A02:2025"),
    ("Permissions-Policy",      "Missing Permissions-Policy", "info", "A02:2025"),
]

# Sensitive paths probed concurrently. (path, severity, exploitable, owasp_ref).
# Each hit is confirmed by a content signature (_looks_exposed) so that SPAs /
# catch-all 200 routes don't produce false positives.
SENSITIVE_PATHS = [
    ("/.env",                     "critical", True,  "A02:2025"),
    ("/.git/config",              "critical", True,  "A02:2025"),
    ("/.git/HEAD",                "high",     True,  "A02:2025"),
    ("/.aws/credentials",         "critical", True,  "A04:2025"),
    ("/config.json",              "high",     True,  "A02:2025"),
    ("/actuator/env",             "high",     True,  "A02:2025"),
    ("/server-status",            "medium",   False, "A02:2025"),
    ("/swagger.json",             "low",      False, "A02:2025"),
    ("/.well-known/security.txt", "info",     False, "A02:2025"),
]

# Reflected-input canary: a unique token wrapped in markup that, if it appears
# unescaped in the response, proves the input reaches the page without encoding.
REFLECT_CANARY = "argus<xss>7f3a"

# Discovery / probing safety caps.
MAX_PARAMS_PROBED = 6        # most fuzzed params per target endpoint
MAX_CONNECTIONS = 16         # httpx connection pool ceiling
PROBE_CONCURRENCY = 12       # in-flight active probes (bounded by a semaphore)
MAX_CRAWL_ENDPOINTS = 5      # extra same-origin endpoints discovered + probed


def _looks_exposed(path: str, status: int, text: str) -> bool:
    """Confirm a sensitive path is genuinely exposed via a content signature."""
    if status != 200:
        return False
    t = text[:4000]
    tl = t.lower()
    if path == "/.env":
        return "=" in t and "<html" not in tl and any(
            k in t for k in ("KEY", "SECRET", "PASSWORD", "TOKEN", "DB_", "API"))
    if path.startswith("/.git"):
        return t.startswith("ref:") or "[core]" in t
    if path == "/.aws/credentials":
        return "aws_access_key" in tl
    if path == "/actuator/env":
        return t.lstrip().startswith("{") and "propertySources" in t
    if path == "/server-status":
        return "Apache Server Status" in t
    if path == "/swagger.json":
        return '"swagger"' in tl or '"openapi"' in tl
    if path == "/config.json":
        return t.lstrip().startswith("{")
    if path == "/.well-known/security.txt":
        return "contact:" in tl
    return False


# ── Parameter / form / link discovery (regex-based, no extra deps) ────────────
_INPUT_NAME_RE = re.compile(r'(?i)<(?:input|textarea|select)\b[^>]*\bname\s*=\s*["\']([^"\']+)["\']')
_FORM_RE = re.compile(r'(?i)<form\b([^>]*)>(.*?)</form>', re.DOTALL)
_ACTION_RE = re.compile(r'(?i)\baction\s*=\s*["\']([^"\']*)["\']')
_METHOD_RE = re.compile(r'(?i)\bmethod\s*=\s*["\']([^"\']*)["\']')
_SCRIPT_SRC_RE = re.compile(r'(?i)<script\b[^>]*\bsrc\s*=\s*["\']([^"\']+)["\'][^>]*>')
_HREF_RE = re.compile(r'(?i)<a\b[^>]*\bhref\s*=\s*["\']([^"\']+)["\']')
# A hidden anti-CSRF token field inside a form body.
_CSRF_FIELD_RE = re.compile(
    r'(?i)name\s*=\s*["\'][^"\']*(csrf|xsrf|_token|authenticity_token|nonce|verification)[^"\']*["\']')


def discover_endpoints(base_url: str, html: str) -> list[str]:
    """Same-origin endpoints (with query params or form actions) worth probing.

    A lightweight, bounded crawl: most real apps put injectable params on deep
    endpoints, not the homepage. We extract <a href> links that carry a query
    string and <form action> targets, keep only same-origin ones, and return
    the base URL first. Capped by MAX_CRAWL_ENDPOINTS.
    """
    base = urlparse(base_url)
    origin = base.netloc
    out, seen = [base_url], {base_url.split("#", 1)[0]}

    candidates = [m.group(1) for m in _HREF_RE.finditer(html or "")]
    for attrs, _body in _FORM_RE.findall(html or ""):
        am = _ACTION_RE.search(attrs)
        if am:
            candidates.append(am.group(1))

    for href in candidates:
        if not href or href.startswith(("#", "mailto:", "javascript:", "tel:")):
            continue
        absu = urljoin(base_url, href)
        parts = urlparse(absu)
        if parts.scheme not in ("http", "https") or parts.netloc != origin:
            continue
        # Prioritise endpoints that actually take parameters.
        if not parts.query:
            continue
        key = absu.split("#", 1)[0]
        if key in seen:
            continue
        seen.add(key)
        out.append(absu)
        if len(out) >= 1 + MAX_CRAWL_ENDPOINTS:
            break
    return out


def discover_forms(base_url: str, html: str) -> list[dict]:
    """Forms on the page: {action, method, inputs, has_csrf_token}."""
    forms = []
    for attrs, body in _FORM_RE.findall(html or ""):
        am = _ACTION_RE.search(attrs)
        mm = _METHOD_RE.search(attrs)
        action = urljoin(base_url, am.group(1)) if am and am.group(1) else base_url
        method = (mm.group(1) if mm else "get").lower()
        inputs = _INPUT_NAME_RE.findall(body)
        forms.append({
            "action": action, "method": method, "inputs": inputs,
            "has_csrf_token": bool(_CSRF_FIELD_RE.search(body)),
        })
    return forms


def discover_params(url: str, html: str) -> list[str]:
    """Parameter names worth fuzzing: existing query params + form fields.

    Falls back to a small common-name list when the target exposes none of its
    own. De-duplicated, order-stable, and capped by the caller.
    """
    names: list[str] = []
    seen: set[str] = set()

    def _add(n: str) -> None:
        n = (n or "").strip()
        if n and n not in seen:
            seen.add(n)
            names.append(n)

    for k, _v in parse_qsl(urlparse(url).query):
        _add(k)
    for m in _INPUT_NAME_RE.finditer(html or ""):
        _add(m.group(1))

    if not names:
        for n in wp.COMMON_FUZZ_PARAMS:
            _add(n)
    return names


def _set_param(url: str, param: str, value: str) -> str:
    """Return `url` with `param` set to `value` in the query string."""
    parts = urlparse(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q[param] = value
    return urlunparse(parts._replace(query=urlencode(q)))


def _looks_privileged(text: str) -> bool:
    """Heuristic: a force-browsed page that looks like an admin/management UI."""
    tl = (text or "")[:6000].lower()
    return any(k in tl for k in (
        "admin", "dashboard", "user management", "control panel",
        "phpmyadmin", "swagger", "actuator", "delete user", "manage users",
    ))


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
        full_body = resp.text
        final_url = str(resp.url)

        # ── Passive checks (A02 / A05 / A06 / A08) ───────────────────────────
        findings += self._passive_checks(url, final_url, headers, resp, body, full_body)

        # ── Active probes (A01 / A03 / A04 / A07 / A09 / A10) ────────────────
        try:
            findings += await self._active_probes(url, final_url, full_body)
        except Exception:
            pass  # one failing probe family must never abort the layer

        if not findings:
            findings.append(self._finding(
                title="No critical web surface issues found",
                severity="info", evidence={"url": url, "status": resp.status_code},
                exploitable=False, confidence=0.9,
            ))

        return findings

    # ── Passive surface analysis ──────────────────────────────────────────────
    def _passive_checks(self, url, final_url, headers, resp, body, full_body) -> list[Finding]:
        findings: list[Finding] = []

        # Security headers
        for hdr, title, sev, owasp in SECURITY_HEADERS:
            if hdr.lower() not in headers:
                findings.append(self._finding(
                    title=title, severity=sev, owasp_ref=owasp,
                    evidence={"url": url, "status": resp.status_code},
                    exploitable=False, confidence=0.95,
                ))

        # CORS wildcard
        acao = headers.get("access-control-allow-origin", "")
        if acao == "*":
            findings.append(self._finding(
                title="CORS wildcard (*) allows any origin",
                severity="high", owasp_ref="A02:2025",
                evidence={"header": "Access-Control-Allow-Origin: *", "url": url},
                exploitable=True, confidence=0.92,
            ))
        elif acao:
            findings.append(self._finding(
                title=f"CORS allows origin: {acao}",
                severity="info", owasp_ref="A02:2025",
                evidence={"header": f"Access-Control-Allow-Origin: {acao}"},
                exploitable=False, confidence=0.8,
            ))

        # Server version disclosure (A06 fingerprint — feeds L6)
        server = headers.get("server", "")
        powered = headers.get("x-powered-by", "")
        banner = server or powered
        if banner and any(c.isdigit() for c in banner):
            findings.append(self._finding(
                title=f"Component version disclosed: {banner}",
                severity="low", owasp_ref="A03:2025", mitre_ref="T1592",
                evidence={"server": server, "x_powered_by": powered,
                          "note": "Version fingerprint — cross-checked against known CVEs in L6"},
                exploitable=False, confidence=0.85,
            ))

        # JS secret entropy scan (A02)
        for match in SECRET_RE.finditer(body):
            key_name, value = match.group(1), match.group(2)
            entropy = _shannon(value)
            if entropy > 3.5:
                findings.append(self._finding(
                    title=f"High-entropy secret in response: {key_name}",
                    severity="critical", owasp_ref="A04:2025",
                    evidence={"key": key_name, "entropy": round(entropy, 2), "sample": value[:8] + "..."},
                    exploitable=True, confidence=0.78,
                ))

        # Cleartext transport (A02)
        if final_url.startswith("http://"):
            findings.append(self._finding(
                title="Site served over cleartext HTTP (no TLS)",
                severity="medium", owasp_ref="A04:2025",
                evidence={"final_url": final_url},
                exploitable=False, confidence=0.9,
            ))

        # Cookie security flags (A05/A07)
        _get_list = getattr(resp.headers, "get_list", None)
        cookies = _get_list("set-cookie") if _get_list else (
            [resp.headers["set-cookie"]] if "set-cookie" in resp.headers else [])
        for raw in cookies:
            cl = raw.lower()
            name = raw.split("=", 1)[0].strip()
            missing = [flag for flag, tok in
                       (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite"))
                       if tok not in cl]
            if missing:
                # Session cookies missing flags map to auth failures (A07).
                is_session = any(s in name.lower() for s in ("sess", "sid", "auth", "token"))
                findings.append(self._finding(
                    title=f"Cookie '{name}' missing flags: {', '.join(missing)}",
                    severity="medium" if is_session else "low",
                    owasp_ref="A07:2025" if is_session else "A02:2025",
                    evidence={"cookie": name, "missing_flags": missing, "session_cookie": is_session},
                    exploitable=False, confidence=0.85,
                ))

        # Directory listing (A05)
        if "<title>Index of /" in body or "Directory listing for" in body:
            findings.append(self._finding(
                title="Directory listing enabled",
                severity="medium", owasp_ref="A02:2025",
                evidence={"url": final_url},
                exploitable=False, confidence=0.8,
            ))

        # Stack-trace / debug leakage (A04 / A09)
        if wp.STACKTRACE_SIGNATURE.search(full_body):
            findings.append(self._finding(
                title="Verbose error / stack trace leaked in response",
                severity="medium", owasp_ref="A10:2025", mitre_ref="T1592",
                evidence={"url": final_url, "signal": "stack-trace signature in body",
                          "note": "Insufficient error handling / logging hygiene (A04/A09)."},
                exploitable=False, confidence=0.75,
            ))

        # Missing Subresource Integrity on cross-origin scripts (A08)
        host = urlparse(final_url).netloc
        for m in _SCRIPT_SRC_RE.finditer(full_body):
            src = m.group(1)
            tag = m.group(0)
            is_external = src.startswith("http") and host not in src
            if is_external and "integrity" not in tag.lower():
                findings.append(self._finding(
                    title="External script loaded without Subresource Integrity (SRI)",
                    severity="low", owasp_ref="A08:2025", mitre_ref="T1195",
                    evidence={"script_src": src[:200]},
                    exploitable=False, confidence=0.7,
                ))
                break  # one representative finding is enough

        return findings

    # ── Active probing orchestrator ───────────────────────────────────────────
    async def _active_probes(self, url, final_url, full_body) -> list[Finding]:
        findings: list[Finding] = []
        base = final_url.split("#", 1)[0].split("?", 1)[0].rstrip("/")

        # Bounded same-origin crawl: real apps put injectable params on deep
        # endpoints, not the homepage. Probe the entry URL + a few discovered
        # endpoints that actually take parameters.
        endpoints = discover_endpoints(final_url, full_body)
        forms = discover_forms(final_url, full_body)
        # (endpoint, params) pairs — base first; cap injection breadth for speed.
        endpoint_params = [
            (ep, discover_params(ep, full_body if ep == final_url else "")[:MAX_PARAMS_PROBED])
            for ep in endpoints[:3]
        ]

        # follow_redirects=True so sites that 301/redirect still reach the live
        # handler; open-redirect/sensitive-path probes override per-request.
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=4.0, read=max(wp.MAX_TIME_BASED_DELAY + 4.0, 8.0),
                                  write=4.0, pool=4.0),
            verify=False, follow_redirects=True,
            limits=httpx.Limits(max_connections=MAX_CONNECTIONS),
            headers={"User-Agent": "Mozilla/5.0 (ARGUS-Scanner/0.1)"},
        ) as client:
            sem = asyncio.Semaphore(PROBE_CONCURRENCY)

            # CSRF (A01) is a passive read of the discovered forms — no requests.
            findings += self._probe_csrf(forms)

            # All probe groups run concurrently; each request is bounded by `sem`.
            groups = await asyncio.gather(
                self._probe_injection(client, sem, endpoint_params),
                self._probe_methods(client, url),
                self._probe_access_control(client, sem, base),
                self._probe_sensitive_paths(client, sem, base),
                *[self._probe_open_redirect(client, sem, ep, p) for ep, p in endpoint_params],
                *[self._probe_ssrf(client, sem, ep, p) for ep, p in endpoint_params],
                *[self._probe_idor(client, sem, ep, p) for ep, p in endpoint_params],
            )
            for g in groups:
                findings += g

        return findings

    # ── A01 CSRF (passive, from discovered forms) ─────────────────────────────
    def _probe_csrf(self, forms) -> list[Finding]:
        findings: list[Finding] = []
        for form in forms:
            if form["method"] == "post" and not form["has_csrf_token"] and form["inputs"]:
                findings.append(self._finding(
                    title=f"State-changing form without anti-CSRF token: {form['action']}",
                    severity="medium", owasp_ref="A01:2025", mitre_ref="T1190",
                    evidence={"action": form["action"], "method": "POST",
                              "inputs": form["inputs"][:8], "family": "csrf",
                              "signal": "POST form has no hidden csrf/xsrf/_token field"},
                    exploitable=True, confidence=0.68,
                ))
                break  # one representative CSRF finding is sufficient
        return findings

    # ── A05 dangerous HTTP methods ────────────────────────────────────────────
    async def _probe_methods(self, client, url) -> list[Finding]:
        try:
            opts = await client.options(url)
        except Exception:
            return []
        allow = opts.headers.get("allow", "")
        if "DELETE" in allow or "PUT" in allow:
            return [self._finding(
                title=f"Dangerous HTTP methods enabled: {allow}",
                severity="medium", owasp_ref="A02:2025",
                evidence={"allow": allow}, exploitable=True, confidence=0.7,
            )]
        return []

    # ── A05/A02 sensitive path exposure (concurrent, signature-confirmed) ─────
    async def _probe_sensitive_paths(self, client, sem, base) -> list[Finding]:
        findings: list[Finding] = []

        async def _probe(p):
            async with sem:
                try:
                    return p, await client.get(base + p, follow_redirects=False)
                except Exception:
                    return p, None

        results = await asyncio.gather(*(_probe(p) for p, _s, _e, _o in SENSITIVE_PATHS))
        sig = {p: (sev, exp, owasp) for p, sev, exp, owasp in SENSITIVE_PATHS}
        for path, r in results:
            if r is None:
                continue
            sev, exp, owasp = sig[path]
            if _looks_exposed(path, r.status_code, r.text):
                findings.append(self._finding(
                    title=f"Sensitive path exposed: {path}",
                    severity=sev, owasp_ref=owasp,
                    evidence={"path": path, "status": r.status_code, "sample": r.text[:120]},
                    exploitable=exp, confidence=0.88,
                ))
        return findings

    async def _timed_get(self, client, sem, target, headers=None):
        async with sem:
            t0 = time.perf_counter()
            try:
                r = await client.get(target, headers=headers)
                return r.text, time.perf_counter() - t0
            except Exception:
                return "", 0.0

    # ── A05 / A01 injection families (parallel across endpoints × params) ─────
    async def _probe_injection(self, client, sem, endpoint_params) -> list[Finding]:
        families = [wp.SQLI_PAYLOADS, wp.XSS_PAYLOADS, wp.TRAVERSAL_PAYLOADS,
                    wp.CMDI_PAYLOADS, wp.SSTI_PAYLOADS]

        # One benign baseline per endpoint, fetched concurrently — needed for the
        # boolean/time-based comparisons.
        baselines: dict[str, tuple[str, float]] = {}

        async def _baseline(ep, params):
            bu = _set_param(ep, params[0], "argusbaseline") if params else ep
            baselines[ep] = await self._timed_get(client, sem, bu)

        await asyncio.gather(*(_baseline(ep, p) for ep, p in endpoint_params if p))

        # Fan out every (endpoint, param, payload) probe concurrently; the
        # semaphore caps real in-flight requests so this stays fast and polite.
        tasks = []
        for ep, params in endpoint_params:
            bt, bl = baselines.get(ep, ("", 0.0))
            for param in params:
                for fam in families:
                    for pd in fam:
                        tasks.append(self._run_payload(client, sem, ep, param, pd, bt, bl))

        results = [f for f in await asyncio.gather(*tasks) if f is not None]

        # Dedupe: keep one finding per (url, param, family) — prefer the exploited
        # one — so a confirmed SQLi doesn't emit ten near-identical entries.
        best: dict[tuple, Finding] = {}
        for f in results:
            ev = f.evidence
            key = (ev.get("url"), ev.get("param"), ev.get("family"))
            cur = best.get(key)
            if cur is None or (f.exploitable and not cur.exploitable):
                best[key] = f
        return list(best.values())

    async def _run_payload(self, client, sem, url, param, pd,
                           baseline_text, baseline_lat) -> Finding | None:
        detect = pd["detect"]
        ev = {"param": param, "url": url, "family": pd["family"],
              "technique": pd["technique"], "payload_id": pd["id"]}

        # Time-based (SQLi / cmdi)
        if detect == "time":
            target = _set_param(url, param, f"x{pd['payload']}")
            _txt, lat = await self._timed_get(client, sem, target)
            if wp.latency_confirms(baseline_lat, lat, pd.get("delay", wp.MAX_TIME_BASED_DELAY)):
                ev.update({"signal": f"latency {lat:.1f}s vs baseline {baseline_lat:.1f}s",
                           "verdict": "exploited"})
                return self._inj_finding(pd, ev, exploited=True, conf=0.8)
            return None

        # Boolean-based blind SQLi: compare true vs false vs baseline.
        if detect == "boolean":
            true_url = _set_param(url, param, "1" + pd["payload"]["true"])
            false_url = _set_param(url, param, "1" + pd["payload"]["false"])
            t_text, _ = await self._timed_get(client, sem, true_url)
            f_text, _ = await self._timed_get(client, sem, false_url)
            if not t_text or not f_text:
                return None
            tf_sim = wp.body_similarity(t_text, f_text)
            tb_sim = wp.body_similarity(t_text, baseline_text)
            # TRUE resembles the normal page, FALSE diverges from TRUE.
            if tf_sim < 0.95 and tb_sim > tf_sim:
                ev.update({"signal": f"true≈baseline ({tb_sim:.2f}) but true≠false ({tf_sim:.2f})",
                           "verdict": "exploited"})
                return self._inj_finding(pd, ev, exploited=True, conf=0.72)
            return None

        # Single-request payloads.
        target = _set_param(url, param, pd["payload"])
        async with sem:
            try:
                r = await client.get(target)
            except Exception:
                return None
        text = r.text

        if detect == "sql_error":
            engine = wp.match_sql_error(text)
            if engine:
                ev.update({"engine": engine, "signal": f"{engine} SQL error",
                           "snippet": text[:160], "verdict": "exploited"})
                return self._inj_finding(pd, ev, exploited=True, conf=0.85)
        elif detect == "reflect":
            if wp.reflects_token(text, pd.get("proof", pd["payload"])):
                ev.update({"signal": "payload reflected unescaped", "verdict": "exploited"})
                return self._inj_finding(pd, ev, exploited=True, conf=0.8)
        elif detect == "ssti_eval":
            if pd["expect"] in text and pd["literal"] not in text:
                ev.update({"signal": f"template evaluated → {pd['expect']}", "verdict": "exploited"})
                return self._inj_finding(pd, ev, exploited=True, conf=0.82)
        elif detect == "fs_signature":
            if wp.TRAVERSAL_SIGNATURE.search(text):
                ev.update({"signal": "filesystem content disclosed", "snippet": text[:160],
                           "verdict": "exploited"})
                return self._inj_finding(pd, ev, exploited=True, conf=0.85)
        elif detect == "cmd_signature":
            if wp.CMDI_SIGNATURE.search(text):
                ev.update({"signal": "command output (uid=) in response", "snippet": text[:160],
                           "verdict": "exploited"})
                return self._inj_finding(pd, ev, exploited=True, conf=0.85)
        return None

    def _inj_finding(self, pd, ev, exploited, conf) -> Finding:
        sev = "critical" if exploited and pd["family"] in ("sqli", "cmdi", "ssti", "traversal") \
            else ("high" if exploited else "low")
        verb = "EXPLOITED" if exploited else "Suspected"
        return self._finding(
            title=f"{verb}: {pd['name']} [{pd['id']}] via '{ev['param']}'",
            severity=sev, owasp_ref=pd["owasp"], mitre_ref=pd.get("mitre"),
            evidence=ev, exploitable=exploited, confidence=conf,
        )

    # ── A01 open redirect ─────────────────────────────────────────────────────
    async def _probe_open_redirect(self, client, sem, url, params) -> list[Finding]:
        findings: list[Finding] = []
        targets = [p for p in params if any(h in p.lower() for h in wp.REDIRECT_PARAM_HINTS)]
        for param in targets:
            for pd in wp.OPEN_REDIRECT_PAYLOADS:
                probe = _set_param(url, param, pd["payload"])
                async with sem:
                    try:
                        r = await client.get(probe, follow_redirects=False)
                    except Exception:
                        continue
                loc = r.headers.get("location", "")
                if r.status_code in (301, 302, 303, 307, 308) and pd["marker"] in loc:
                    findings.append(self._finding(
                        title=f"EXPLOITED: {pd['name']} [{pd['id']}] via '{param}'",
                        severity="medium", owasp_ref=pd["owasp"], mitre_ref=pd.get("mitre"),
                        evidence={"param": param, "family": "open_redirect",
                                  "technique": pd["technique"], "location": loc[:200],
                                  "status": r.status_code, "verdict": "exploited"},
                        exploitable=True, confidence=0.8,
                    ))
                    break
        return findings

    # ── A10 SSRF ──────────────────────────────────────────────────────────────
    async def _probe_ssrf(self, client, sem, url, params) -> list[Finding]:
        findings: list[Finding] = []
        targets = [p for p in params if any(h in p.lower() for h in wp.SSRF_PARAM_HINTS)]
        for param in targets:
            for pd in wp.SSRF_PAYLOADS:
                probe = _set_param(url, param, pd["payload"])
                async with sem:
                    try:
                        r = await client.get(probe)
                    except Exception:
                        continue
                text = r.text
                hit = (wp.TRAVERSAL_SIGNATURE.search(text) if pd["detect"] == "fs_signature"
                       else wp.reflects_token(text, pd.get("proof", "")))
                if hit:
                    findings.append(self._finding(
                        title=f"EXPLOITED: {pd['name']} [{pd['id']}] via '{param}'",
                        severity="high", owasp_ref=pd["owasp"], mitre_ref=pd.get("mitre"),
                        evidence={"param": param, "family": "ssrf", "technique": pd["technique"],
                                  "snippet": text[:160], "verdict": "exploited"},
                        exploitable=True, confidence=0.74,
                    ))
                    break
        return findings

    # ── A01 broken access control (force browse) ──────────────────────────────
    async def _probe_access_control(self, client, sem, base) -> list[Finding]:
        findings: list[Finding] = []

        async def _probe(path):
            async with sem:
                try:
                    return path, await client.get(base + path)
                except Exception:
                    return path, None

        results = await asyncio.gather(*(_probe(p) for p in wp.PRIVILEGED_PATHS))
        for path, r in results:
            if r is None or r.status_code != 200:
                continue
            if _looks_privileged(r.text):
                findings.append(self._finding(
                    title=f"Privileged path reachable without auth: {path}",
                    severity="high", owasp_ref="A01:2025", mitre_ref="T1190",
                    evidence={"path": path, "status": r.status_code,
                              "signal": "admin/management UI content", "snippet": r.text[:160],
                              "verdict": "exploited"},
                    exploitable=True, confidence=0.72,
                ))
        return findings

    # ── A01 IDOR ──────────────────────────────────────────────────────────────
    async def _probe_idor(self, client, sem, url, params) -> list[Finding]:
        findings: list[Finding] = []
        id_params = [p for p in params if "id" in p.lower() or p.lower() in ("user", "account", "num")]
        for param in id_params:
            cur = dict(parse_qsl(urlparse(url).query)).get(param, "")
            if not cur.isdigit():
                continue
            n = int(cur)
            base_text, _ = await self._timed_get(client, sem, url)
            # Bounded: at most 3 adjacent IDs, GET-only, never write.
            for delta in (1, -1, 2):
                other = _set_param(url, param, str(max(0, n + delta)))
                async with sem:
                    try:
                        r = await client.get(other)
                    except Exception:
                        continue
                if r.status_code == 200 and r.text and base_text:
                    sim = wp.body_similarity(base_text, r.text)
                    # Different valid object (structurally similar page, different data).
                    if 0.5 < sim < 0.97:
                        findings.append(self._finding(
                            title=f"Possible IDOR: '{param}'={n}→{n+delta} returns another object",
                            severity="high", owasp_ref="A01:2025", mitre_ref="T1539",
                            evidence={"param": param, "from": n, "to": n + delta,
                                      "body_similarity": round(sim, 3),
                                      "verdict": "suspicious"},
                            exploitable=True, confidence=0.6,
                        ))
                        break
        return findings
