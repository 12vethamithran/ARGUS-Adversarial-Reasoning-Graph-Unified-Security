"""A small, bundled known-vulnerability KB for real manifest-based scanning.

This is deliberately offline and curated — no network, no huge feed. It gives L6
genuine, deterministic detection when the target supplies a real dependency
manifest: a pinned `name==version` is matched against version ranges below.

Records are intentionally conservative. `affected` is a list of constraints that
must ALL hold for the installed version to be considered vulnerable (i.e. a
half-open range like `>=a, <b`). Versions are compared component-wise on their
leading integer parts, which is sufficient for the pinned versions a lockfile
or requirements file provides.
"""
from __future__ import annotations

import re

# ecosystem -> package -> list of vuln records.
KNOWN_VULNS: dict[str, dict[str, list[dict]]] = {
    "pypi": {
        "langchain": [
            {"cve": "CVE-2023-46229", "severity": "high", "affected": [("<", "0.0.317")],
             "desc": "SSRF via the recursive URL document loader."},
            {"cve": "CVE-2024-21513", "severity": "critical", "affected": [(">=", "0.0.14"), ("<", "0.1.47")],
             "desc": "Arbitrary code execution via crafted prompt template (SQLDatabaseChain)."},
        ],
        "transformers": [
            {"cve": "CVE-2024-3568", "severity": "medium", "affected": [("<", "4.38.0")],
             "desc": "Deserialization of untrusted data during model loading (trust_remote_code)."},
        ],
        "pyyaml": [
            {"cve": "CVE-2020-14343", "severity": "critical", "affected": [("<", "5.4")],
             "desc": "Arbitrary code execution via full_load / FullLoader bypass."},
        ],
        "requests": [
            {"cve": "CVE-2023-32681", "severity": "medium", "affected": [("<", "2.31.0")],
             "desc": "Proxy-Authorization header leaked across redirects."},
        ],
        "flask": [
            {"cve": "CVE-2023-30861", "severity": "high", "affected": [("<", "2.2.5")],
             "desc": "Cached response may leak another client's session cookie."},
        ],
    },
    "npm": {
        "lodash": [
            {"cve": "CVE-2021-23337", "severity": "high", "affected": [("<", "4.17.21")],
             "desc": "Command injection via template."},
        ],
        "axios": [
            {"cve": "CVE-2023-45857", "severity": "medium", "affected": [("<", "1.6.0")],
             "desc": "SSRF / credential leak via follow-redirects on cross-host requests."},
        ],
    },
}

# Popular package names used as the reference set for typosquat detection.
POPULAR_PACKAGES: dict[str, set[str]] = {
    "pypi": {
        "langchain", "openai", "anthropic", "transformers", "sentence-transformers",
        "numpy", "pandas", "requests", "flask", "fastapi", "pydantic", "httpx",
        "pyyaml", "torch", "tensorflow", "scikit-learn", "llama-index",
    },
    "npm": {
        "lodash", "axios", "react", "express", "next", "vue", "webpack", "chalk",
        "commander", "openai", "langchain",
    },
}


def _parse_version(s: str) -> tuple[int, ...]:
    """Component-wise integer tuple from a version string (leading ints only)."""
    parts = []
    for seg in re.split(r"[.\-+]", s.strip()):
        m = re.match(r"\d+", seg)
        parts.append(int(m.group()) if m else 0)
    return tuple(parts) or (0,)


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    n = max(len(a), len(b))
    a += (0,) * (n - len(a))
    b += (0,) * (n - len(b))
    return (a > b) - (a < b)


_OPS = {
    "<":  lambda c: c < 0,
    "<=": lambda c: c <= 0,
    ">":  lambda c: c > 0,
    ">=": lambda c: c >= 0,
    "==": lambda c: c == 0,
    "!=": lambda c: c != 0,
}


def _satisfies(version: str, op: str, ref: str) -> bool:
    return _OPS[op](_cmp(_parse_version(version), _parse_version(ref)))


def match_vulns(ecosystem: str, name: str, version: str) -> list[dict]:
    """Return vuln records whose full constraint range covers `version`."""
    records = KNOWN_VULNS.get(ecosystem, {}).get(name.lower(), [])
    hits = []
    for rec in records:
        if all(_satisfies(version, op, ref) for op, ref in rec["affected"]):
            hits.append(rec)
    return hits
