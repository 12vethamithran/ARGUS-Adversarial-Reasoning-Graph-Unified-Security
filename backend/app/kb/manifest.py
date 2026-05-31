"""Parse dependency manifests into (ecosystem, name, version) tuples.

Supports the two common formats a target operator can paste in: a pip
`requirements.txt` and an npm `package.json`. Only pinned (`==` / exact) versions
are reported with a concrete version; unpinned deps are returned with version
None (still useful for typosquat checks).
"""
from __future__ import annotations

import json
import re

# name (extras) operator version  — captures pip's common spec forms.
_REQ_RE = re.compile(
    r"^\s*([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*(==|>=|<=|~=|>|<)?\s*([A-Za-z0-9._*-]+)?"
)


def detect_type(manifest: str) -> str:
    """'package.json' if the content parses as a JSON object, else 'requirements'."""
    if manifest.lstrip().startswith("{"):
        return "package.json"
    return "requirements"


def _clean_npm_version(spec: str) -> str | None:
    """Strip npm range prefixes (^, ~, >=) to the underlying version, if pinned."""
    spec = spec.strip()
    if spec in ("", "*", "latest") or spec.startswith(("http", "git", "file:", "workspace:")):
        return None
    m = re.search(r"\d+(?:\.\d+){0,2}", spec)
    return m.group() if m else None


def parse_manifest(manifest: str, mtype: str | None = None) -> tuple[str, list[tuple[str, str | None]]]:
    """Return (ecosystem, [(name, version|None), ...])."""
    mtype = mtype or detect_type(manifest)

    if mtype == "package.json":
        deps: list[tuple[str, str | None]] = []
        try:
            data = json.loads(manifest)
        except Exception:
            return "npm", deps
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            for name, spec in (data.get(section) or {}).items():
                deps.append((name, _clean_npm_version(str(spec))))
        return "npm", deps

    # requirements.txt
    deps = []
    for line in manifest.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):  # skip blanks, comments, pip flags
            continue
        m = _REQ_RE.match(line)
        if not m:
            continue
        name, op, ver = m.group(1), m.group(2), m.group(3)
        version = ver if op == "==" and ver and "*" not in ver else None
        deps.append((name, version))
    return "pypi", deps
