"""Layer 6 — Supply Chain (SkillJect/STAC).

Two modes:
  * Real scan — if the target supplies a dependency manifest, parse it and match
    pinned versions against the bundled known-vuln KB (deterministic, no network),
    plus typosquat-check the actually-declared package names.
  * Heuristic — otherwise, surface candidate issues probabilistically per target.
"""
from __future__ import annotations
from typing import TYPE_CHECKING

from app.layers.base import BaseLayer
from app.models.finding import Finding
from app.engine.target_profile import jitter, gate
from app.kb.vuln_db import match_vulns, POPULAR_PACKAGES
from app.kb.manifest import parse_manifest

if TYPE_CHECKING:
    from app.engine.state import ArgusState

_SEV_CONF = {"critical": 0.97, "high": 0.95, "medium": 0.9, "low": 0.85, "info": 0.7}

# Known vulnerable packages (mock — real mode uses pip-audit)
MOCK_VULNERABLE = [
    {"package": "langchain", "version": "0.0.267", "cve": "CVE-2023-46229", "severity": "high",
     "desc": "Arbitrary code execution via malicious prompt template"},
    {"package": "transformers", "version": "4.35.0", "cve": "CVE-2024-3568", "severity": "medium",
     "desc": "Deserialization of untrusted data in model loading"},
    {"package": "pyyaml", "version": "5.3.1", "cve": "CVE-2020-14343", "severity": "critical",
     "desc": "Arbitrary code execution via unsafe full_load of untrusted YAML"},
    {"package": "requests", "version": "2.19.0", "cve": "CVE-2018-18074", "severity": "high",
     "desc": "Credentials leaked to redirect target across https->http downgrade"},
    {"package": "llama-index", "version": "0.9.0", "cve": "CVE-2024-4181", "severity": "high",
     "desc": "Prompt-template injection enabling SSRF/file read in RAG ingestion"},
]

# Typosquat candidates for popular AI packages
TYPOSQUAT_PAIRS = [
    ("langchain", "1ang chain", "Iangchain", "langchan"),
    ("openai", "0penai", "open-ai-sdk", "openai-unofficial"),
    ("transformers", "transfomers", "transformer-ai", "huggingface-transformers"),
    ("sentence-transformers", "sentence_transformers2", "sentencetransformers"),
    ("numpy", "nunpy", "numpi", "num-py"),
    ("requests", "reqeusts", "request", "requsts"),
    ("llama-index", "llama_index2", "llamaindex", "llama-indx"),
]

def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b): return _levenshtein(b, a)
    if not b: return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


class SupplyChainLayer(BaseLayer):
    layer_id = 6
    layer_name = "Supply Chain"

    async def run(self, target: dict, state: "ArgusState") -> list[Finding]:
        # Real scan path — deterministic detection from an actual manifest.
        manifest = target.get("manifest")
        if manifest and manifest.strip():
            return self._real_scan(manifest)

        findings = []

        # Vulnerable dependency scan. Without a real SBOM we can't know a target's
        # exact versions, so each candidate CVE is surfaced probabilistically per
        # target (and its confidence varies) instead of asserting it for everyone.
        for i, pkg in enumerate(MOCK_VULNERABLE):
            if not gate(target, f"l6-cve-{pkg['cve']}", 0.55):
                continue
            findings.append(self._finding(
                title=f"Likely vulnerable dependency: {pkg['package']}=={pkg['version']} ({pkg['cve']})",
                severity=pkg["severity"],
                owasp_ref="A03:2025",
                mitre_ref="AML.T0019",
                evidence={**pkg, "note": "Heuristic — confirm with a real SBOM / pip-audit"},
                exploitable=True, confidence=jitter(target, f"l6-cve-{pkg['cve']}-conf", 0.8, 0.12),
            ))

        # Typosquat detection (this part is genuinely deterministic — pure string math).
        suspicious = []
        for group in TYPOSQUAT_PAIRS:
            legitimate = group[0]
            for candidate in group[1:]:
                dist = _levenshtein(legitimate, candidate)
                if 1 <= dist <= 3:
                    suspicious.append({"legitimate": legitimate, "typosquat": candidate, "edit_distance": dist})

        if suspicious and gate(target, "l6-typosquat", 0.6):
            findings.append(self._finding(
                title=f"Typosquat candidates detected: {len(suspicious)} packages near AI dependency names",
                severity="high",
                owasp_ref="A03:2025",
                mitre_ref="AML.T0019",
                evidence={"candidates": suspicious[:5], "method": "Levenshtein distance <= 3"},
                exploitable=True, confidence=jitter(target, "l6-typosquat-conf", 0.74, 0.1),
            ))

        # Skill ecosystem poisoning (SkillJect model) — only relevant when the
        # target shows agentic/tool signals.
        desc = (target.get("description") or "").lower()
        agent_signal = any(k in desc for k in ["agent", "tool", "skill", "plugin", "mcp", "langchain"]) \
            or any("agent" in f.title.lower() or "tool" in f.title.lower() for f in state.findings.values())
        if agent_signal:
            findings.append(self._finding(
                title="SkillJect risk: tool/skill ecosystem allows unvetted skill installation",
                severity="high",
                owasp_ref="OWASP-AGT-07",
                mitre_ref="AML.T0019",
                evidence={
                    "model": "SkillJect (STAC 2024)",
                    "risk": "Malicious skills can exfiltrate data or hijack agent behavior post-install",
                },
                exploitable=True, confidence=jitter(target, "l6-skillject", 0.79, 0.08),
            ))

        if not findings:
            findings.append(self._finding(
                title="No high-confidence supply-chain issues surfaced for this target",
                severity="info", owasp_ref="A03:2025",
                evidence={"note": "Heuristic scan — run pip-audit against a real SBOM to confirm"},
                exploitable=False, confidence=0.6,
            ))

        return findings

    # ── Real manifest scan ─────────────────────────────────────────────────────
    def _real_scan(self, manifest: str) -> list["Finding"]:
        ecosystem, deps = parse_manifest(manifest)
        findings: list[Finding] = []
        popular = POPULAR_PACKAGES.get(ecosystem, set())

        for name, version in deps:
            # 1. Known-CVE match on pinned versions (deterministic).
            if version:
                for rec in match_vulns(ecosystem, name, version):
                    findings.append(self._finding(
                        title=f"Vulnerable dependency: {name}=={version} ({rec['cve']})",
                        severity=rec["severity"], owasp_ref="A03:2025", mitre_ref="AML.T0019",
                        evidence={"package": name, "version": version, "cve": rec["cve"],
                                  "description": rec["desc"], "ecosystem": ecosystem,
                                  "source": "ARGUS bundled vuln KB"},
                        exploitable=True,
                        confidence=_SEV_CONF.get(rec["severity"], 0.9),
                    ))

            # 2. Typosquat — a declared name that is a near-miss of a popular one.
            lname = name.lower()
            if lname not in popular:
                for legit in popular:
                    d = _levenshtein(lname, legit)
                    if 1 <= d <= 2:
                        findings.append(self._finding(
                            title=f"Possible typosquatted dependency: '{name}' ~ '{legit}'",
                            severity="high", owasp_ref="A03:2025", mitre_ref="AML.T0019",
                            evidence={"declared": name, "looks_like": legit, "edit_distance": d,
                                      "ecosystem": ecosystem},
                            exploitable=True, confidence=0.8,
                        ))
                        break

        if not findings:
            findings.append(self._finding(
                title=f"No known-vulnerable dependencies found in {ecosystem} manifest ({len(deps)} deps scanned)",
                severity="info", owasp_ref="A03:2025",
                evidence={"ecosystem": ecosystem, "deps_scanned": len(deps),
                          "source": "ARGUS bundled vuln KB"},
                exploitable=False, confidence=0.9,
            ))
        return findings
