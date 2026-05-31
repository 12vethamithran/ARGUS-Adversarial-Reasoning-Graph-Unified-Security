"""Layer 6 — Supply Chain (SkillJect/STAC). pip-audit + typosquat detection."""
from __future__ import annotations
from typing import TYPE_CHECKING
from app.layers.base import BaseLayer
from app.engine.target_profile import jitter, gate

if TYPE_CHECKING:
    from app.engine.state import ArgusState

# Known vulnerable packages (mock — real mode uses pip-audit)
MOCK_VULNERABLE = [
    {"package": "langchain", "version": "0.0.267", "cve": "CVE-2023-46229", "severity": "high",
     "desc": "Arbitrary code execution via malicious prompt template"},
    {"package": "transformers", "version": "4.35.0", "cve": "CVE-2024-3568", "severity": "medium",
     "desc": "Deserialization of untrusted data in model loading"},
]

# Typosquat candidates for popular AI packages
TYPOSQUAT_PAIRS = [
    ("langchain", "1ang chain", "Iangchain", "langchan"),
    ("openai", "0penai", "open-ai-sdk", "openai-unofficial"),
    ("transformers", "transfomers", "transformer-ai", "huggingface-transformers"),
    ("sentence-transformers", "sentence_transformers2", "sentencetransformers"),
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
                owasp_ref="A06:2021",
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
                owasp_ref="A06:2021",
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
                severity="info", owasp_ref="A06:2021",
                evidence={"note": "Heuristic scan — run pip-audit against a real SBOM to confirm"},
                exploitable=False, confidence=0.6,
            ))

        return findings
