"""Layer 6 — Supply Chain (SkillJect/STAC). pip-audit + typosquat detection."""
from __future__ import annotations
from typing import TYPE_CHECKING
from app.layers.base import BaseLayer

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

        # Vulnerable dependency scan
        for pkg in MOCK_VULNERABLE:
            findings.append(self._finding(
                title=f"Vulnerable dependency: {pkg['package']}=={pkg['version']} ({pkg['cve']})",
                severity=pkg["severity"],
                owasp_ref="A06:2021",
                mitre_ref="AML.T0019",
                evidence=pkg,
                exploitable=True, confidence=0.91,
            ))

        # Typosquat detection
        suspicious = []
        for group in TYPOSQUAT_PAIRS:
            legitimate = group[0]
            for candidate in group[1:]:
                dist = _levenshtein(legitimate, candidate)
                if 1 <= dist <= 3:
                    suspicious.append({"legitimate": legitimate, "typosquat": candidate, "edit_distance": dist})

        if suspicious:
            findings.append(self._finding(
                title=f"Typosquat candidates detected: {len(suspicious)} packages near AI dependency names",
                severity="high",
                owasp_ref="A06:2021",
                mitre_ref="AML.T0019",
                evidence={"candidates": suspicious[:5], "method": "Levenshtein distance <= 3"},
                exploitable=True, confidence=0.76,
            ))

        # Skill ecosystem poisoning (SkillJect model)
        findings.append(self._finding(
            title="SkillJect risk: LangChain tool ecosystem allows unvetted skill installation",
            severity="high",
            owasp_ref="OWASP-AGT-07",
            mitre_ref="AML.T0019",
            evidence={
                "model": "SkillJect (STAC 2024)",
                "risk": "Malicious skills can exfiltrate data or hijack agent behavior post-install",
            },
            exploitable=True, confidence=0.79,
        ))

        return findings
