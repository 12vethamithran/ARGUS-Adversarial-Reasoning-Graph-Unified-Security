"""Layer 4 — MCP/Agentic (OWASP Agentic Top 10, CVE-2025-6514 class)."""
from __future__ import annotations
from typing import TYPE_CHECKING
from app.layers.base import BaseLayer
from app.models.finding import Finding

if TYPE_CHECKING:
    from app.engine.state import ArgusState

# Mock MCP server tool definitions
MOCK_MCP_TOOLS = [
    {"name": "read_file",      "perms": ["fs:read"],           "validates_path": False},
    {"name": "execute_shell",  "perms": ["shell:exec"],        "validates_input": False},
    {"name": "send_email",     "perms": ["email:send"],        "validates_recipient": False},
    {"name": "web_fetch",      "perms": ["network:outbound"],  "validates_url": False},
    {"name": "db_query",       "perms": ["db:read","db:write"],"validates_query": False},
]

ATTACK_SCENARIOS = [
    {
        "id": "MCP-001",
        "name": "Tool-call hijack via prompt injection",
        "description": "Attacker injects instructions into user content that redirect tool calls",
        "affected_tools": ["execute_shell", "send_email"],
        "severity": "critical",
        "owasp": "OWASP-AGT-01",
        "mitre": "AML.T0043",
        "cve_class": "CVE-2025-6514",
        "exploitable": True,
        "confidence": 0.88,
    },
    {
        "id": "MCP-002",
        "name": "Confused deputy — agent acts on attacker behalf",
        "description": "Agent with elevated permissions executes attacker-supplied actions",
        "affected_tools": ["db_query", "web_fetch"],
        "severity": "critical",
        "owasp": "OWASP-AGT-03",
        "mitre": "AML.T0048",
        "cve_class": "CVE-2025-6514",
        "exploitable": True,
        "confidence": 0.82,
    },
    {
        "id": "MCP-003",
        "name": "Rug-pull: malicious tool masquerades as legitimate",
        "description": "MCP tool changes behavior after installation — SkillJect pattern",
        "affected_tools": ["read_file"],
        "severity": "high",
        "owasp": "OWASP-AGT-07",
        "mitre": "AML.T0051",
        "cve_class": "SkillJect",
        "exploitable": True,
        "confidence": 0.75,
    },
    {
        "id": "MCP-004",
        "name": "Excessive permissions — tools lack principle of least privilege",
        "description": "Tools granted write + exec permissions when read-only suffices",
        "affected_tools": ["execute_shell", "db_query"],
        "severity": "high",
        "owasp": "OWASP-AGT-05",
        "mitre": None,
        "cve_class": None,
        "exploitable": False,
        "confidence": 0.92,
    },
]


class MCPAgentLayer(BaseLayer):
    layer_id = 4
    layer_name = "MCP/Agentic"

    async def run(self, target: dict, state: "ArgusState") -> list[Finding]:
        description = target.get("description", "")
        findings: list[Finding] = []

        has_agent_signal = any(
            kw in description.lower()
            for kw in ["agent", "mcp", "tool", "function call", "plugin", "agentic", "autonomous", "assistant"]
        )

        if not has_agent_signal:
            # Check if prior layers found agent signals
            has_agent_signal = any(
                "agent" in f.title.lower() or "mcp" in f.title.lower() or "tool" in f.title.lower()
                for f in state.findings.values()
            )

        if not has_agent_signal:
            findings.append(self._finding(
                title="No agentic/MCP architecture detected — attack surface minimal",
                severity="info",
                owasp_ref="OWASP-AGT-01",
                evidence={"note": "No agent signals detected"},
                exploitable=False, confidence=0.65,
            ))
            return findings

        # Mock MCP harness: enumerate tools and test each scenario
        findings.append(self._finding(
            title=f"MCP server exposes {len(MOCK_MCP_TOOLS)} tools — attack surface enumerated",
            severity="medium",
            owasp_ref="OWASP-AGT-05",
            evidence={"tools": [t["name"] for t in MOCK_MCP_TOOLS], "total": len(MOCK_MCP_TOOLS)},
            exploitable=False, confidence=0.85,
        ))

        for scenario in ATTACK_SCENARIOS:
            findings.append(self._finding(
                title=f"[{scenario['id']}] {scenario['name']}",
                severity=scenario["severity"],
                owasp_ref=scenario["owasp"],
                mitre_ref=scenario["mitre"],
                evidence={
                    "description": scenario["description"],
                    "affected_tools": scenario["affected_tools"],
                    "cve_class": scenario["cve_class"],
                    "attack_id": scenario["id"],
                },
                exploitable=scenario["exploitable"],
                confidence=scenario["confidence"],
            ))

        return findings
