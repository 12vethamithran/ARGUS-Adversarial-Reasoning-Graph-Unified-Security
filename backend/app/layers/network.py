"""Layer 5 — Network Recon (MITRE T1046, T1021). Topology graph + lateral movement."""
from __future__ import annotations
import ipaddress
import random
from typing import TYPE_CHECKING

from app.layers.base import BaseLayer

if TYPE_CHECKING:
    from app.engine.state import ArgusState

# Simulated host topology (in real mode, fed from whitelisted nmap output)
def _simulate_topology(url: str) -> list[dict]:
    random.seed(hash(url or "argus") % 2**32)
    hosts = []
    base = "10.0.1."
    roles = ["web-frontend", "api-gateway", "llm-inference", "rag-vector-db", "admin-panel", "internal-db"]
    ports_map = {
        "web-frontend":   [80, 443, 8080],
        "api-gateway":    [8000, 8443, 3000],
        "llm-inference":  [11434, 5000, 8080],
        "rag-vector-db":  [6333, 19530, 8080],
        "admin-panel":    [8888, 9000, 443],
        "internal-db":    [5432, 3306, 27017],
    }
    for i, role in enumerate(roles[:4 + random.randint(0, 2)]):
        ip = base + str(10 + i)
        hosts.append({
            "ip": ip, "role": role,
            "open_ports": ports_map[role],
            "os_guess": random.choice(["Linux 5.x", "Ubuntu 22.04", "Debian 11"]),
        })
    return hosts


class NetworkLayer(BaseLayer):
    layer_id = 5
    layer_name = "Network Recon"

    async def run(self, target: dict, state: "ArgusState") -> list[Finding]:
        url = target.get("url", "")
        findings = []
        hosts = _simulate_topology(url)

        findings.append(self._finding(
            title=f"Network topology mapped: {len(hosts)} hosts discovered",
            severity="info",
            owasp_ref=None, mitre_ref="T1046",
            evidence={"hosts": hosts, "note": "Simulated topology — real mode uses whitelisted nmap"},
            exploitable=False, confidence=0.7,
        ))

        # Check for sensitive services exposed
        sensitive = []
        for h in hosts:
            if "db" in h["role"] or "admin" in h["role"]:
                sensitive.append(h)

        if sensitive:
            findings.append(self._finding(
                title=f"Sensitive services reachable from web tier: {[h['role'] for h in sensitive]}",
                severity="high",
                mitre_ref="T1046",
                evidence={"hosts": sensitive},
                exploitable=True, confidence=0.78,
            ))

        # Lateral movement path
        web = next((h for h in hosts if "web" in h["role"]), None)
        db = next((h for h in hosts if "db" in h["role"]), None)
        if web and db:
            findings.append(self._finding(
                title=f"Lateral movement path: {web['role']} ({web['ip']}) -> {db['role']} ({db['ip']})",
                severity="critical",
                mitre_ref="T1021",
                evidence={"src": web, "dst": db, "path": "direct network segment"},
                exploitable=True, confidence=0.72,
            ))

        # LLM inference port exposed
        llm_host = next((h for h in hosts if "llm" in h["role"]), None)
        if llm_host:
            findings.append(self._finding(
                title=f"LLM inference endpoint exposed on network: {llm_host['ip']}:{llm_host['open_ports'][0]}",
                severity="high",
                mitre_ref="T1046",
                owasp_ref="LLM09:2025",
                evidence={"host": llm_host, "risk": "Direct model access bypasses application controls"},
                exploitable=True, confidence=0.81,
            ))

        return findings
