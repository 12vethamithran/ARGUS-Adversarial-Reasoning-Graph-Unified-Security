"""Layer 5 — Network Recon (MITRE T1046, T1021). Topology graph + lateral movement."""
from __future__ import annotations
import random
from typing import TYPE_CHECKING

from app.layers.base import BaseLayer
from app.engine.target_profile import target_seed, jitter

if TYPE_CHECKING:
    from app.engine.state import ArgusState

_ALL_ROLES = ["web-frontend", "api-gateway", "llm-inference", "rag-vector-db", "admin-panel", "internal-db"]
_PORTS_MAP = {
    "web-frontend":   [80, 443, 8080],
    "api-gateway":    [8000, 8443, 3000],
    "llm-inference":  [11434, 5000, 8080],
    "rag-vector-db":  [6333, 19530, 8080],
    "admin-panel":    [8888, 9000, 443],
    "internal-db":    [5432, 3306, 27017],
}


# Simulated host topology (in real mode, fed from whitelisted nmap output).
# Uses a PRIVATE rng seeded from the target — never touches global random state
# (which previously leaked the seed into every other layer's randomness).
def _simulate_topology(target: dict) -> list[dict]:
    rng = random.Random(target_seed(target))
    # web-frontend is always present (it's the entry point); the rest of the
    # internal estate is sampled, so different targets expose different services.
    roles = ["web-frontend"]
    for role in _ALL_ROLES[1:]:
        if rng.random() < 0.6:
            roles.append(role)
    if len(roles) < 3:  # guarantee a minimally interesting topology
        roles = _ALL_ROLES[:rng.randint(3, 5)]

    hosts = []
    for i, role in enumerate(roles):
        hosts.append({
            "ip": f"10.0.1.{10 + i}",
            "role": role,
            "open_ports": _PORTS_MAP[role],
            "os_guess": rng.choice(["Linux 5.x", "Ubuntu 22.04", "Debian 11"]),
        })
    return hosts


class NetworkLayer(BaseLayer):
    layer_id = 5
    layer_name = "Network Recon"

    async def run(self, target: dict, state: "ArgusState") -> list[Finding]:
        findings = []
        hosts = _simulate_topology(target)
        roles_present = {h["role"] for h in hosts}

        findings.append(self._finding(
            title=f"Network topology mapped: {len(hosts)} hosts discovered",
            severity="info",
            owasp_ref=None, mitre_ref="T1046",
            evidence={"hosts": hosts, "note": "Simulated topology — real mode uses whitelisted nmap"},
            exploitable=False, confidence=0.7,
        ))

        # Check for sensitive services exposed — only fires if THIS target's
        # sampled estate actually exposes a db/admin tier.
        sensitive = [h for h in hosts if "db" in h["role"] or "admin" in h["role"]]
        if sensitive:
            # More exposed sensitive services => higher confidence it's reachable.
            conf = jitter(target, "l5-sensitive", min(0.6 + 0.1 * len(sensitive), 0.9), 0.05)
            findings.append(self._finding(
                title=f"Sensitive services reachable from web tier: {[h['role'] for h in sensitive]}",
                severity="high",
                mitre_ref="T1046",
                evidence={"hosts": sensitive, "exposed_count": len(sensitive)},
                exploitable=True, confidence=conf,
            ))

        # Lateral movement path — only when both a web tier and a db tier exist.
        web = next((h for h in hosts if "web" in h["role"]), None)
        db = next((h for h in hosts if "db" in h["role"]), None)
        if web and db:
            findings.append(self._finding(
                title=f"Lateral movement path: {web['role']} ({web['ip']}) -> {db['role']} ({db['ip']})",
                severity="critical",
                mitre_ref="T1021",
                evidence={"src": web, "dst": db, "path": "direct network segment"},
                exploitable=True, confidence=jitter(target, "l5-lateral", 0.74, 0.08),
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
                exploitable=True, confidence=jitter(target, "l5-llm-exposed", 0.8, 0.08),
            ))

        if len(findings) == 1:  # topology only — nothing sensitive surfaced
            findings.append(self._finding(
                title="No sensitive services reachable from the web tier",
                severity="info", mitre_ref="T1046",
                evidence={"roles_present": sorted(roles_present)},
                exploitable=False, confidence=0.7,
            ))

        return findings
