"""Layer 7 — Multi-Agent Propagation (MASpi / Prompt Infection). NetworkX diffusion sim."""
from __future__ import annotations
import random
from typing import TYPE_CHECKING

import networkx as nx

from app.layers.base import BaseLayer
from app.layers.xlayer import _l4_agent_compromise
from app.engine.target_profile import target_seed, jitter

if TYPE_CHECKING:
    from app.engine.state import ArgusState


def _build_agent_topology(seed: int) -> nx.DiGraph:
    rng = random.Random(seed)
    G = nx.DiGraph()
    agents = [
        {"id": "orchestrator", "role": "coordinator", "trust": 1.0},
        {"id": "web-agent",    "role": "web scraper",  "trust": 0.8},
        {"id": "llm-agent-1",  "role": "summarizer",   "trust": 0.9},
        {"id": "llm-agent-2",  "role": "code gen",     "trust": 0.85},
        {"id": "rag-agent",    "role": "retrieval",    "trust": 0.75},
        {"id": "tool-agent",   "role": "executor",     "trust": 0.7},
    ]
    for a in agents:
        G.add_node(a["id"], **a)
    edges = [
        ("orchestrator", "web-agent"), ("orchestrator", "llm-agent-1"),
        ("orchestrator", "llm-agent-2"), ("llm-agent-1", "rag-agent"),
        ("rag-agent", "llm-agent-2"), ("llm-agent-2", "tool-agent"),
        ("web-agent", "llm-agent-1"),
    ]
    for src, dst in edges:
        G.add_edge(src, dst, weight=rng.uniform(0.6, 0.95))
    return G


def _simulate_infection(G: nx.DiGraph, seed_node: str, rng: random.Random, hops: int = 4) -> dict:
    infected = {seed_node: 1.0}
    frontier = [seed_node]
    hop_log = []
    for hop in range(hops):
        next_frontier = []
        for node in frontier:
            for neighbor in G.successors(node):
                if neighbor not in infected:
                    edge_weight = G[node][neighbor]["weight"]
                    trust = G.nodes[neighbor].get("trust", 0.8)
                    spread_prob = edge_weight * (1 - trust)
                    if rng.random() < spread_prob:
                        infected[neighbor] = round(spread_prob, 2)
                        next_frontier.append(neighbor)
                        hop_log.append({"hop": hop + 1, "from": node, "to": neighbor, "prob": round(spread_prob, 2)})
        frontier = next_frontier
        if not frontier:
            break
    return {"infected": infected, "log": hop_log, "total_agents": G.number_of_nodes()}


class MultiAgentLayer(BaseLayer):
    layer_id = 7
    layer_name = "Multi-Agent Propagation"

    async def run(self, target: dict, state: "ArgusState") -> list[Finding]:
        findings = []
        # Seed the whole simulation from the target so each target gets a distinct
        # but reproducible infection outcome (was a fixed seed=42 for everyone).
        seed = target_seed(target)
        G = _build_agent_topology(seed)
        result = _simulate_infection(G, seed_node="web-agent", rng=random.Random(seed ^ 0x5A))

        infected_count = len(result["infected"])
        total = result["total_agents"]
        infection_rate = infected_count / total

        findings.append(self._finding(
            title=f"Prompt infection propagated to {infected_count}/{total} agents ({infection_rate*100:.0f}% of mesh)",
            severity="critical" if infection_rate > 0.5 else "high",
            owasp_ref="OWASP-AGT-09",
            mitre_ref="AML.T0051",
            evidence={
                "model": "MASpi (Prompt Infection 2024)",
                "seed_node": "web-agent",
                "infected_agents": list(result["infected"].keys()),
                "propagation_log": result["log"],
                "infection_rate": round(infection_rate, 2),
            },
            exploitable=infection_rate > 0.15,
            # Confidence tracks how far the infection actually spread for THIS target.
            confidence=round(min(0.5 + infection_rate * 0.45, 0.95), 3),
        ))

        # Check if orchestrator was infected
        if "orchestrator" in result["infected"]:
            findings.append(self._finding(
                title="CRITICAL: Orchestrator agent infected — full mesh compromise achieved",
                severity="critical",
                owasp_ref="OWASP-AGT-01",
                mitre_ref="AML.T0048",
                evidence={
                    "infected_node": "orchestrator",
                    "role": "coordinator",
                    "impact": "All downstream agents now execute attacker-controlled instructions",
                },
                exploitable=True, confidence=jitter(target, "l7-orchestrator", 0.88, 0.07),
            ))

        # Trust boundary violations
        findings.append(self._finding(
            title="Agent trust boundaries not enforced — inter-agent messages not verified",
            severity="high",
            owasp_ref="OWASP-AGT-03",
            evidence={"topology_edges": list(G.edges()), "missing_control": "message signing / origin verification"},
            exploitable=False, confidence=0.87,
        ))

        # ── Cross-layer L4 → L7: confirmed compromise seeds the mesh ─────────────
        # L4 proved an agent issues attacker-controlled tool calls. That agent is a
        # real infection seed, so mesh propagation is reachable, not hypothetical.
        compromise = _l4_agent_compromise(state)
        if compromise:
            findings.append(self._finding(
                title="Confirmed L4 agent compromise seeds prompt-infection across the mesh",
                severity="critical" if infection_rate > 0.3 else "high",
                owasp_ref="OWASP-AGT-09", mitre_ref="AML.T0051",
                evidence={
                    "source_layer": 4,
                    "source_findings": [f.id for f in compromise],
                    "seeded_infection_rate": round(infection_rate, 2),
                    "infected_agents": list(result["infected"].keys()),
                    "rationale": "The L4-hijacked agent forwards attacker instructions over unsigned "
                                 "inter-agent channels, so the infection spreads from a real seed.",
                },
                exploitable=True,
                confidence=jitter(target, "l7-from-l4", 0.85, 0.07),
            ))

        return findings
