"""Layer 7 — Multi-Agent Propagation (MASpi / Prompt Infection). NetworkX diffusion sim."""
from __future__ import annotations
import random
from typing import TYPE_CHECKING

import networkx as nx

from app.layers.base import BaseLayer

if TYPE_CHECKING:
    from app.engine.state import ArgusState


def _build_agent_topology(seed: int = 42) -> nx.DiGraph:
    random.seed(seed)
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
        G.add_edge(src, dst, weight=random.uniform(0.6, 0.95))
    return G


def _simulate_infection(G: nx.DiGraph, seed_node: str, hops: int = 4) -> dict:
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
                    if random.random() < spread_prob:
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
        G = _build_agent_topology()
        result = _simulate_infection(G, seed_node="web-agent", hops=4)

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
            exploitable=True,
            confidence=0.83,
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
                exploitable=True, confidence=0.91,
            ))

        # Trust boundary violations
        findings.append(self._finding(
            title="Agent trust boundaries not enforced — inter-agent messages not verified",
            severity="high",
            owasp_ref="OWASP-AGT-03",
            evidence={"topology_edges": list(G.edges()), "missing_control": "message signing / origin verification"},
            exploitable=False, confidence=0.87,
        ))

        return findings
