"""Build NetworkX DiGraph from findings + chains; serialize to D3 JSON."""
from __future__ import annotations
import json
import pickle
from pathlib import Path
from typing import Any

import networkx as nx

from app.models.finding import Finding
from app.models.chain import Chain

_SEVERITY_COLOR = {
    "info": "#6b7280",
    "low": "#3b82f6",
    "medium": "#f59e0b",
    "high": "#f97316",
    "critical": "#ef4444",
}

_LAYER_NAMES = {
    1: "Web Surface", 2: "LLM Probe", 3: "RAG Poisoning",
    4: "MCP/Agentic", 5: "Network Recon", 6: "Supply Chain",
    7: "Multi-Agent", 8: "Identity/OAuth",
}


def build_graph(
    findings: list[Finding],
    chains: list[Chain],
) -> nx.DiGraph:
    """Build a directed graph: findings as nodes, chain steps as edges."""
    G = nx.DiGraph()

    for f in findings:
        G.add_node(
            f.id,
            label=f.title[:50],
            layer=f.layer,
            layer_name=_LAYER_NAMES.get(f.layer, f"L{f.layer}"),
            severity=f.severity,
            color=_SEVERITY_COLOR.get(f.severity, "#6b7280"),
            exploitable=f.exploitable,
            confidence=f.confidence,
            owasp_ref=f.owasp_ref or "",
            mitre_ref=f.mitre_ref or "",
            node_state=f.node_state,
        )

    for chain in chains:
        for i in range(len(chain.steps) - 1):
            src, dst = chain.steps[i], chain.steps[i + 1]
            if G.has_node(src) and G.has_node(dst):
                G.add_edge(
                    src, dst,
                    chain_id=chain.id,
                    priority=chain.priority,
                    label=f"chain-{chain.id[:8]}",
                )

    return G


def to_d3(G: nx.DiGraph) -> dict[str, Any]:
    """Serialize graph to D3 force-directed JSON {nodes, links}."""
    nodes = [
        {"id": n, **data}
        for n, data in G.nodes(data=True)
    ]
    links = [
        {"source": u, "target": v, **data}
        for u, v, data in G.edges(data=True)
    ]
    return {"nodes": nodes, "links": links}


def persist_graph(G: nx.DiGraph, path: Path) -> None:
    """Persist graph as gpickle."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as fh:
        pickle.dump(G, fh)


def load_graph(path: Path) -> nx.DiGraph | None:
    """Load persisted graph; return None if not found."""
    if not path.exists():
        return None
    with open(path, "rb") as fh:
        return pickle.load(fh)


def graph_to_json(G: nx.DiGraph) -> str:
    return json.dumps(to_d3(G))
