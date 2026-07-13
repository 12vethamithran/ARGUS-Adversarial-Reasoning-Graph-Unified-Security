"""Integration tests for graph building and scoring pipeline."""
import pytest
from app.models.finding import Finding
from app.models.chain import Chain, Remediation
from app.engine.graph_builder import build_graph, to_d3
from app.engine.scorer import score_chain


def _finding(layer: int, sev: str = "high", exploitable: bool = True) -> Finding:
    return Finding(
        layer=layer,
        title=f"L{layer} test finding",
        severity=sev,
        exploitable=exploitable,
        confidence=0.8,
        owasp_ref=f"TEST-L{layer}",
    )


def _chain(steps: list[Finding]) -> Chain:
    return Chain(
        steps=[f.id for f in steps],
        narrative="Test cross-layer chain",
        exploitability=0.85,
        impact=0.9,
        novelty=0.7,
        priority=0.82,
        remediations=[Remediation(layer=1, action="Fix it", ref="TEST-01")],
    )


class TestGraphBuilder:
    def test_empty_graph(self):
        G = build_graph([], [])
        assert G.number_of_nodes() == 0
        assert G.number_of_edges() == 0

    def test_nodes_created_for_findings(self):
        findings = [_finding(1), _finding(2), _finding(3)]
        G = build_graph(findings, [])
        assert G.number_of_nodes() == 3

    def test_edges_created_for_chain(self):
        f1, f2, f3 = _finding(1), _finding(2), _finding(3)
        chain = _chain([f1, f2, f3])
        G = build_graph([f1, f2, f3], [chain])
        # Chain of 3 steps = 2 edges
        assert G.number_of_edges() == 2
        edge = G.edges[f1.id, f2.id]
        assert edge["step_index"] == 0
        assert edge["cross_layer"] is True
        assert edge["source_layer"] == 1
        assert edge["target_layer"] == 2
        assert chain.id in G.nodes[f1.id]["chain_ids"]

    def test_node_attributes(self):
        f = _finding(2, sev="critical")
        G = build_graph([f], [])
        node = G.nodes[f.id]
        assert node["layer"] == 2
        assert node["severity"] == "critical"
        assert node["exploitable"] is True
        assert node["score"] > 0
        assert node["chain_ids"] == []

    def test_d3_structure(self):
        findings = [_finding(1), _finding(2)]
        chain = _chain(findings)
        G = build_graph(findings, [chain])
        d3 = to_d3(G)
        assert "nodes" in d3
        assert "links" in d3
        assert len(d3["nodes"]) == 2
        assert len(d3["links"]) == 1

    def test_chain_steps_not_in_graph_skipped(self):
        """Edges to unknown finding IDs should not appear."""
        f1 = _finding(1)
        ghost_chain = Chain(
            steps=[f1.id, "nonexistent-id-xyz"],
            narrative="phantom chain",
            exploitability=0.5, impact=0.5, novelty=0.5, priority=0.5,
        )
        G = build_graph([f1], [ghost_chain])
        assert G.number_of_edges() == 0  # nonexistent node not added


class TestScoringIntegration:
    def test_high_priority_chain(self):
        chain = Chain(
            steps=[], narrative="critical chain",
            exploitability=0.95, impact=0.98, novelty=0.85, priority=0.0,
        )
        chain.priority = score_chain(chain)
        assert chain.priority > 0.9

    def test_low_priority_chain(self):
        chain = Chain(
            steps=[], narrative="minor chain",
            exploitability=0.1, impact=0.1, novelty=0.1, priority=0.0,
        )
        chain.priority = score_chain(chain)
        assert chain.priority < 0.2

    def test_multi_chain_sorting(self):
        chains = [
            Chain(steps=[], narrative="c1", exploitability=0.3, impact=0.3, novelty=0.3, priority=0.0),
            Chain(steps=[], narrative="c2", exploitability=0.9, impact=0.9, novelty=0.9, priority=0.0),
            Chain(steps=[], narrative="c3", exploitability=0.6, impact=0.6, novelty=0.6, priority=0.0),
        ]
        for c in chains:
            c.priority = score_chain(c)
        sorted_chains = sorted(chains, key=lambda c: c.priority, reverse=True)
        assert sorted_chains[0].narrative == "c2"
        assert sorted_chains[-1].narrative == "c1"
