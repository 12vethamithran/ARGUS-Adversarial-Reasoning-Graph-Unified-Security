import networkx as nx

from app.engine.graph_builder import load_graph, persist_graph


def test_graph_persistence_uses_json_round_trip(tmp_path):
    graph = nx.DiGraph()
    graph.add_node("a", severity="high")
    graph.add_edge("a", "b", chain_id="chain-1")

    path = tmp_path / "graph.gpickle"
    persist_graph(graph, path)

    raw = path.read_text(encoding="utf-8")
    assert raw.lstrip().startswith("{")

    loaded = load_graph(path)
    assert loaded is not None
    assert loaded.nodes["a"]["severity"] == "high"
    assert loaded.edges["a", "b"]["chain_id"] == "chain-1"
