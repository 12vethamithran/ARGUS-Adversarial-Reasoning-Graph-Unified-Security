from app.engine.reasoner import _heuristic_chains
from app.models.finding import Finding


def _finding(layer: int, title: str, ref: str) -> Finding:
    return Finding(
        layer=layer,
        title=title,
        severity="high",
        exploitable=True,
        confidence=0.86,
        owasp_ref=ref,
    )


def test_heuristic_chains_include_reasoning_and_layer_path():
    tokens: list[str] = []
    findings = [
        _finding(1, "Reflected input reaches model context", "A03:2021"),
        _finding(2, "Prompt injection alters tool intent", "LLM01:2025"),
        _finding(5, "Internal service reachable from agent", "T1021"),
    ]

    chains = _heuristic_chains(findings, tokens.append)

    assert chains
    chain = chains[0]
    assert chain.layer_path == [1, 2, 5]
    assert chain.reasoning
    assert "Attacker starts with" in chain.narrative
    assert len(chain.remediations) == 3
    assert "Security domains touched" in " ".join(chain.reasoning)
