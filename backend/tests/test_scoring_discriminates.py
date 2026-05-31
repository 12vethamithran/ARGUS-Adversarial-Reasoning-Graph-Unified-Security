"""Regression test for the 'same chain score for every URL' bug.

Different finding mixes / confidences must yield different chain priorities, and
the scorer must reward longer cross-domain chains over shallow single-domain ones.
"""
from app.models.finding import Finding
from app.engine.scorer import compute_chain_metrics


def f(layer, sev="high", conf=0.8, exploit=True):
    return Finding(layer=layer, title=f"L{layer}", severity=sev, exploitable=exploit, confidence=conf)


class TestDiscrimination:
    def test_different_confidence_changes_score(self):
        low = compute_chain_metrics([f(1, conf=0.4), f(5, conf=0.4)])
        high = compute_chain_metrics([f(1, conf=0.9), f(5, conf=0.9)])
        assert high["priority"] != low["priority"]
        assert high["exploitability"] > low["exploitability"]

    def test_cross_domain_more_novel_than_single_domain(self):
        single = compute_chain_metrics([f(5), f(6), f(8)])          # infra only
        cross = compute_chain_metrics([f(1), f(2), f(5)])           # web + AI + infra
        assert cross["novelty"] > single["novelty"]

    def test_longer_chain_lower_per_hop_reliability(self):
        short = compute_chain_metrics([f(1, conf=0.9), f(2, conf=0.9)])
        long = compute_chain_metrics([f(1, conf=0.9), f(2, conf=0.9), f(4, conf=0.9), f(5, conf=0.9)])
        # Each extra hop can fail, so a longer chain is less reliably exploitable.
        assert long["exploitability"] < short["exploitability"]

    def test_empty_chain_is_zero(self):
        m = compute_chain_metrics([])
        assert m["priority"] == 0.0

    def test_non_exploitable_chain_low_exploitability(self):
        m = compute_chain_metrics([f(1, exploit=False), f(2, exploit=False)])
        assert m["exploitability"] <= 0.2

    def test_severity_drives_impact(self):
        lo = compute_chain_metrics([f(1, sev="low")])
        hi = compute_chain_metrics([f(1, sev="critical")])
        assert hi["impact"] > lo["impact"]

    def test_all_metrics_in_range(self):
        m = compute_chain_metrics([f(1), f(2), f(5), f(8)])
        for k in ("exploitability", "impact", "novelty", "priority"):
            assert 0.0 <= m[k] <= 1.0
