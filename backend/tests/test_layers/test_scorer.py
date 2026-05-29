"""Unit tests for scorer.py — deterministic, no network."""
import pytest
from app.models.finding import Finding
from app.models.chain import Chain, Remediation
from app.engine.scorer import score_finding, score_chain


def make_finding(**kwargs) -> Finding:
    defaults = dict(layer=1, title="test", severity="medium", exploitable=False, confidence=0.5)
    return Finding(**{**defaults, **kwargs})


def make_chain(**kwargs) -> Chain:
    defaults = dict(
        steps=[], narrative="test chain",
        exploitability=0.5, impact=0.5, novelty=0.5, priority=0.5,
    )
    return Chain(**{**defaults, **kwargs})


class TestScoreFinding:
    def test_critical_exploitable_scores_high(self):
        # critical(1.0) * layer_weight(0.6) * conf(1.0) + exploitable_bonus(0.15) = 0.75
        f = make_finding(severity="critical", exploitable=True, confidence=1.0)
        s = score_finding(f)
        assert s >= 0.75

    def test_info_not_exploitable_scores_low(self):
        f = make_finding(severity="info", exploitable=False, confidence=0.3)
        s = score_finding(f)
        assert s < 0.3

    def test_score_in_range(self):
        for sev in ("info", "low", "medium", "high", "critical"):
            f = make_finding(severity=sev, confidence=0.8)
            s = score_finding(f)
            assert 0.0 <= s <= 1.0

    def test_exploitable_bonus_raises_score(self):
        f_base = make_finding(severity="high", exploitable=False, confidence=0.8)
        f_exploit = make_finding(severity="high", exploitable=True, confidence=0.8)
        assert score_finding(f_exploit) > score_finding(f_base)


class TestScoreChain:
    def test_weights_sum_correctly(self):
        c = make_chain(exploitability=1.0, impact=1.0, novelty=1.0)
        assert score_chain(c) == pytest.approx(1.0, abs=1e-4)

    def test_zero_chain(self):
        c = make_chain(exploitability=0.0, impact=0.0, novelty=0.0)
        assert score_chain(c) == pytest.approx(0.0, abs=1e-4)

    def test_partial_chain(self):
        c = make_chain(exploitability=0.8, impact=0.6, novelty=0.4)
        # 0.40*0.8 + 0.35*0.6 + 0.25*0.4 = 0.32 + 0.21 + 0.10 = 0.63
        assert score_chain(c) == pytest.approx(0.63, abs=0.01)

    def test_result_is_float_in_range(self):
        c = make_chain(exploitability=0.5, impact=0.7, novelty=0.3)
        s = score_chain(c)
        assert isinstance(s, float)
        assert 0.0 <= s <= 1.0
