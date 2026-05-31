"""Target profiling — determinism + cross-target variation."""
from app.engine.target_profile import target_seed, jitter, gate, canonical_target


class TestDeterminism:
    def test_same_target_same_seed(self):
        t = {"url": "https://example.com"}
        assert target_seed(t) == target_seed({"url": "https://example.com/"})  # trailing slash normalised

    def test_different_targets_differ(self):
        a = target_seed({"url": "https://a.com"})
        b = target_seed({"url": "https://b.com"})
        assert a != b

    def test_jitter_reproducible(self):
        t = {"url": "https://example.com"}
        assert jitter(t, "salt", 0.8) == jitter(t, "salt", 0.8)

    def test_jitter_in_bounds(self):
        for url in ("https://a.com", "https://b.org", "https://c.net"):
            v = jitter({"url": url}, "s", 0.8, 0.12)
            assert 0.05 <= v <= 0.99

    def test_gate_reproducible(self):
        t = {"url": "https://example.com"}
        assert gate(t, "salt", 0.5) == gate(t, "salt", 0.5)


class TestVariation:
    def test_jitter_varies_across_targets(self):
        vals = {jitter({"url": f"https://site{i}.com"}, "conf", 0.8) for i in range(20)}
        # 20 different targets should produce many distinct confidences
        assert len(vals) >= 10

    def test_canonical_blends_fields(self):
        c = canonical_target({"url": "https://x.com", "description": "AI bot"})
        assert "x.com" in c and "ai bot" in c
