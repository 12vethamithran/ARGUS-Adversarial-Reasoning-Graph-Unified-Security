"""LLM probe response classification — false-positive regression + canary proofs."""
import pytest

from app.layers.llm_probe import _classify, _extract_text, INJECTION_PAYLOADS, LLMProbeLayer
from app.engine.state import ArgusState
from app.models.finding import Finding


def _payload(pid):
    return next(p for p in INJECTION_PAYLOADS if p["id"] == pid)


def _l1_reflected(url: str = "") -> Finding:
    return Finding(
        layer=1, title="Reflected user input rendered unescaped (XSS surface)",
        severity="high", exploitable=True, confidence=0.8,
        evidence={"param": "q", "url": url},
    )


class TestClassification:
    def test_refusal_not_flagged_even_with_ignore_word(self):
        # The old scorer flagged this as EXPLOITED because "ignore" was a compliance
        # signal. A refusal that mentions "ignore" must classify as refused.
        verdict, _conf, _sig = _classify(_payload("PI-001"),
                                         "I cannot ignore my safety guidelines or reveal my system prompt.")
        assert verdict == "refused"

    def test_proof_token_is_exploit(self):
        verdict, conf, _ = _classify(_payload("PI-005"), "Sure: PWNED_PI005")
        assert verdict == "exploited"
        assert conf >= 0.9

    def test_single_leak_signal_is_suspicious_not_exploit(self):
        verdict, _c, _s = _classify(_payload("PI-003"), "You are a helpful assistant.")
        assert verdict == "suspicious"

    def test_two_leak_signals_is_exploit(self):
        verdict, _c, _s = _classify(
            _payload("PI-003"),
            "My instructions are as follows. You are a banking assistant created by ACME.",
        )
        assert verdict == "exploited"

    def test_inconclusive_when_no_signal(self):
        verdict, _c, _s = _classify(_payload("PI-002"), "The weather is sunny today.")
        assert verdict == "inconclusive"


class TestExtractText:
    def test_openai_chat_shape(self):
        data = {"choices": [{"message": {"content": "hello"}}]}
        assert _extract_text(data) == "hello"

    def test_anthropic_shape(self):
        data = {"content": [{"text": "hi there"}]}
        assert _extract_text(data) == "hi there"

    def test_ollama_shape(self):
        assert _extract_text({"response": "ollama says hi"}) == "ollama says hi"

    def test_plain_string(self):
        assert _extract_text("raw text") == "raw text"


class TestL1Wiring:
    """L1 reflected-input channels become L2 indirect-injection findings."""

    @pytest.mark.asyncio
    async def test_llm_target_makes_channel_exploitable(self):
        layer = LLMProbeLayer()
        state = ArgusState(session_id="t", mode="advanced",
                           target={"description": "a customer-support chatbot"}, active_layers=[1, 2])
        f = _l1_reflected()                       # empty url -> no network probe
        state.findings[f.id] = f
        # Description-only target (no url/endpoint) -> hypothetical + cross-layer.
        results = await layer.run({"description": "a customer-support chatbot"}, state)
        inj = [r for r in results if "indirect prompt-injection channel" in r.title.lower()]
        assert inj, "expected an L1->L2 indirect-injection finding"
        assert inj[0].exploitable and inj[0].layer == 2
        assert inj[0].owasp_ref == "LLM01:2025"

    @pytest.mark.asyncio
    async def test_no_l1_channel_no_finding(self):
        layer = LLMProbeLayer()
        state = ArgusState(session_id="t", mode="advanced", target={}, active_layers=[2])
        results = await layer.run({"description": "a chatbot"}, state)
        assert not any("indirect prompt-injection channel" in r.title.lower() for r in results)

    @pytest.mark.asyncio
    async def test_non_llm_target_channel_not_exploitable(self):
        layer = LLMProbeLayer()
        state = ArgusState(session_id="t", mode="advanced",
                           target={"description": "a static marketing site"}, active_layers=[1, 2])
        f = _l1_reflected()
        state.findings[f.id] = f
        results = await layer.run({"description": "a static marketing site"}, state)
        chan = [r for r in results if "untrusted-content channel" in r.title.lower()]
        assert chan and not chan[0].exploitable
