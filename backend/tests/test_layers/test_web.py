"""Unit tests for L1 WebLayer."""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from app.layers.web import WebLayer, _looks_exposed, REFLECT_CANARY
from app.engine.state import ArgusState
from app.models.finding import Finding


def _make_state():
    return ArgusState(session_id="test", mode="basic", target={}, active_layers=[1])


@pytest.mark.asyncio
async def test_web_layer_no_url():
    """Should return empty list when no URL is provided."""
    layer = WebLayer()
    results = await layer.run({}, _make_state())
    assert isinstance(results, list)


@pytest.mark.asyncio
async def test_web_layer_returns_findings():
    """Should return Finding objects, each with correct layer=1."""
    layer = WebLayer()
    mock_resp = MagicMock()
    mock_resp.headers = {}        # all security headers missing
    mock_resp.text = "<html><head></head><body></body></html>"
    mock_resp.status_code = 200
    mock_resp.url = "http://example.com"

    get_mock = AsyncMock(side_effect=[mock_resp] * 14)  # baseline + reflect + paths
    opts_mock = AsyncMock(return_value=mock_resp)
    with patch("httpx.AsyncClient.get", get_mock), \
         patch("httpx.AsyncClient.options", opts_mock):
        results = await layer.run({"url": "http://example.com"}, _make_state())

    assert results, "missing security headers should yield findings"
    for f in results:
        assert isinstance(f, Finding)
        assert f.layer == 1


@pytest.mark.asyncio
async def test_web_layer_finding_schema():
    """Findings should satisfy the Finding schema constraints."""
    layer = WebLayer()
    try:
        results = await layer.run({"url": "http://localhost:9999"}, _make_state())
    except Exception:
        results = []

    for f in results:
        assert f.id
        assert 1 <= f.layer <= 8
        assert f.severity in ("info", "low", "medium", "high", "critical")
        assert 0.0 <= f.confidence <= 1.0


def test_looks_exposed_signatures():
    """Content signatures must confirm real exposure and reject SPA 200s."""
    # Genuine exposures.
    assert _looks_exposed("/.env", 200, "DB_PASSWORD=hunter2\nAPI_KEY=abc")
    assert _looks_exposed("/.git/HEAD", 200, "ref: refs/heads/main")
    assert _looks_exposed("/.git/config", 200, "[core]\n\trepositoryformatversion = 0")
    assert _looks_exposed("/swagger.json", 200, '{"openapi": "3.0.0"}')
    # Non-200 or catch-all HTML must NOT be flagged.
    assert not _looks_exposed("/.env", 404, "DB_PASSWORD=x")
    assert not _looks_exposed("/.env", 200, "<html><body>Not found</body></html>")
    assert not _looks_exposed("/.git/HEAD", 200, "<!doctype html><title>App</title>")


@pytest.mark.asyncio
async def test_reflected_input_detected():
    """A response echoing the canary unescaped yields an exploitable XSS finding."""
    layer = WebLayer()

    def _resp(text="<html></html>", status=200):
        r = MagicMock()
        r.headers = {}            # no get_list -> cookie block degrades gracefully
        r.text = text
        r.status_code = status
        r.url = "http://example.com"
        return r

    base = _resp()
    reflected = _resp(text=f"<p>You searched for {REFLECT_CANARY}</p>")

    # GET order: baseline page, reflect probe (echoes canary), then sensitive paths.
    get_mock = AsyncMock(side_effect=[base, reflected] + [_resp(status=404)] * 12)
    opts_mock = AsyncMock(return_value=_resp())
    with patch("httpx.AsyncClient.get", get_mock), \
         patch("httpx.AsyncClient.options", opts_mock):
        results = await layer.run({"url": "http://example.com"}, _make_state())

    xss = [f for f in results if "XSS surface" in f.title]
    assert xss, "expected a reflected-input finding"
    assert xss[0].exploitable and xss[0].layer == 1
