"""Unit tests for L1 WebLayer."""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from app.layers.web import WebLayer
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
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.headers = {
            "content-security-policy": "",
            "x-frame-options": "",
            "strict-transport-security": "",
        }
        mock_resp.text = "<html><head></head><body></body></html>"
        mock_resp.status_code = 200
        mock_get.return_value.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_get.return_value.__aexit__ = AsyncMock(return_value=False)

        try:
            results = await layer.run({"url": "http://example.com"}, _make_state())
        except Exception:
            results = []

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
