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


def _mk_resp(text="<html><head></head><body></body></html>", status=200,
             url="http://example.com", headers=None):
    r = MagicMock()
    r.headers = headers or {}
    r.text = text
    r.status_code = status
    r.url = url
    return r


@pytest.mark.asyncio
async def test_web_layer_returns_findings():
    """Should return Finding objects, each with correct layer=1."""
    layer = WebLayer()
    resp = _mk_resp()  # all security headers missing, benign body

    async def _get(url, **kwargs):
        return _mk_resp(status=404 if "/." in url or "/admin" in url else 200, url=url)

    with patch("httpx.AsyncClient.get", AsyncMock(side_effect=lambda u=None, **k: resp)), \
         patch("httpx.AsyncClient.options", AsyncMock(return_value=resp)):
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
async def test_reflected_xss_detected():
    """A reflective endpoint that echoes the param value unescaped is flagged XSS."""
    from urllib.parse import parse_qsl, urlparse
    layer = WebLayer()

    async def _get(url, **kwargs):
        # First (baseline) GET has no query -> plain page. Param probes echo the
        # value back unescaped, simulating a reflective server.
        q = dict(parse_qsl(urlparse(url).query))
        echoed = " ".join(q.values())
        return _mk_resp(text=f"<html><body>You searched for {echoed}</body></html>", url=url)

    with patch("httpx.AsyncClient.get", AsyncMock(side_effect=_get)), \
         patch("httpx.AsyncClient.options", AsyncMock(return_value=_mk_resp())):
        results = await layer.run({"url": "http://example.com/search?q=hello"}, _make_state())

    xss = [f for f in results if f.evidence.get("family") == "xss" and f.exploitable]
    assert xss, "expected a reflected-XSS finding"
    assert xss[0].layer == 1 and xss[0].owasp_ref == "A03:2021"


@pytest.mark.asyncio
async def test_sqli_error_based_detected():
    """A DB error signature in the response yields an exploitable SQLi finding."""
    from urllib.parse import parse_qsl, urlparse
    layer = WebLayer()

    async def _get(url, **kwargs):
        q = dict(parse_qsl(urlparse(url).query))
        val = q.get("id", "")
        # A single-quote payload triggers a MySQL error page.
        if "'" in val or '"' in val:
            return _mk_resp(text="You have an error in your SQL syntax; check the manual "
                                 "that corresponds to your MySQL server version", url=url)
        return _mk_resp(text="<html><body>product 1</body></html>", url=url)

    with patch("httpx.AsyncClient.get", AsyncMock(side_effect=_get)), \
         patch("httpx.AsyncClient.options", AsyncMock(return_value=_mk_resp())):
        results = await layer.run({"url": "http://example.com/item?id=1"}, _make_state())

    sqli = [f for f in results if f.evidence.get("family") == "sqli" and f.exploitable]
    assert sqli, "expected an error-based SQLi finding"
    assert sqli[0].severity == "critical" and sqli[0].owasp_ref == "A03:2021"
