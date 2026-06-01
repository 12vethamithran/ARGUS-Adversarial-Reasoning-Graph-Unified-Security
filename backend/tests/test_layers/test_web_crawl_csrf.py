"""Tests for L1 endpoint/form discovery, CSRF detection, and OWASP-2025 refs."""
import pytest
from unittest.mock import AsyncMock, patch

from app.layers.web import WebLayer, discover_endpoints, discover_forms, MAX_CRAWL_ENDPOINTS
from app.layers import web_payloads as wp
from app.engine.state import ArgusState


HTML = """
<html><body>
  <a href="/list.php?cat=1">cat</a>
  <a href="/artists.php?artist=2">artist</a>
  <a href="https://other.example/x?q=1">offsite</a>
  <a href="/about">no params</a>
  <form action="/login" method="post">
    <input name="user"><input name="pass">
  </form>
  <form action="/search" method="get"><input name="q"></form>
</body></html>
"""


def test_discover_endpoints_same_origin_with_params():
    eps = discover_endpoints("http://shop.example/", HTML)
    assert eps[0] == "http://shop.example/"          # base first
    joined = " ".join(eps)
    assert "list.php?cat=1" in joined and "artists.php?artist=2" in joined
    assert "other.example" not in joined             # off-origin excluded
    assert "/about" not in joined                    # no params -> skipped
    assert len(eps) <= 1 + MAX_CRAWL_ENDPOINTS       # bounded crawl


def test_discover_forms_csrf_flags():
    forms = discover_forms("http://shop.example/", HTML)
    login = next(f for f in forms if f["action"].endswith("/login"))
    assert login["method"] == "post" and login["has_csrf_token"] is False
    assert "user" in login["inputs"]


def test_csrf_finding_emitted():
    forms = discover_forms("http://shop.example/", HTML)
    findings = WebLayer()._probe_csrf(forms)
    assert findings, "POST form without a token should yield a CSRF finding"
    f = findings[0]
    assert f.owasp_ref == "A01:2025" and f.evidence["family"] == "csrf" and f.exploitable


def test_csrf_suppressed_when_token_present():
    html = ('<form action="/x" method="post"><input name="a">'
            '<input type="hidden" name="csrf_token" value="z"></form>')
    findings = WebLayer()._probe_csrf(discover_forms("http://h/", html))
    assert not findings


def test_payload_refs_are_2025():
    for fam in (wp.SQLI_PAYLOADS, wp.XSS_PAYLOADS, wp.CMDI_PAYLOADS, wp.SSTI_PAYLOADS):
        assert all(p["owasp"] == "A05:2025" for p in fam)
    assert all(p["owasp"] == "A01:2025" for p in wp.TRAVERSAL_PAYLOADS)
    assert all(p["owasp"] == "A01:2025" for p in wp.SSRF_PAYLOADS)
    assert all(p["owasp"] == "A01:2025" for p in wp.OPEN_REDIRECT_PAYLOADS)


@pytest.mark.asyncio
async def test_crawled_endpoint_sqli_detected():
    """SQLi on a deep endpoint discovered via crawl (not the entry URL) is found."""
    from urllib.parse import parse_qsl, urlparse

    home = ('<html><body><a href="/item.php?id=1">item</a></body></html>')

    from unittest.mock import MagicMock

    async def _get(url, **kwargs):
        q = dict(parse_qsl(urlparse(url).query))
        resp = MagicMock()
        resp.headers = {}
        resp.status_code = 200
        resp.url = url
        if "item.php" in url and ("'" in q.get("id", "")):
            resp.text = "SQL syntax; check the manual that corresponds to your MySQL server"
        elif url.rstrip("/").endswith("shop.example") or url.endswith("/"):
            resp.text = home
        else:
            resp.text = "<html><body>ok</body></html>"
        return resp

    st = ArgusState(session_id="t", mode="advanced", target={"url": "http://shop.example/"},
                    active_layers=[1])
    with patch("httpx.AsyncClient.get", AsyncMock(side_effect=_get)), \
         patch("httpx.AsyncClient.options", AsyncMock(side_effect=_get)):
        res = await WebLayer().run({"url": "http://shop.example/"}, st)

    sqli = [f for f in res if (f.evidence or {}).get("family") == "sqli" and f.exploitable]
    assert sqli, "expected SQLi found on the crawled /item.php endpoint"
    assert "item.php" in sqli[0].evidence["url"]
