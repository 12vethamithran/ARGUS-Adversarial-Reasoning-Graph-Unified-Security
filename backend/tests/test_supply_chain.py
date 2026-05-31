"""Tests for the real (manifest-driven) L6 supply-chain scan and its KB."""
import pytest

from app.kb.vuln_db import match_vulns, _parse_version, _satisfies
from app.kb.manifest import parse_manifest, detect_type
from app.layers.supply_chain import SupplyChainLayer
from app.engine.state import ArgusState


def _state():
    return ArgusState(session_id="t", mode="advanced", target={}, active_layers=[6])


# ── Version matching ───────────────────────────────────────────────────────────
def test_parse_and_compare_versions():
    assert _parse_version("1.2.3") == (1, 2, 3)
    # Leading-int-per-segment: a pre-release suffix without a separator is dropped.
    assert _parse_version("4.38.0rc1") == (4, 38, 0)
    assert _parse_version("1.6.0-beta.2") == (1, 6, 0, 0, 2)
    assert _satisfies("0.0.300", "<", "0.0.317")
    assert not _satisfies("0.0.317", "<", "0.0.317")
    assert _satisfies("2.31.0", ">=", "2.31.0")


def test_match_vulns_range():
    # langchain CVE-2024-21513 is >=0.0.14, <0.1.47
    assert any(r["cve"] == "CVE-2024-21513" for r in match_vulns("pypi", "langchain", "0.1.0"))
    # A patched version matches nothing.
    assert match_vulns("pypi", "requests", "2.31.0") == []
    assert match_vulns("pypi", "requests", "2.30.0")  # below fix -> hit


# ── Manifest parsing ───────────────────────────────────────────────────────────
def test_detect_and_parse_requirements():
    assert detect_type("requests==2.30.0\n") == "requirements"
    eco, deps = parse_manifest("requests==2.30.0\n# comment\nflask>=2.0\nlangchain==0.1.0\n")
    assert eco == "pypi"
    assert ("requests", "2.30.0") in deps
    assert ("langchain", "0.1.0") in deps
    # Unpinned spec -> version None.
    assert ("flask", None) in deps


def test_parse_package_json():
    pkg = '{"dependencies": {"lodash": "^4.17.20", "react": "18.2.0"}}'
    assert detect_type(pkg) == "package.json"
    eco, deps = parse_manifest(pkg)
    assert eco == "npm"
    assert ("lodash", "4.17.20") in deps
    assert ("react", "18.2.0") in deps


# ── End-to-end L6 real scan ────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_real_scan_flags_known_cve():
    layer = SupplyChainLayer()
    target = {"manifest": "langchain==0.1.0\nrequests==2.30.0\npyyaml==5.3\n"}
    findings = await layer.run(target, _state())
    titles = " ".join(f.title for f in findings)
    assert "CVE-2024-21513" in titles      # langchain
    assert "CVE-2023-32681" in titles      # requests
    assert "CVE-2020-14343" in titles      # pyyaml
    assert all(f.layer == 6 for f in findings)
    assert any(f.exploitable for f in findings)


@pytest.mark.asyncio
async def test_real_scan_clean_manifest():
    layer = SupplyChainLayer()
    target = {"manifest": "requests==2.31.0\nflask==2.2.5\n"}  # both patched
    findings = await layer.run(target, _state())
    assert len(findings) == 1
    assert not findings[0].exploitable
    assert "No known-vulnerable dependencies" in findings[0].title


@pytest.mark.asyncio
async def test_real_scan_detects_typosquat():
    layer = SupplyChainLayer()
    target = {"manifest": "requets==2.31.0\n"}  # typo of 'requests'
    findings = await layer.run(target, _state())
    assert any("typosquat" in f.title.lower() for f in findings)
