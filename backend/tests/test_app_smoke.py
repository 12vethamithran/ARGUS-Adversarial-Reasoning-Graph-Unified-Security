"""App-level smoke tests: lifespan (janitor) boots, and the session router is
storage-backed (create -> get -> list round-trip survives a fresh router call).

Skipped automatically if FastAPI/Starlette TestClient isn't installed.
"""
import pytest

pytest.importorskip("fastapi")
from starlette.testclient import TestClient  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr("app.config.settings.data_dir", str(tmp_path))
    import app.main as main
    # TestClient as a context manager runs startup/shutdown (lifespan + janitor).
    with TestClient(main.app) as c:
        yield c


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_session_create_get_list_roundtrip(client):
    body = {"mode": "advanced", "target": {"description": "agent app"}}
    r = client.post("/api/sessions/", json=body)
    assert r.status_code == 200
    sid = r.json()["id"]
    assert r.json()["active_layers"] == list(range(1, 9))

    # Persisted to storage, so a subsequent GET finds it.
    r2 = client.get(f"/api/sessions/{sid}")
    assert r2.status_code == 200
    assert r2.json()["id"] == sid

    r3 = client.get("/api/sessions/")
    assert any(s["id"] == sid for s in r3.json())


def test_get_missing_session_404(client):
    assert client.get("/api/sessions/01DOESNOTEXIST0000000000000").status_code == 404
