from app.routers.terminal import _origin_allowed


def test_terminal_origin_policy_allows_configured_origin(monkeypatch):
    monkeypatch.setattr(
        "app.config.settings.allowed_origins",
        '["https://app.example.com"]',
    )

    assert _origin_allowed("https://app.example.com")
    assert not _origin_allowed("https://evil.example.com")


def test_terminal_origin_policy_allows_local_dev(monkeypatch):
    monkeypatch.setattr(
        "app.config.settings.allowed_origins",
        '["https://app.example.com"]',
    )

    assert _origin_allowed("http://localhost:5173")
    assert _origin_allowed("http://127.0.0.1:5173")
