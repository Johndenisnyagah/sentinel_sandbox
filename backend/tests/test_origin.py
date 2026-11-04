"""WebSocket Origin check (CWE-1385) and CORS allowlist."""

import pytest
from starlette.websockets import WebSocketDisconnect


def test_foreign_origin_websocket_is_refused(client):
    """Before the fix this connection was accepted and received every alert."""
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/ws/alerts", headers={"Origin": "https://evil.example"}):
            pass
    assert exc.value.code == 1008


def test_allowed_origin_websocket_connects(client):
    with client.websocket_connect("/ws/alerts", headers={"Origin": "http://localhost:5173"}):
        pass


def test_no_origin_header_connects(client):
    with client.websocket_connect("/ws/alerts"):
        pass


def test_cors_does_not_echo_foreign_origin(client):
    r = client.get("/rules", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in r.headers


def test_cors_allows_frontend_origin(client):
    r = client.get("/rules", headers={"Origin": "http://localhost:5173"})
    assert r.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_origins_from_env(tmp_path, monkeypatch, app_module):
    import importlib
    import sys

    monkeypatch.setenv("ALLOWED_ORIGINS", "https://a.example, https://b.example")
    for name in [m for m in sys.modules if m == "main" or m.startswith("app")]:
        del sys.modules[name]
    mod = importlib.import_module("main")
    assert mod.allowed_origins == ["https://a.example", "https://b.example"]
    assert mod.origin_allowed("https://b.example")
    assert not mod.origin_allowed("http://localhost:5173")
