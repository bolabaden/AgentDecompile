from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agentdecompile_recovery.corpus.dashboard.router import create_dashboard_router
from agentdecompile_recovery.corpus.dashboard.server_control import (
    clear_server_hooks,
    register_server_hooks,
)

pytestmark = pytest.mark.unit


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(create_dashboard_router())
    return TestClient(app)


def test_server_shutdown_calls_hook() -> None:
    called: list[str] = []

    def shutdown() -> None:
        called.append("shutdown")

    register_server_hooks(shutdown=shutdown)
    try:
        client = _client()
        res = client.post("/dashboard/api/server/shutdown")
        assert res.status_code == 200
        payload = res.json()
        assert payload["ok"] is True
        assert payload["action"] == "shutdown"
        assert called == ["shutdown"]
    finally:
        clear_server_hooks()


def test_server_restart_calls_hook() -> None:
    called: list[str] = []

    def restart() -> None:
        called.append("restart")

    register_server_hooks(restart=restart)
    try:
        client = _client()
        res = client.post("/dashboard/api/server/restart")
        assert res.status_code == 200
        payload = res.json()
        assert payload["ok"] is True
        assert payload["action"] == "restart"
        assert called == ["restart"]
    finally:
        clear_server_hooks()


def test_server_control_disabled_by_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_DECOMPILE_DASHBOARD_ALLOW_SERVER_CONTROL", "0")
    client = _client()
    res = client.post("/dashboard/api/server/shutdown")
    assert res.status_code == 403


def test_workbench_js_exposes_server_controls() -> None:
    from pathlib import Path

    js = Path("src/agentdecompile_recovery/corpus/dashboard/static/workbench-app.js").read_text(
        encoding="utf-8"
    )
    assert "serverShutdown" in js
    assert "serverRestart" in js
    assert "restartServer" in js
    assert "shutdownServer" in js
