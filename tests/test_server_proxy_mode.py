from __future__ import annotations

import sys
import types

from typing import Any, ClassVar, Coroutine

import pytest

from agentdecompile_cli import server as server_entrypoint


class _DummyCli:
    last_launcher: ClassVar[Any | None] = None
    last_project_manager: ClassVar[Any | None] = None
    last_backend: ClassVar[Any | None] = None

    def __init__(
        self,
        launcher: Any | None,
        project_manager: Any | None,
        backend: Any | None,
    ):
        _DummyCli.last_launcher = launcher
        _DummyCli.last_project_manager = project_manager
        _DummyCli.last_backend = backend

    async def run(self):
        return None


def test_server_proxy_stdio_mode_uses_remote_backend_without_local_init(monkeypatch: pytest.MonkeyPatch):
    called: dict[str, int] = {"run_async": 0, "local_init": 0}

    def _run_async_stub(_coro: Coroutine[Any, Any, Any]):
        called["run_async"] += 1
        close = getattr(_coro, "close", None)
        if callable(close):
            close()

    def _init_context_stub(**_kwargs: Any):
        called["local_init"] += 1
        raise AssertionError("Local init should not run in proxy mode")

    monkeypatch.setattr(server_entrypoint, "run_async", _run_async_stub)
    monkeypatch.setattr(server_entrypoint, "init_agentdecompile_context", _init_context_stub)
    monkeypatch.setitem(
        sys.modules,
        "agentdecompile_cli.__main__",
        types.SimpleNamespace(AgentDecompileCLI=_DummyCli),
    )
    monkeypatch.setitem(
        sys.modules,
        "agentdecompile_cli.bridge",
        types.SimpleNamespace(_apply_mcp_session_fix=lambda: None),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "agentdecompile-server",
            "--transport",
            "stdio",
            "--backend-url",
            "http://127.0.0.1:8080",
        ],
    )

    server_entrypoint.main()

    assert called["run_async"] == 1
    assert called["local_init"] == 0
    assert _DummyCli.last_launcher is None
    assert _DummyCli.last_project_manager is None
    assert _DummyCli.last_backend == "http://127.0.0.1:8080/mcp/message"


def test_server_proxy_mode_rejects_binary_inputs(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setitem(
        sys.modules,
        "agentdecompile_cli.bridge",
        types.SimpleNamespace(_apply_mcp_session_fix=lambda: None),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "agentdecompile-server",
            "--transport",
            "stdio",
            "--backend-url",
            "http://127.0.0.1:8080",
            "sample.bin",
        ],
    )

    with pytest.raises(SystemExit):
        server_entrypoint.main()
