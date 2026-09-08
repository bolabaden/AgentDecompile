"""Local shutdown/restart hooks for the dashboard workbench."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import time
from typing import Any, Callable

from fastapi import Request

_SHUTDOWN: Callable[[], None] | None = None
_RESTART: Callable[[], None] | None = None
_LOCAL_HOSTS = frozenset({"127.0.0.1", "::1", "localhost", "testclient"})


def register_server_hooks(
    *,
    shutdown: Callable[[], None] | None = None,
    restart: Callable[[], None] | None = None,
) -> None:
    """Called by the MCP HTTP server when uvicorn starts."""
    global _SHUTDOWN, _RESTART
    if shutdown is not None:
        _SHUTDOWN = shutdown
    if restart is not None:
        _RESTART = restart


def clear_server_hooks() -> None:
    global _SHUTDOWN, _RESTART
    _SHUTDOWN = None
    _RESTART = None


def local_control_allowed(request: Request) -> bool:
    raw = (os.environ.get("AGENT_DECOMPILE_DASHBOARD_ALLOW_SERVER_CONTROL") or "1").strip().lower()
    if raw in {"0", "false", "no", "off"}:
        return False
    client = request.client
    if client is not None and (client.host or "").lower() in _LOCAL_HOSTS:
        return True
    return False


def restart_command() -> list[str]:
    raw = (os.environ.get("AGENT_DECOMPILE_SERVER_RESTART_ARGV") or "").strip()
    if raw:
        try:
            parsed = json.loads(raw)
        except (TypeError, ValueError):
            parsed = None
        if isinstance(parsed, list) and parsed and all(isinstance(item, str) for item in parsed):
            return list(parsed)
    return [sys.executable, *sys.argv[1:]]


def spawn_restart_then_shutdown() -> list[str]:
    """Launch a detached replacement process, then stop the current server."""
    cmd = restart_command()

    def _run() -> None:
        time.sleep(0.35)
        subprocess.Popen(
            cmd,
            cwd=os.getcwd(),
            start_new_session=True,
            close_fds=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        request_shutdown()

    threading.Thread(target=_run, name="dashboard-server-restart", daemon=True).start()
    return cmd


def request_shutdown() -> dict[str, Any]:
    if _SHUTDOWN is not None:
        _SHUTDOWN()
        return {"ok": True, "action": "shutdown", "method": "hook"}

    os.kill(os.getpid(), signal.SIGTERM)
    return {"ok": True, "action": "shutdown", "method": "sigterm"}


def request_restart() -> dict[str, Any]:
    if _RESTART is not None:
        _RESTART()
        return {"ok": True, "action": "restart", "method": "hook"}

    cmd = spawn_restart_then_shutdown()
    return {"ok": True, "action": "restart", "method": "spawn", "command": cmd}
