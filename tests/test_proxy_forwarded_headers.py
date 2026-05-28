from __future__ import annotations

import pytest

from agentdecompile_cli.mcp_server.proxy_server import (
    PROXY_FORWARDABLE_SHARED_HEADER_NAMES,
    forwardable_shared_headers_from_scope,
)


def _http_scope(headers: list[tuple[bytes, bytes]]) -> dict:
    return {"type": "http", "headers": headers}


@pytest.mark.unit
def test_forwardable_shared_headers_includes_project_path() -> None:
    assert "x-agentdecompile-project-path" in PROXY_FORWARDABLE_SHARED_HEADER_NAMES


@pytest.mark.unit
def test_forwardable_shared_headers_extracts_project_path() -> None:
    scope = _http_scope(
        [
            (b"x-agentdecompile-project-path", b"/tmp/shared/my_project.gpr"),
            (b"x-not-allowed", b"ignored"),
        ]
    )
    forwarded = forwardable_shared_headers_from_scope(scope)
    assert forwarded["x-agentdecompile-project-path"] == "/tmp/shared/my_project.gpr"
    assert "x-not-allowed" not in forwarded


@pytest.mark.unit
def test_forwardable_shared_headers_preserves_header_casing() -> None:
    scope = _http_scope([(b"X-AgentDecompile-Project-Path", b"/data/proj.gpr")])
    forwarded = forwardable_shared_headers_from_scope(scope)
    assert forwarded["X-AgentDecompile-Project-Path"] == "/data/proj.gpr"


@pytest.mark.unit
def test_forwardable_shared_headers_non_http_scope_returns_empty() -> None:
    assert forwardable_shared_headers_from_scope({"type": "websocket"}) == {}


@pytest.mark.unit
def test_forwardable_shared_headers_forwards_mcp_session_cookie() -> None:
    scope = _http_scope([(b"cookie", b"mcp_session_id=abc123; other=ignored")])
    forwarded = forwardable_shared_headers_from_scope(scope)
    assert forwarded["Cookie"] == "mcp_session_id=abc123"
