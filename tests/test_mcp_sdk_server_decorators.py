"""Regression: MCP low-level Server must expose decorator registration APIs.

Cursor's ``agdec-mcp-local`` installs via ``uvx --from git+…``, which resolves
dependencies from ``pyproject.toml`` (not the workspace lock alone). An unpinned
``mcp`` dependency can pull MCP SDK 2.0, where ``Server.list_tools`` /
``call_tool`` / ``list_resources`` / etc. were removed in favor of constructor
``on_*`` handlers — crashing ``PythonMcpServer._create_mcp_server``.
"""

from __future__ import annotations

import importlib.metadata

import pytest
from mcp.server import Server
from packaging.version import Version


@pytest.mark.unit
def test_mcp_sdk_version_is_v1() -> None:
    version = Version(importlib.metadata.version("mcp"))
    assert version.major == 1, (
        f"mcp {version} is incompatible: pin mcp>=1.26.0,<2 until low-level "
        "Server decorator registration is migrated to MCP 2.0 on_* handlers"
    )


@pytest.mark.unit
def test_mcp_server_exposes_list_tools_decorator() -> None:
    required = (
        "list_tools",
        "call_tool",
        "list_resources",
        "read_resource",
        "list_prompts",
        "get_prompt",
    )
    missing = [name for name in required if not hasattr(Server, name)]
    assert not missing, (
        f"mcp.server.Server is missing decorator APIs {missing}; "
        "this matches MCP SDK 2.0 and breaks agentdecompile MCP startup"
    )


@pytest.mark.unit
def test_mcp_server_list_tools_decorator_registers() -> None:
    """Smoke the exact registration path that crashed in _create_mcp_server."""
    server = Server(name="agentdecompile-sdk-compat", version="0.0.0")

    @server.list_tools()
    async def list_tools() -> list:
        return []

    @server.call_tool(validate_input=False)
    async def call_tool(name: str, arguments: dict) -> list:
        return []

    assert list_tools is not None
    assert call_tool is not None
