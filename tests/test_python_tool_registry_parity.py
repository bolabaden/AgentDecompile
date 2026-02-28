from __future__ import annotations

from agentdecompile_cli.mcp_server.tool_providers import ToolProviderManager
from agentdecompile_cli.registry import ADVERTISED_TOOLS, to_snake_case


def test_python_advertises_all_canonical_tools() -> None:
    manager = ToolProviderManager()
    manager.register_all_providers()

    advertised = {tool.name for tool in manager.list_tools()}
    expected = {to_snake_case(name) for name in ADVERTISED_TOOLS}

    missing = expected - advertised
    assert not missing, f"Missing canonical tools from Python advertisement: {sorted(missing)}"
