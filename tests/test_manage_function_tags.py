from __future__ import annotations

import pytest

from agentdecompile_cli.mcp_server.program_metadata import payload_has_mutating_action
from agentdecompile_cli.mcp_server.providers.getfunction import GetFunctionToolProvider
from agentdecompile_cli.registry import Tool


@pytest.mark.unit
def test_manage_function_tags_schema_includes_set_mode() -> None:
    provider = GetFunctionToolProvider()
    tools = provider.list_tools()
    manage = next(tool for tool in tools if tool.name == Tool.MANAGE_FUNCTION_TAGS.value)
    mode_enum = manage.inputSchema["properties"]["mode"]["enum"]
    assert "set" in mode_enum
    assert "tags" in manage.inputSchema["properties"]


@pytest.mark.unit
def test_manage_function_tags_handler_is_registered() -> None:
    provider = GetFunctionToolProvider()
    assert "managefunctiontags" in provider.HANDLERS


@pytest.mark.unit
def test_parse_tag_names_from_comma_separated_string() -> None:
    provider = GetFunctionToolProvider()
    assert provider._parse_tag_names({"tags": "crypto,network"}) == ["crypto", "network"]


@pytest.mark.unit
def test_parse_tag_names_from_list() -> None:
    provider = GetFunctionToolProvider()
    assert provider._parse_tag_names({"tags": ["crypto", "network"]}) == ["crypto", "network"]


@pytest.mark.unit
def test_parse_tag_names_from_single_tag() -> None:
    provider = GetFunctionToolProvider()
    assert provider._parse_tag_names({"tag": "crypto"}) == ["crypto"]


@pytest.mark.unit
def test_payload_has_mutating_action_manage_function_tags() -> None:
    assert payload_has_mutating_action("managefunctiontags", {"action": "set"})
    assert payload_has_mutating_action("managefunctiontags", {"action": "add"})
    assert not payload_has_mutating_action("managefunctiontags", {"action": "list"})
    assert not payload_has_mutating_action("managefunctiontags", {"action": "search"})
