from __future__ import annotations

from typing import Any

import pytest
from mcp import types

from agentdecompile_cli.mcp_server.providers.getfunction import (
    GetFunctionToolProvider,
    is_default_decompiler_var_name,
    parse_colon_mappings,
)
from agentdecompile_cli.mcp_server.tool_providers import create_success_response
from agentdecompile_cli.registry import Tool, resolve_tool_name


@pytest.mark.unit
def test_manage_function_schema_includes_variable_modes() -> None:
    provider = GetFunctionToolProvider()
    tools = provider.list_tools()
    manage = next(tool for tool in tools if tool.name == "manage-function")
    mode_enum = manage.inputSchema["properties"]["mode"]["enum"]
    assert "rename_variable" in mode_enum
    assert "set_variable_type" in mode_enum
    assert "change_datatypes" in mode_enum


@pytest.mark.unit
def test_manage_function_variable_alias_handlers_registered() -> None:
    provider = GetFunctionToolProvider()
    for alias in (
        "renamevariable",
        "renamevariables",
        "setlocalvariabletype",
        "changevariabledatatypes",
    ):
        assert alias in provider.HANDLERS


@pytest.mark.unit
def test_variable_tool_aliases_resolve_to_manage_function() -> None:
    for alias in ("rename-variable", "set-local-variable-type", "change-variable-datatypes"):
        assert resolve_tool_name(alias) == Tool.MANAGE_FUNCTION.value


@pytest.mark.unit
def test_parse_colon_mappings_batch() -> None:
    pairs = parse_colon_mappings("var_1:itemCount,local_8:slotIndex", label="variableMappings")
    assert pairs == [("var_1", "itemCount"), ("local_8", "slotIndex")]


@pytest.mark.unit
def test_parse_colon_mappings_rejects_invalid() -> None:
    with pytest.raises(ValueError, match="Invalid variableMappings"):
        parse_colon_mappings("badentry", label="variableMappings")


@pytest.mark.unit
def test_is_default_decompiler_var_name() -> None:
    assert is_default_decompiler_var_name("local_8")
    assert is_default_decompiler_var_name("uVar2")
    assert not is_default_decompiler_var_name("itemCount")


@pytest.mark.unit
@pytest.mark.asyncio
async def test_rename_variable_alias_presets_mode() -> None:
    provider = GetFunctionToolProvider()
    captured: dict[str, Any] = {}

    async def fake_handle_manage(args: dict[str, Any]) -> list[types.TextContent]:
        captured.update(args)
        return create_success_response({"action": "rename_variable", "success": True})

    provider._handle_manage = fake_handle_manage  # type: ignore[method-assign]
    await provider._handle_rename_variable_alias({})
    assert captured.get("mode") == "rename_variable"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_set_variable_type_alias_presets_mode() -> None:
    provider = GetFunctionToolProvider()
    captured: dict[str, Any] = {}

    async def fake_handle_manage(args: dict[str, Any]) -> list[types.TextContent]:
        captured.update(args)
        return create_success_response({"action": "set_variable_type", "success": True})

    provider._handle_manage = fake_handle_manage  # type: ignore[method-assign]
    await provider._handle_set_variable_type_alias({})
    assert captured.get("mode") == "set_variable_type"
