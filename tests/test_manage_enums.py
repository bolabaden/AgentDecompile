from __future__ import annotations

import pytest
from mcp import types

from agentdecompile_cli.mcp_server.providers.enums import (
    EnumToolProvider,
    is_cobra_case,
    parse_enum_member_specs,
    require_cobra_case_member_name,
)
from agentdecompile_cli.mcp_server.response_formatter import render_tool_response
from agentdecompile_cli.mcp_server.tool_providers import create_success_response
from agentdecompile_cli.registry import Tool, resolve_tool_name


@pytest.mark.unit
def test_manage_enums_schema_includes_all_modes() -> None:
    provider = EnumToolProvider()
    tools = provider.list_tools()
    manage = next(tool for tool in tools if tool.name == "manage-enums")
    mode_enum = manage.inputSchema["properties"]["mode"]["enum"]
    assert mode_enum == [
        "list",
        "info",
        "create",
        "add_member",
        "edit_member",
        "remove_member",
        "delete",
    ]


@pytest.mark.unit
def test_manage_enums_handler_is_registered() -> None:
    provider = EnumToolProvider()
    assert "manageenums" in provider.HANDLERS


@pytest.mark.unit
def test_manage_enums_aliases_resolve() -> None:
    for alias in ("create-enum", "edit-enum", "list-enums", "delete-enum", "get-enum-info"):
        assert resolve_tool_name(alias) == Tool.MANAGE_ENUMS.value


@pytest.mark.unit
def test_parse_enum_member_specs_from_batch() -> None:
    specs = parse_enum_member_specs(
        [
            {"name": "FLAG_A", "value": 0},
            {"memberName": "FLAG_B", "memberValue": 1},
        ],
    )
    assert specs == [("FLAG_A", 0), ("FLAG_B", 1)]


@pytest.mark.unit
def test_parse_enum_member_specs_single_pair() -> None:
    specs = parse_enum_member_specs(None, single_name="ONLY_ONE", single_value=42)
    assert specs == [("ONLY_ONE", 42)]


@pytest.mark.unit
def test_parse_enum_member_specs_requires_value() -> None:
    with pytest.raises(ValueError, match="missing integer value"):
        parse_enum_member_specs([{"name": "BAD"}])


@pytest.mark.unit
def test_is_cobra_case_accepts_screaming_snake() -> None:
    assert is_cobra_case("SAVE_SLOT_EMPTY")
    assert is_cobra_case("A")
    assert not is_cobra_case("saveSlot")
    assert not is_cobra_case("1BAD")


@pytest.mark.unit
def test_manage_enums_alias_handlers_are_registered() -> None:
    provider = EnumToolProvider()
    for alias in ("createenum", "editenum", "listenums", "deleteenum", "getenuminfo"):
        assert alias in provider.HANDLERS


@pytest.mark.unit
@pytest.mark.asyncio
async def test_create_enum_alias_presets_mode() -> None:
    from typing import Any

    provider = EnumToolProvider()
    captured: dict[str, Any] = {}

    async def fake_handle(args: dict[str, Any]) -> list[types.TextContent]:
        captured.update(args)
        return create_success_response({"action": "create", "success": True})

    provider._handle = fake_handle  # type: ignore[method-assign]
    await provider._handle_create_alias({})
    assert captured.get("mode") == "create"


@pytest.mark.unit
def test_require_cobra_case_member_name_rejects_camel_case() -> None:
    with pytest.raises(ValueError, match="COBRA_CASE"):
        require_cobra_case_member_name("saveSlot")


@pytest.mark.unit
def test_parse_enum_member_specs_rejects_non_cobra_case() -> None:
    with pytest.raises(ValueError, match="COBRA_CASE"):
        parse_enum_member_specs([{"name": "badName", "value": 0}])


@pytest.mark.unit
def test_render_enums_list_action() -> None:
    markdown = render_tool_response(
        "manageenums",
        {"action": "list", "enums": [{"name": "MyEnum", "path": "/", "memberCount": 2}], "count": 1},
    )
    assert "MyEnum" in markdown
    assert "manage-enums" in markdown.lower() or "Enum" in markdown


@pytest.mark.unit
def test_render_enums_conflict_payload() -> None:
    markdown = render_tool_response(
        "manageenums",
        {
            "success": False,
            "modificationConflict": True,
            "conflictId": "test-id",
            "tool": "manage-enums",
            "conflictSummary": "Create enum would overwrite",
            "nextStep": "resolve-modification-conflict",
        },
    )
    assert "conflict" in markdown.lower() or "resolve-modification-conflict" in markdown
