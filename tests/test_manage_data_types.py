from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from agentdecompile_cli.mcp_server.program_metadata import payload_has_mutating_action
from agentdecompile_cli.mcp_server.providers.datatypes import DataTypeToolProvider
from agentdecompile_cli.registry import Tool, resolve_tool_name
from tests.helpers import create_test_program, ghidra_install_available

_INTEGRATION_SKIP = pytest.mark.skipif(
    not ghidra_install_available(),
    reason="GHIDRA_INSTALL_DIR not available",
)


@pytest.mark.unit
def test_manage_data_types_schema_includes_catalog_modes() -> None:
    provider = DataTypeToolProvider()
    tools = provider.list_tools()
    manage = next(tool for tool in tools if tool.name == Tool.MANAGE_DATA_TYPES.value)
    mode_enum = manage.inputSchema["properties"]["mode"]["enum"]
    assert "create" in mode_enum
    assert "update" in mode_enum
    assert "delete" in mode_enum
    assert "info" in mode_enum


@pytest.mark.unit
def test_manage_data_types_handler_is_registered() -> None:
    provider = DataTypeToolProvider()
    assert "managedatatypes" in provider.HANDLERS


@pytest.mark.unit
def test_manage_data_types_aliases_resolve() -> None:
    for alias in ("create-data-type", "update-data-type", "delete-data-type"):
        assert resolve_tool_name(alias) == Tool.MANAGE_DATA_TYPES.value


@pytest.mark.unit
def test_payload_has_mutating_action_manage_data_types() -> None:
    assert payload_has_mutating_action("managedatatypes", {"action": "create"})
    assert payload_has_mutating_action("managedatatypes", {"action": "update"})
    assert payload_has_mutating_action("managedatatypes", {"action": "apply"})
    assert not payload_has_mutating_action("managedatatypes", {"action": "list"})
    assert not payload_has_mutating_action("managedatatypes", {"action": "info"})


@pytest.fixture(scope="module")
def datatype_test_program():
    builder = create_test_program()
    if builder is None:
        pytest.skip("Failed to create test program")
    yield builder
    try:
        builder.dispose()
    except Exception:
        pass


@pytest.mark.integration
@_INTEGRATION_SKIP
@pytest.mark.asyncio
async def test_manage_data_types_create_typedef_persists(ghidra_initialized, datatype_test_program) -> None:
    program = datatype_test_program.getProgram()
    provider = DataTypeToolProvider()
    provider.program_info = SimpleNamespace(program=program, flat_api=None)

    result = await provider._create(
        {
            "mode": "create",
            "dataTypeString": "unsigned int",
            "name": "AgentTestUInt",
            "categoryPath": "/",
        },
    )
    payload = json.loads(result[0].text)
    assert payload["success"] is True
    assert payload["action"] == "create"

    from agentdecompile_cli.mcp_server.providers.datatypes import find_catalog_data_type

    dt = find_catalog_data_type(program.getDataTypeManager(), "AgentTestUInt", "/")
    assert dt is not None

    update_result = await provider._update(
        {"mode": "update", "name": "AgentTestUInt", "categoryPath": "/", "description": "agent test uint"},
    )
    update_payload = json.loads(update_result[0].text)
    assert update_payload["success"] is True
    assert update_payload["action"] == "update"
    updated = find_catalog_data_type(program.getDataTypeManager(), "AgentTestUInt", "/")
    assert updated is not None
    assert updated.getDescription() == "agent test uint"

    delete_result = await provider._delete({"mode": "delete", "name": "AgentTestUInt", "categoryPath": "/"})
    delete_payload = json.loads(delete_result[0].text)
    assert delete_payload["success"] is True
    assert find_catalog_data_type(program.getDataTypeManager(), "AgentTestUInt", "/") is None
