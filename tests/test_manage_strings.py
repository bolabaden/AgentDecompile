from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from agentdecompile_cli.mcp_server.program_metadata import payload_has_mutating_action
from agentdecompile_cli.mcp_server.providers.strings import (
    StringToolProvider,
    encode_program_string,
    ghidra_string_type_name,
    normalize_string_encoding,
)
from agentdecompile_cli.registry import Tool
from tests.helpers import create_test_program, ghidra_install_available

_INTEGRATION_SKIP = pytest.mark.skipif(
    not ghidra_install_available(),
    reason="GHIDRA_INSTALL_DIR not available",
)


@pytest.mark.unit
def test_manage_strings_schema_includes_crud_modes() -> None:
    provider = StringToolProvider()
    tools = provider.list_tools()
    manage = next(tool for tool in tools if tool.name == Tool.MANAGE_STRINGS.value)
    mode_enum = manage.inputSchema["properties"]["mode"]["enum"]
    assert "create" in mode_enum
    assert "update" in mode_enum
    assert "delete" in mode_enum


@pytest.mark.unit
def test_manage_strings_handler_is_registered() -> None:
    provider = StringToolProvider()
    assert "managestrings" in provider.HANDLERS


@pytest.mark.unit
def test_normalize_string_encoding_defaults_ascii() -> None:
    assert normalize_string_encoding(None) == "ascii"
    assert normalize_string_encoding("UTF-16") == "utf16"


@pytest.mark.unit
def test_encode_program_string_ascii_null_terminated() -> None:
    assert encode_program_string("hi", "ascii") == b"hi\x00"


@pytest.mark.unit
def test_encode_program_string_utf16_null_terminated() -> None:
    assert encode_program_string("A", "utf16") == "A".encode("utf-16-le") + b"\x00\x00"


@pytest.mark.unit
def test_ghidra_string_type_name() -> None:
    assert ghidra_string_type_name("ascii") == "string"
    assert ghidra_string_type_name("utf16") == "unicode"


@pytest.mark.unit
def test_payload_has_mutating_action_manage_strings() -> None:
    assert payload_has_mutating_action("managestrings", {"action": "create"})
    assert payload_has_mutating_action("managestrings", {"action": "delete"})
    assert not payload_has_mutating_action("managestrings", {"action": "list"})
    assert not payload_has_mutating_action("managestrings", {})


@pytest.fixture(scope="module")
def strings_test_program():
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
async def test_manage_strings_create_persists_in_program(ghidra_initialized, strings_test_program) -> None:
    program = strings_test_program.getProgram()
    target = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x00401300)

    provider = StringToolProvider()
    provider.program_info = SimpleNamespace(program=program, flat_api=None)

    result = await provider._handle_create(
        {
            "mode": "create",
            "addressOrSymbol": str(target),
            "value": "CreatedByTest",
        },
    )
    payload = json.loads(result[0].text)
    assert payload["success"] is True
    assert payload["action"] == "create"

    data = program.getListing().getDataAt(target)
    assert data is not None
    assert "CreatedByTest" in str(data.getValue())
