"""Unit tests for StructureToolProvider, DataTypeToolProvider, and DataToolProvider.

Covers:
- manage-structures schema and action enum
- manage-data-types schema and action enum
- get-data and apply-data-type schemas
- HANDLERS normalization
- Error handling without program
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from agentdecompile_cli.mcp_server.providers.structures import StructureToolProvider
from agentdecompile_cli.mcp_server.providers.datatypes import DataTypeToolProvider
from agentdecompile_cli.mcp_server.providers.data import DataToolProvider
from agentdecompile_cli.registry import normalize_identifier as n
from tests.helpers import parse_single_text_content_json


def _make_structure_provider(with_program: bool = False) -> StructureToolProvider:
    if not with_program:
        return StructureToolProvider(program_info=None)
    pi = MagicMock()
    pi.program = MagicMock()
    pi.program.getDataTypeManager = MagicMock(return_value=MagicMock())
    pi.program.startTransaction = MagicMock(return_value=1)
    pi.program.endTransaction = MagicMock()
    return StructureToolProvider(program_info=pi)


def _make_datatype_provider(with_program: bool = False) -> DataTypeToolProvider:
    if not with_program:
        return DataTypeToolProvider(program_info=None)
    pi = MagicMock()
    pi.program = MagicMock()
    dtm_mock = MagicMock()
    dtm_mock.getName = MagicMock(return_value="TestProgram")
    dtm_mock.getCategoryCount = MagicMock(return_value=0)
    dtm_mock.getDataTypeCount = MagicMock(return_value=0)
    dtm_mock.getSourceArchives = MagicMock(return_value=[])
    pi.program.getDataTypeManager = MagicMock(return_value=dtm_mock)
    return DataTypeToolProvider(program_info=pi)


def _make_data_provider(with_program: bool = False) -> DataToolProvider:
    if not with_program:
        return DataToolProvider(program_info=None)
    pi = MagicMock()
    pi.program = MagicMock()
    pi.program.getListing = MagicMock(return_value=MagicMock())
    pi.program.getMemory = MagicMock(return_value=MagicMock())
    return DataToolProvider(program_info=pi)


def _parse(resp) -> dict:
    return parse_single_text_content_json(resp)


# ---------------------------------------------------------------------------
# StructureToolProvider
# ---------------------------------------------------------------------------


class TestStructureProviderSchema:
    def test_manage_structures_tool_present(self):
        p = _make_structure_provider()
        names = {t.name for t in p.list_tools()}
        assert "manage-structures" in names

    def test_action_enum(self):
        p = _make_structure_provider()
        tool = p.list_tools()[0]
        actions = tool.inputSchema["properties"]["action"]["enum"]
        for a in ("parse", "validate", "create", "list", "apply", "delete"):
            assert a in actions

    def test_c_definition_param(self):
        p = _make_structure_provider()
        tool = p.list_tools()[0]
        assert "cDefinition" in tool.inputSchema["properties"]

    def test_fields_array_param(self):
        p = _make_structure_provider()
        tool = p.list_tools()[0]
        assert "fields" in tool.inputSchema["properties"]

    def test_is_union_param(self):
        p = _make_structure_provider()
        tool = p.list_tools()[0]
        props = tool.inputSchema["properties"]
        assert "isUnion" in props


class TestStructureProviderHandlers:
    def test_handler_keys_normalized(self):
        for key in StructureToolProvider.HANDLERS:
            assert key == n(key)

    def test_managestructures_present(self):
        assert "managestructures" in StructureToolProvider.HANDLERS


class TestStructureProviderValidation:
    @pytest.mark.asyncio
    async def test_no_program_returns_error(self):
        p = _make_structure_provider(with_program=False)
        resp = await p.call_tool("manage-structures", {"action": "list"})
        result = _parse(resp)
        assert result.get("success") is False or "error" in result

    @pytest.mark.asyncio
    async def test_list_action_works(self):
        p = _make_structure_provider(with_program=True)
        # set up mock dtm
        dtm_mock = MagicMock()
        dtm_mock.getRootCategory = MagicMock(return_value=MagicMock(
            getDataTypes=MagicMock(return_value=[]),
            getCategories=MagicMock(return_value=[]),
        ))
        p.program_info.program.getDataTypeManager = MagicMock(return_value=dtm_mock)
        resp = await p.call_tool("manage-structures", {"action": "list"})
        result = _parse(resp)
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# DataTypeToolProvider
# ---------------------------------------------------------------------------


class TestDataTypeProviderSchema:
    def test_manage_data_types_tool_present(self):
        p = _make_datatype_provider()
        names = {t.name for t in p.list_tools()}
        assert "manage-data-types" in names

    def test_action_enum(self):
        p = _make_datatype_provider()
        tool = p.list_tools()[0]
        actions = tool.inputSchema["properties"]["action"]["enum"]
        for a in ("archives", "list", "by_string", "apply"):
            assert a in actions

    def test_action_default_list(self):
        p = _make_datatype_provider()
        tool = p.list_tools()[0]
        assert tool.inputSchema["properties"]["action"].get("default") == "list"

    def test_data_type_string_param(self):
        p = _make_datatype_provider()
        tool = p.list_tools()[0]
        assert "dataTypeString" in tool.inputSchema["properties"]


class TestDataTypeProviderHandlers:
    def test_handler_keys_normalized(self):
        for key in DataTypeToolProvider.HANDLERS:
            assert key == n(key)

    def test_managedatatypes_present(self):
        assert "managedatatypes" in DataTypeToolProvider.HANDLERS


class TestDataTypeProviderValidation:
    @pytest.mark.asyncio
    async def test_no_program_returns_error(self):
        p = _make_datatype_provider(with_program=False)
        resp = await p.call_tool("manage-data-types", {"action": "archives"})
        result = _parse(resp)
        assert result.get("success") is False or "error" in result

    @pytest.mark.asyncio
    async def test_archives_action(self):
        p = _make_datatype_provider(with_program=True)
        resp = await p.call_tool("manage-data-types", {"action": "archives"})
        result = _parse(resp)
        if "error" not in result:
            assert "archives" in result or "count" in result

    @pytest.mark.asyncio
    async def test_invalid_action_returns_error(self):
        p = _make_datatype_provider(with_program=True)
        p._require_program = MagicMock()
        resp = await p.call_tool("manage-data-types", {"action": "unknown_xyz"})
        result = _parse(resp)
        assert "error" in result


# ---------------------------------------------------------------------------
# DataToolProvider
# ---------------------------------------------------------------------------


class TestDataProviderSchema:
    def test_tools_advertised(self):
        p = _make_data_provider()
        names = {t.name for t in p.list_tools()}
        assert "get-data" in names
        assert "apply-data-type" in names

    def test_get_data_format_enum(self):
        p = _make_data_provider()
        tool = next(t for t in p.list_tools() if t.name == "get-data")
        formats = tool.inputSchema["properties"]["format"]["enum"]
        for f in ("hex", "ascii", "both"):
            assert f in formats

    def test_apply_data_type_params(self):
        p = _make_data_provider()
        tool = next(t for t in p.list_tools() if t.name == "apply-data-type")
        props = tool.inputSchema["properties"]
        assert "addressOrSymbol" in props
        assert "dataType" in props

class TestDataProviderHandlers:
    def test_handler_keys_normalized(self):
        for key in DataToolProvider.HANDLERS:
            assert key == n(key)

    def test_getdata_present(self):
        assert "getdata" in DataToolProvider.HANDLERS

    def test_applydatatype_present(self):
        assert "applydatatype" in DataToolProvider.HANDLERS

class TestDataProviderValidation:
    @pytest.mark.asyncio
    async def test_no_program_returns_error(self):
        p = _make_data_provider(with_program=False)
        resp = await p.call_tool("get-data", {"addressOrSymbol": "0x1000"})
        result = _parse(resp)
        assert result.get("success") is False or "error" in result

    @pytest.mark.asyncio
    async def test_get_data_requires_address(self):
        p = _make_data_provider(with_program=True)
        p._require_program = MagicMock()
        resp = await p.call_tool("get-data", {})
        result = _parse(resp)
        assert "error" in result

    @pytest.mark.asyncio
    async def test_apply_data_type_requires_address(self):
        p = _make_data_provider(with_program=True)
        p._require_program = MagicMock()
        resp = await p.call_tool("apply-data-type", {"dataType": "int"})
        result = _parse(resp)
        assert "error" in result
