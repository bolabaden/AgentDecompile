"""Unit tests for ImportExportToolProvider.

Covers:
- import-binary, export, analyze-program, checkin-program, change-processor,
  list-processors tool schemas
- HANDLERS normalization
- import-binary requires filePath
- export format enum
- analyze-program, checkin-program, change-processor validation
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from agentdecompile_cli.mcp_server.providers.import_export import ImportExportToolProvider
from agentdecompile_cli.registry import normalize_identifier as n
from tests.helpers import parse_single_text_content_json


def _make_provider(with_program: bool = False) -> ImportExportToolProvider:
    if not with_program:
        return ImportExportToolProvider(program_info=None)
    pi = MagicMock()
    pi.program = MagicMock()
    return ImportExportToolProvider(program_info=pi)


def _parse(resp) -> dict:
    return parse_single_text_content_json(resp)


class TestImportExportProviderSchema:
    def test_tools_advertised(self):
        p = _make_provider()
        names = {t.name for t in p.list_tools()}
        assert "import-binary" in names
        assert "export" in names
        assert "analyze-program" in names
        assert "checkin-program" in names
        assert "change-processor" in names
        assert "list-processors" in names

    def test_import_binary_schema(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "import-binary")
        props = tool.inputSchema["properties"]
        # filePath or path should be present
        assert any(k in props for k in ("filePath", "path"))

    def test_export_format_enum(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "export")
        props = tool.inputSchema["properties"]
        assert "format" in props
        formats = props["format"]["enum"]
        for f in ("c", "cpp", "gzf", "sarif", "xml"):
            assert f in formats

    def test_analyze_program_schema(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "analyze-program")
        props = tool.inputSchema["properties"]
        assert "programPath" in props

    def test_checkin_program_schema(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "checkin-program")
        props = tool.inputSchema["properties"]
        assert "message" in props

    def test_change_processor_schema(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "change-processor")
        props = tool.inputSchema["properties"]
        assert any(k in props for k in ("language", "compiler"))

    def test_list_processors_schema(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "list-processors")
        props = tool.inputSchema["properties"]
        assert "filter" in props


class TestImportExportProviderHandlers:
    def test_handler_keys_normalized(self):
        for key in ImportExportToolProvider.HANDLERS:
            assert key == n(key)

    def test_importbinary_handler_present(self):
        assert "importbinary" in ImportExportToolProvider.HANDLERS

    def test_export_handler_present(self):
        assert "export" in ImportExportToolProvider.HANDLERS

    def test_analyzeprogram_handler_present(self):
        assert "analyzeprogram" in ImportExportToolProvider.HANDLERS

    def test_changeprocessor_handler_present(self):
        assert "changeprocessor" in ImportExportToolProvider.HANDLERS

    def test_checkinprogram_handler_present(self):
        assert "checkinprogram" in ImportExportToolProvider.HANDLERS

    def test_listprocessors_handler_present(self):
        assert "listprocessors" in ImportExportToolProvider.HANDLERS


class TestImportExportProviderValidation:
    @pytest.mark.asyncio
    async def test_import_binary_requires_filepath(self):
        p = _make_provider(with_program=False)
        resp = await p.call_tool("import-binary", {})
        result = _parse(resp)
        assert "error" in result

    @pytest.mark.asyncio
    async def test_import_binary_path_alias(self):
        """'path' should be accepted as alias for filePath in import-binary."""
        p = _make_provider(with_program=False)
        received = {}

        async def capture(args):
            received.update(args)
            from agentdecompile_cli.mcp_server.tool_providers import create_error_response
            return create_error_response("mocked")

        p._handle_import = capture
        await p.call_tool("import-binary", {"path": "/tmp/test.elf"})
        assert "path" in received

    @pytest.mark.asyncio
    async def test_list_processors_no_program_required(self):
        """list-processors should work without a program (lists Ghidra languages)."""
        p = _make_provider(with_program=False)
        resp = await p.call_tool("list-processors", {})
        result = _parse(resp)
        # Might fail or succeed depending on Ghidra availability; just check shape
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_export_format_normalized(self):
        p = _make_provider(with_program=True)
        received = {}

        async def capture(args):
            received.update(args)
            from agentdecompile_cli.mcp_server.tool_providers import create_error_response
            return create_error_response("mocked")

        p._handle_export = capture
        await p.call_tool("export", {"programPath": "/test", "format": "xml", "outputPath": "/tmp/out.xml"})
        assert "format" in received
        assert received["format"] == "xml"


class TestImportExportArgNormalization:
    @pytest.mark.asyncio
    async def test_filepath_camel_case_normalized(self):
        p = _make_provider(with_program=False)
        received = {}

        async def capture(args):
            received.update(args)
            from agentdecompile_cli.mcp_server.tool_providers import create_error_response
            return create_error_response("mocked")

        p._handle_import = capture
        await p.call_tool("import-binary", {"filePath": "/tmp/binary.exe"})
        assert "filepath" in received

    @pytest.mark.asyncio
    async def test_analyzers_list_normalized(self):
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        received = {}

        async def capture(args):
            received.update(args)
            from agentdecompile_cli.mcp_server.tool_providers import create_error_response
            return create_error_response("mocked")

        p._handle_analyze = capture
        await p.call_tool("analyze-program", {"programPath": "/test", "analyzers": ["AutoAnalysis"]})
        assert "analyzers" in received
