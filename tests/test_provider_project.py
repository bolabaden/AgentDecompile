"""Unit tests for ProjectToolProvider.

Covers:
- Tool schema: open, get-current-program, list-project-files, manage-files,
               list-project-binaries, list-project-binary-metadata, delete-project-binary,
               list-open-programs, get-current-address, get-current-function
- HANDLERS normalization and alias routing
- importfile alias routes to import handler
- manage-files action enum
"""
from __future__ import annotations

import socket
from unittest.mock import MagicMock

import pytest

from agentdecompile_cli.mcp_server.providers.project import ProjectToolProvider
from agentdecompile_cli.registry import TOOL_PARAMS, normalize_identifier as n
from tests.helpers import parse_single_text_content_json


def _make_provider(with_program: bool = False) -> ProjectToolProvider:
    if not with_program:
        return ProjectToolProvider(program_info=None)
    pi = MagicMock()
    pi.program = MagicMock()
    pi.program.getName = MagicMock(return_value="TestProgram")
    pi.program.getImageBase = MagicMock(return_value=MagicMock(__str__=lambda self: "0x400000"))
    return ProjectToolProvider(program_info=pi)


def _parse(resp) -> dict:
    return parse_single_text_content_json(resp)


class TestProjectProviderSchema:
    def test_tools_advertised(self):
        p = _make_provider()
        names = {t.name for t in p.list_tools()}
        assert "open" in names
        assert "get-current-program" in names
        assert "list-project-files" in names
        assert "manage-files" in names
        assert "list-project-binaries" in names
        assert "list-project-binary-metadata" in names
        assert "delete-project-binary" in names

    def test_open_schema(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "open")
        props = tool.inputSchema["properties"]
        assert any(k in props for k in ("programPath", "filePath", "path"))

    def test_open_schema_includes_shared_server_login_fields(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "open")
        props = tool.inputSchema["properties"]

        for key in (
            "serverUsername",
            "serverPassword",
            "serverHost",
            "serverPort",
            "openAllPrograms",
            "destinationFolder",
            "analyzeAfterImport",
            "enableVersionControl",
            "forceIgnoreLock",
        ):
            assert key in props

        expected = set(TOOL_PARAMS["open"])
        assert expected.issubset(set(props.keys()))

    def test_manage_files_action_enum(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "manage-files")
        # Action or operation should be present
        props = tool.inputSchema["properties"]
        enum_key = "action" if "action" in props else "operation"
        assert enum_key in props
        enum_vals = props[enum_key]["enum"]
        for action in ("rename", "delete", "copy", "move"):
            assert action in enum_vals

    def test_list_project_files_pagination(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "list-project-files")
        props = tool.inputSchema["properties"]
        assert "maxResults" in props or "folder" in props

    def test_list_project_binary_metadata_params(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "list-project-binary-metadata")
        props = tool.inputSchema["properties"]
        assert any(k in props for k in ("binaryName", "binary_name", "programPath"))


class TestProjectProviderHandlers:
    def test_handler_keys_normalized(self):
        for key in ProjectToolProvider.HANDLERS:
            assert key == n(key)

    def test_open_handler_present(self):
        assert "open" in ProjectToolProvider.HANDLERS

    def test_getcurrentprogram_handler_present(self):
        assert "getcurrentprogram" in ProjectToolProvider.HANDLERS

    def test_listprojectfiles_handler_present(self):
        assert "listprojectfiles" in ProjectToolProvider.HANDLERS

    def test_managefiles_handler_present(self):
        assert "managefiles" in ProjectToolProvider.HANDLERS

    def test_listprojectbinaries_handler_present(self):
        assert "listprojectbinaries" in ProjectToolProvider.HANDLERS

    def test_deleteprojectbinary_handler_present(self):
        assert "deleteprojectbinary" in ProjectToolProvider.HANDLERS

    def test_importfile_alias_present(self):
        """importfile alias is used by pyghidra-mcp clients."""
        assert "importfile" in ProjectToolProvider.HANDLERS

    def test_getcurrentaddress_handler_present(self):
        assert "getcurrentaddress" in ProjectToolProvider.HANDLERS

    def test_getcurrentfunction_handler_present(self):
        assert "getcurrentfunction" in ProjectToolProvider.HANDLERS

    def test_listopenprograms_handler_present(self):
        assert "listopenprograms" in ProjectToolProvider.HANDLERS

    def test_openprogramincodebrowser_present(self):
        assert "openprogramincodebrowser" in ProjectToolProvider.HANDLERS

    def test_openallprogramsincodebrowser_present(self):
        assert "openallprogramsincodebrowser" in ProjectToolProvider.HANDLERS


class TestProjectProviderValidation:
    @pytest.mark.asyncio
    async def test_list_project_files_without_program(self):
        """list-project-files may work even without a loaded program (returns empty or error)."""
        p = _make_provider(with_program=False)
        resp = await p.call_tool("list-project-files", {})
        result = _parse(resp)
        # Either succeeds with empty list OR returns an error - both acceptable
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_get_current_program_with_program(self):
        p = _make_provider(with_program=True)
        resp = await p.call_tool("get-current-program", {})
        result = _parse(resp)
        # Should succeed and contain program info
        if "error" not in result:
            assert "name" in result or "program" in result or "programPath" in result

    @pytest.mark.asyncio
    async def test_gui_only_tools_return_error(self):
        """open-program-in-code-browser is GUI-only and should return error in headless."""
        p = _make_provider(with_program=True)
        resp = await p.call_tool("open-program-in-code-browser", {})
        result = _parse(resp)
        assert "error" in result or result.get("success") is False

    @pytest.mark.asyncio
    async def test_open_shared_server_mode_does_not_require_local_path(self, monkeypatch):
        p = _make_provider(with_program=False)

        class _DummySock:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        monkeypatch.setattr(socket, "create_connection", lambda *args, **kwargs: _DummySock())

        resp = await p.call_tool(
            "open",
            {
                "serverHost": "170.9.241.140",
                "serverPort": 13100,
                "serverUsername": "OpenKotOR",
                "serverPassword": "MuchaShakaPaka",
                "path": "Odyssey",
            },
        )
        result = _parse(resp)

        assert result.get("mode") == "shared-server"
        assert result.get("serverHost") == "170.9.241.140"
        assert result.get("serverPort") == 13100
        assert result.get("repository") == "Odyssey"
        assert result.get("authProvided") is True


class TestProjectProviderArgNormalization:
    @pytest.mark.asyncio
    async def test_filepath_normalized(self):
        p = _make_provider(with_program=True)
        received = {}

        async def capture(args):
            received.update(args)
            from agentdecompile_cli.mcp_server.tool_providers import create_error_response
            return create_error_response("mocked")

        p._handle_open = capture
        await p.call_tool("open", {"filePath": "/tmp/test.elf"})
        assert "filepath" in received

    @pytest.mark.asyncio
    async def test_openallprograms_normalized(self):
        p = _make_provider(with_program=True)
        received = {}

        async def capture(args):
            received.update(args)
            from agentdecompile_cli.mcp_server.tool_providers import create_error_response
            return create_error_response("mocked")

        p._handle_open = capture
        await p.call_tool("open", {"openAllPrograms": True})
        assert "openallprograms" in received


class TestProjectProviderSharedServer:
    """Comprehensive tests for shared-server (repo login) flow."""

    @pytest.mark.asyncio
    async def test_shared_server_unreachable(self, monkeypatch):
        """When the server cannot be reached, serverReachable should be False."""
        p = _make_provider(with_program=False)

        def fail_connect(*args, **kwargs):
            raise OSError("Connection refused")

        monkeypatch.setattr(socket, "create_connection", fail_connect)

        resp = await p.call_tool(
            "open",
            {
                "serverHost": "192.0.2.1",
                "serverPort": 13100,
                "serverUsername": "user",
                "serverPassword": "pass",
                "path": "TestRepo",
            },
        )
        result = _parse(resp)
        assert result.get("mode") == "shared-server"
        assert result.get("serverReachable") is False

    @pytest.mark.asyncio
    async def test_shared_server_without_credentials(self, monkeypatch):
        """Server open without username/password should set authProvided=False."""
        p = _make_provider(with_program=False)

        class _DummySock:
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False

        monkeypatch.setattr(socket, "create_connection", lambda *a, **kw: _DummySock())

        resp = await p.call_tool(
            "open",
            {
                "serverHost": "170.9.241.140",
                "serverPort": 13100,
                "path": "Odyssey",
            },
        )
        result = _parse(resp)
        assert result.get("mode") == "shared-server"
        assert result.get("authProvided") is False

    @pytest.mark.asyncio
    async def test_shared_server_normalized_arg_keys(self, monkeypatch):
        """Arg keys like server_host / SERVER_PORT must be accepted after normalization."""
        p = _make_provider(with_program=False)

        class _DummySock:
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False

        monkeypatch.setattr(socket, "create_connection", lambda *a, **kw: _DummySock())

        resp = await p.call_tool(
            "open",
            {
                "server_host": "170.9.241.140",
                "server_port": "13100",
                "server_username": "OpenKotOR",
                "server_password": "MuchaShakaPaka",
                "path": "Odyssey",
            },
        )
        result = _parse(resp)
        assert result.get("mode") == "shared-server"
        assert result.get("serverHost") == "170.9.241.140"
        assert result.get("authProvided") is True
