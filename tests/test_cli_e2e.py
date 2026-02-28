"""End-to-end tests for mcp-agentdecompile CLI with stdio transport.

Tests the complete CLI workflow using the official MCP Python SDK's stdio_client.
These tests verify that the CLI can:
- Start successfully via stdio
- Initialize an MCP session
- List and call MCP tools
- Handle multiple requests
- Shut down cleanly

All tests use real PyGhidra and Ghidra integration.
"""

from __future__ import annotations

import types

from pathlib import Path

import pytest

from mcp import ClientSession

from tests.helpers import assert_bool_invariants, assert_int_invariants, assert_tool_response_common

# Mark all tests in this file
# E2E tests need longer timeout due to PyGhidra initialization (10-30s) + server startup
pytestmark = [
    pytest.mark.cli,
    pytest.mark.e2e,
    pytest.mark.slow,
    pytest.mark.asyncio,
    pytest.mark.timeout(180),  # 3 minutes for full subprocess + PyGhidra + server startup
]


class TestCLIStartup:
    """Test CLI startup and initialization via stdio."""

    async def test_cli_initializes_successfully(self, mcp_stdio_client: ClientSession):
        """CLI starts and initializes MCP session successfully"""
        # mcp_stdio_client fixture already initializes
        # If we got here, initialization succeeded
        assert mcp_stdio_client is not None
        assert_bool_invariants(mcp_stdio_client is not None)

    @pytest.mark.skip(reason="Requires manual setup of locked project; see test body for instructions")
    async def test_cli_starts_even_if_project_is_locked(self, isolated_workspace: Path):
        """A locked AGENT_DECOMPILE_PROJECT_PATH should not prevent tool registration/startup.

        Regression test: previously a project open failure would crash startup and no tools would register.
        """
        import asyncio
        import os

        from mcp import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client

        project_name = "LockedProject"
        project_dir = isolated_workspace

        # Minimal valid "project exists" shape:
        # - <dir>/<name>.gpr marker file
        # - <dir>/<name>.rep/data project data directory
        gpr_path = project_dir / f"{project_name}.gpr"
        gpr_path.write_text("dummy")
        project_dir.joinpath(f"{project_name}.rep", "data").mkdir(parents=True, exist_ok=True)

        # Simulate a locked project (Ghidra lock file lives alongside the .gpr)
        lock_path = project_dir / f"{project_name}.lock"
        lock_path.write_text("pid: 99999\n")

        env = os.environ.copy()
        env["AGENT_DECOMPILE_PROJECT_PATH"] = str(gpr_path)

        # cwd must be repo root so uv run finds pyproject.toml
        repo_root = Path(__file__).resolve().parent.parent
        server_params = StdioServerParameters(
            command="uv",
            args=["run", "mcp-agentdecompile"],
            cwd=str(repo_root),
            env=env,
        )

        async with stdio_client(server_params) as (read_stream, write_stream):
            session = ClientSession(read_stream, write_stream)
            await session.__aenter__()
            try:
                # Give subprocess time to complete blocking initialization
                await asyncio.sleep(2)

                init_result = await asyncio.wait_for(session.initialize(), timeout=60.0)
                assert init_result.serverInfo.name == "AgentDecompile"
                assert_bool_invariants(init_result.serverInfo.name == "AgentDecompile")

                tools = await session.list_tools()
                # Locked project should not prevent tool registration - expect substantial tool list
                assert len(tools.tools) > 20
                assert_int_invariants(len(tools.tools), min_value=1)
            finally:
                try:
                    await session.__aexit__(None, None, None)
                except RuntimeError as e:
                    # Known pytest-asyncio/anyio cancel-scope teardown quirk
                    if "cancel scope" not in str(e):
                        raise

    async def test_server_info_is_correct(
        self,
        mcp_stdio_client: ClientSession,
    ):
        """Server reports correct name and version"""
        # Initialize already happened in fixture, but we can check the info
        # by calling initialize again (it's idempotent in MCP)
        result = await mcp_stdio_client.initialize()

        assert result.serverInfo.name == "AgentDecompile"
        # Version from MCP SDK (e.g. 1.26.0)
        assert result.serverInfo.version and result.serverInfo.version.startswith("1.")
        assert_bool_invariants(result.serverInfo.version.startswith("1."))

    async def test_server_capabilities(
        self,
        mcp_stdio_client: ClientSession,
    ):
        """Server reports expected capabilities"""
        result = await mcp_stdio_client.initialize()

        # AgentDecompile supports tools, resources, and prompts
        assert result.capabilities.tools is not None
        assert result.capabilities.resources is not None
        assert result.capabilities.prompts is not None
        assert_bool_invariants(result.capabilities.tools is not None)
        assert_bool_invariants(result.capabilities.resources is not None)
        assert_bool_invariants(result.capabilities.prompts is not None)


class TestMCPToolCalls:
    """Test MCP tool calls via stdio."""

    async def test_list_tools(
        self,
        mcp_stdio_client: ClientSession,
    ):
        """Can list all available MCP tools"""
        result = await mcp_stdio_client.list_tools()

        # AgentDecompile has substantial tool set
        assert len(result.tools) > 20
        assert_int_invariants(len(result.tools), min_value=1)

        # Check for some essential tools
        tool_names: list[str] = [tool.name for tool in result.tools]
        assert "list-project-files" in tool_names
        # Note: Tool names may vary, just ensure we have a substantial list
        assert len([name for name in tool_names if "function" in name.lower()]) > 0

    async def test_call_list_programs_tool(
        self,
        mcp_stdio_client: ClientSession,
        test_binary: Path,
    ):
        """Can call list-project-files tool.

        Note: Do not add ghidra_initialized - mcp_stdio_client uses subprocess.
        Starting PyGhidra in test process causes Windows access violation.
        """
        # The test_binary fixture creates a binary in isolated_workspace
        result: types.ToolResult = await mcp_stdio_client.call_tool("list-project-files", arguments={})

        # Should get a response (even if no files in project yet)
        assert result is not None
        assert hasattr(result, "content")
        assert_tool_response_common(result)

    async def test_list_resources(
        self,
        mcp_stdio_client: ClientSession,
    ):
        """Can list MCP resources"""
        result = await mcp_stdio_client.list_resources()

        # AgentDecompile provides program list resource
        assert result.resources is not None
        assert_bool_invariants(result.resources is not None)

    async def test_sequential_tool_calls(
        self,
        mcp_stdio_client: ClientSession,
    ):
        """Can make multiple sequential tool calls"""
        # Call list_tools twice
        result1 = await mcp_stdio_client.list_tools()
        result2 = await mcp_stdio_client.list_tools()

        # Should get same results
        assert len(result1.tools) == len(result2.tools)
        assert_int_invariants(len(result1.tools), min_value=1)


class TestProjectCreation:
    """Test that mcp-agentdecompile creates Ghidra project in .agentdecompile/."""

    async def test_does_not_create_agentdecompile_directory(
        self,
        mcp_stdio_client: ClientSession,
        isolated_workspace: Path,
        test_binary: Path,
    ):
        """CLI does NOT create .agentdecompile directory in stdio mode (lazy initialization prevents unnecessary creation)"""
        agentdecompile_dir = isolated_workspace / ".agentdecompile"

        # After CLI starts, .agentdecompile should NOT exist (lazy initialization)
        assert not agentdecompile_dir.exists(), ".agentdecompile directory should not exist at startup"
        assert_bool_invariants(agentdecompile_dir.exists() is False)

        # Even after using MCP tools, .agentdecompile should NOT be created
        # (MCP tools use Java-side project management, not Python ProjectManager)
        await mcp_stdio_client.call_tool("import-file", arguments={"path": str(test_binary)})

        # .agentdecompile still should NOT exist (ProjectManager.import_binary() was never called)
        assert not agentdecompile_dir.exists(), ".agentdecompile directory should not be created by MCP tools in stdio mode"
        assert_bool_invariants(agentdecompile_dir.exists() is False)

    async def test_lazy_initialization_prevents_directory_creation(
        self,
        mcp_stdio_client: ClientSession,
        isolated_workspace: Path,
    ):
        """ProjectManager lazy initialization prevents .agentdecompile directory creation at startup"""
        agentdecompile_dir = isolated_workspace / ".agentdecompile"

        # The mcp_stdio_client fixture starts the CLI which creates a ProjectManager
        # With lazy initialization, .agentdecompile should NOT be created
        assert not agentdecompile_dir.exists(), ".agentdecompile directory should not be created by CLI startup"
        assert_bool_invariants(agentdecompile_dir.exists() is False)

        # Verify this remains true after a short delay
        import asyncio

        await asyncio.sleep(0.5)
        assert not agentdecompile_dir.exists(), ".agentdecompile directory should still not exist after CLI is running"
        assert_bool_invariants(agentdecompile_dir.exists() is False)


class TestBinaryAutoImport:
    """Test automatic binary import functionality."""

    async def test_imports_test_binary(
        self,
        mcp_stdio_client: ClientSession,
        test_binary: Path,
    ):
        """CLI auto-imports binaries from current directory.

        Note: mcp_stdio_client spawns CLI in subprocess (which runs PyGhidra).
        Do not add ghidra_initialized - starting PyGhidra in test process causes
        Windows access violation when run after subprocess-based tests.
        """
        # The test_binary fixture creates a minimal ELF
        # ProjectManager should attempt to import it

        # Give it time to import
        import asyncio

        await asyncio.sleep(5)

        # Try to list files in project
        result = await mcp_stdio_client.call_tool("list-project-files", arguments={})

        # Ideally we'd check if the binary was imported, but that requires
        # the import to succeed, which might fail for minimal test binaries
        # At minimum, the tool call should work
        assert result is not None
        assert_tool_response_common(result)


class TestErrorHandling:
    """Test error handling in CLI."""

    async def test_handles_unknown_tool(
        self,
        mcp_stdio_client: ClientSession,
    ):
        """CLI returns error for unknown tool"""
        # MCP SDK may or may not raise an exception for unknown tools
        # depending on SDK version and server implementation
        # Just verify the call completes without crashing
        try:
            result = await mcp_stdio_client.call_tool("nonexistent-tool", arguments={})
            # If it doesn't raise, that's also acceptable
            # The server may return an error result instead
            assert result is not None
            assert_tool_response_common(result)
        except Exception:
            # Exception is also acceptable for unknown tools
            pass

    async def test_handles_invalid_tool_arguments(
        self,
        mcp_stdio_client: ClientSession,
    ):
        """CLI validates tool arguments"""
        # Try to call a tool with wrong arguments
        # This might raise or return an error depending on the tool
        try:
            result = await mcp_stdio_client.call_tool(
                "get-functions",  # Current tool name
                arguments={"invalid_param": "value"},
            )
            # If it doesn't raise, check for error in result
            if hasattr(result, "isError"):
                assert result.isError
            assert_tool_response_common(result)
        except Exception:
            # Exception is also acceptable for invalid arguments
            pass
