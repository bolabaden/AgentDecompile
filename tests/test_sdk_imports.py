"""Unit tests for the AgentDecompile Python SDK / public imports.

Ported from root-level test_sdk.py.
No backend or PyGhidra required — pure import + instantiation checks.
"""

from __future__ import annotations


class TestImports:
    """Verify that public API surface can be imported."""

    def test_tool_provider_manager_importable(self) -> None:
        from agentdecompile_cli.mcp_server.tool_providers import ToolProviderManager  # noqa: F401

        assert ToolProviderManager is not None

    def test_tool_registry_importable(self) -> None:
        from agentdecompile_cli.registry import ToolRegistry  # noqa: F401

        assert ToolRegistry is not None

    def test_tool_provider_manager_submodule_importable(self) -> None:
        import agentdecompile_cli.mcp_server.tool_providers as tpm  # noqa: F401

        assert tpm is not None

    def test_agentdecompile_cli_package_importable(self) -> None:
        import agentdecompile_cli  # noqa: F401

        assert agentdecompile_cli is not None
