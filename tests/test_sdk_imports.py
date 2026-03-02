"""Unit tests for the AgentDecompile Python SDK / public imports.

Ported from root-level test_sdk.py.
No backend or PyGhidra required — pure import + instantiation checks.
"""

from __future__ import annotations

from typing import Any

import pytest


class TestImports:
    """Verify that public API surface can be imported."""

    def test_tool_provider_manager_importable(self) -> None:
        from agentdecompile_cli.mcp_server.tool_providers import ToolProviderManager  # noqa: F401

        assert ToolProviderManager is not None

    def test_normalize_identifier_importable(self) -> None:
        from agentdecompile_cli.registry import normalize_identifier  # noqa: F401

        assert normalize_identifier is not None

    def test_tool_registry_importable(self) -> None:
        from agentdecompile_cli.registry import ToolRegistry  # noqa: F401

        assert ToolRegistry is not None

    def test_tool_provider_manager_submodule_importable(self) -> None:
        import agentdecompile_cli.mcp_server.tool_providers as tpm  # noqa: F401

        assert tpm is not None

    def test_agentdecompile_cli_package_importable(self) -> None:
        import agentdecompile_cli  # noqa: F401

        assert agentdecompile_cli is not None


class TestToolProviderManagerInstantiation:
    """Verify ToolProviderManager can be constructed and introspected."""

    @pytest.fixture(scope="class")
    def manager(self):
        from agentdecompile_cli.mcp_server.tool_providers import ToolProviderManager

        return ToolProviderManager()

    def test_manager_is_not_none(self, manager) -> None:
        assert manager is not None

    def test_list_tools_returns_list(self, manager) -> None:
        tool_list = manager.list_tools()
        assert isinstance(tool_list, list)

    def test_list_tools_is_non_empty(self, manager) -> None:
        tool_list = manager.list_tools()
        assert len(tool_list) > 0

    def test_each_tool_has_name(self, manager) -> None:
        tool_list = manager.list_tools()
        for tool in tool_list:
            name = tool.name if hasattr(tool, "name") else tool.get("name")  # type: ignore[union-attr]
            assert name is not None, f"Tool entry missing 'name': {tool!r}"
            assert isinstance(name, str)
            assert name.strip() != ""

    def test_each_tool_has_description(self, manager) -> None:
        tool_list = manager.list_tools()
        for tool in tool_list:
            desc = tool.description if hasattr(tool, "description") else tool.get("description")  # type: ignore[union-attr]
            name = tool.name if hasattr(tool, "name") else "?"
            assert desc is not None, f"Tool '{name}' missing 'description'"
            assert isinstance(desc, str)

    def test_tool_count_at_least_10(self, manager) -> None:
        """Sanity check — the project advertises 49 tools."""
        tool_list = manager.list_tools()
        assert len(tool_list) >= 10

    def test_known_tool_names_present(self, manager) -> None:
        tool_list = manager.list_tools()
        names = {
            (t.name if hasattr(t, "name") else t.get("name", ""))  # type: ignore[union-attr]
            for t in tool_list
        }
        # list_tools() returns Tool objects whose .name uses underscores
        expected = {
            "manage_symbols",
            "inspect_memory",
            "manage_comments",
            "manage_bookmarks",
        }
        missing = expected - names
        assert not missing, f"Expected tools not advertised: {missing}"

    def test_list_tools_idempotent(self, manager) -> None:
        def _name(t: Any) -> str:
            return t.name if hasattr(t, "name") else t.get("name", "")  # type: ignore[union-attr]

        first = manager.list_tools()
        second = manager.list_tools()
        assert len(first) == len(second)
        assert [_name(t) for t in first] == [_name(t) for t in second]


class TestNormalizeIdentifier:
    """Unit tests for the canonical normalization function."""

    @pytest.fixture(scope="class")
    def n(self):
        from agentdecompile_cli.registry import normalize_identifier

        return normalize_identifier

    def test_snake_case(self, n) -> None:
        assert n("manage_symbols") == "managesymbols"

    def test_kebab_case(self, n) -> None:
        assert n("manage-symbols") == "managesymbols"

    def test_camel_case(self, n) -> None:
        assert n("manageSymbols") == "managesymbols"

    def test_uppercase(self, n) -> None:
        assert n("MANAGE_SYMBOLS") == "managesymbols"

    def test_spaces(self, n) -> None:
        assert n("manage symbols") == "managesymbols"

    def test_mixed_separators(self, n) -> None:
        assert n("@@manage-symbols___") == "managesymbols"

    def test_idempotent_on_normalized_input(self, n) -> None:
        normalized = n("manage-symbols")
        assert n(normalized) == normalized

    def test_empty_string(self, n) -> None:
        assert n("") == ""

    def test_all_non_alpha(self, n) -> None:
        assert n("___---!!!") == ""
