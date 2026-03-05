"""Tests for legacy tools advertisement control via environment variables.

This test module validates:
- AGENTDECOMPILE_ENABLE_LEGACY_TOOLS env var controls tool advertisement
- AGENTDECOMPILE_SHOW_LEGACY_TOOLS env var controls tool advertisement
- Both env vars produce identical behavior (synonyms)
- Default behavior (no env vars) limits advertisement to DEFAULT_ADVERTISED_TOOLS
- Truthy value parsing works correctly (1, true, yes, on)

IMPORTANT: These tests modify global registry state via module reloading.
Run this test file in isolation or before other registry-dependent tests.
"""

from __future__ import annotations

import importlib
import os
import sys
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Generator

pytestmark = pytest.mark.unit


def _reload_registry_fresh() -> None:
    """Force complete reload of registry module and clear all caches."""
    # Remove from sys.modules to force true reload
    if 'agentdecompile_cli.registry' in sys.modules:
        del sys.modules['agentdecompile_cli.registry']
    # Also clear dependent modules that import registry
    modules_to_clear = [
        'agentdecompile_cli.mcp_server.tool_providers',
        'agentdecompile_cli.cli',
    ]
    for mod in modules_to_clear:
        if mod in sys.modules:
            del sys.modules[mod]


@pytest.fixture(scope="function")
def clean_env() -> Generator[None, None, None]:
    """Ensure clean environment for each test by removing legacy tool env vars."""
    env_vars = (
        "AGENTDECOMPILE_ENABLE_LEGACY_TOOLS",
        "AGENTDECOMPILE_SHOW_LEGACY_TOOLS",
        "AGENTDECOMPILE_ENABLE_TOOLS",
        "AGENTDECOMPILE_DISABLE_TOOLS",
    )
    
    # Save original values
    original_values = {var: os.environ.get(var) for var in env_vars}
    
    # Remove all env vars
    for var in env_vars:
        os.environ.pop(var, None)
    
    # Force fresh reload
    _reload_registry_fresh()
    
    yield
    
    # Restore original values
    for var in env_vars:
        os.environ.pop(var, None)
        original_val = original_values[var]
        if original_val is not None:
            os.environ[var] = original_val
    
    # Force fresh reload to restore original state
    _reload_registry_fresh()


@pytest.fixture(scope="module", autouse=True)
def restore_registry_after_module() -> Generator[None, None, None]:
    """Ensure registry is restored to original state after all tests in this module."""
    # Save original env state
    env_vars = (
        "AGENTDECOMPILE_ENABLE_LEGACY_TOOLS",
        "AGENTDECOMPILE_SHOW_LEGACY_TOOLS",
        "AGENTDECOMPILE_ENABLE_TOOLS",
        "AGENTDECOMPILE_DISABLE_TOOLS",
    )
    original_values = {var: os.environ.get(var) for var in env_vars}
    
    yield
    
    # Restore and reload
    for var in env_vars:
        os.environ.pop(var, None)
        original_val = original_values[var]
        if original_val is not None:
            os.environ[var] = original_val
    
    # Final cleanup reload
    _reload_registry_fresh()
    # Reimport to populate sys.modules
    import agentdecompile_cli.registry  # noqa: F401


class TestLegacyToolsEnvironmentVariables:
    """Validate environment variable control of legacy tool advertisement."""
    
    def test_default_advertises_minimal_tool_set(self, clean_env):
        """With no env vars set, only DEFAULT_ADVERTISED_TOOLS should be advertised."""
        from agentdecompile_cli.registry import ADVERTISED_TOOLS, DEFAULT_ADVERTISED_TOOLS, TOOLS
        
        # Should advertise default set (minus GUI-only tools)
        assert len(ADVERTISED_TOOLS) < len(TOOLS), "Default should advertise fewer tools than total"
        assert len(ADVERTISED_TOOLS) >= len(DEFAULT_ADVERTISED_TOOLS) - 5, "Should advertise approximately default count"
    
    def test_enable_legacy_tools_advertises_all(self, clean_env):
        """AGENTDECOMPILE_ENABLE_LEGACY_TOOLS=1 should advertise all tools."""
        os.environ["AGENTDECOMPILE_ENABLE_LEGACY_TOOLS"] = "1"
        
        import agentdecompile_cli.registry
        importlib.reload(agentdecompile_cli.registry)
        
        from agentdecompile_cli.registry import ADVERTISED_TOOLS, DISABLED_GUI_ONLY_TOOLS, TOOLS
        
        # Should advertise all tools except GUI-only
        expected_count = len([t for t in TOOLS if t not in DISABLED_GUI_ONLY_TOOLS])
        assert len(ADVERTISED_TOOLS) == expected_count, "Should advertise all non-GUI tools"
    
    def test_show_legacy_tools_advertises_all(self, clean_env):
        """AGENTDECOMPILE_SHOW_LEGACY_TOOLS=1 should advertise all tools (synonym)."""
        os.environ["AGENTDECOMPILE_SHOW_LEGACY_TOOLS"] = "1"
        
        import agentdecompile_cli.registry
        importlib.reload(agentdecompile_cli.registry)
        
        from agentdecompile_cli.registry import ADVERTISED_TOOLS, DISABLED_GUI_ONLY_TOOLS, TOOLS
        
        # Should advertise all tools except GUI-only
        expected_count = len([t for t in TOOLS if t not in DISABLED_GUI_ONLY_TOOLS])
        assert len(ADVERTISED_TOOLS) == expected_count, "SHOW_LEGACY should behave identically to ENABLE_LEGACY"
    
    @pytest.mark.parametrize("truthy_value", ["1", "true", "True", "TRUE", "yes", "Yes", "YES", "on", "On", "ON"])
    def test_truthy_value_variations(self, clean_env, truthy_value):
        """All truthy value variations should enable legacy tools."""
        os.environ["AGENTDECOMPILE_ENABLE_LEGACY_TOOLS"] = truthy_value
        
        import agentdecompile_cli.registry
        importlib.reload(agentdecompile_cli.registry)
        
        from agentdecompile_cli.registry import ADVERTISED_TOOLS, DISABLED_GUI_ONLY_TOOLS, TOOLS
        
        expected_count = len([t for t in TOOLS if t not in DISABLED_GUI_ONLY_TOOLS])
        assert len(ADVERTISED_TOOLS) == expected_count, f"Value '{truthy_value}' should enable legacy tools"
    
    @pytest.mark.parametrize("falsy_value", ["0", "false", "False", "no", "off", "", " "])
    def test_falsy_value_variations(self, clean_env, falsy_value):
        """All falsy value variations should NOT enable legacy tools."""
        os.environ["AGENTDECOMPILE_ENABLE_LEGACY_TOOLS"] = falsy_value
        
        import agentdecompile_cli.registry
        importlib.reload(agentdecompile_cli.registry)
        
        from agentdecompile_cli.registry import ADVERTISED_TOOLS, TOOLS
        
        assert len(ADVERTISED_TOOLS) < len(TOOLS), f"Value '{falsy_value}' should NOT enable legacy tools"
    
    def test_either_env_var_enables_legacy_tools(self, clean_env):
        """Either ENABLE or SHOW env var should be sufficient to enable legacy tools."""
        # Test with only ENABLE set
        os.environ["AGENTDECOMPILE_ENABLE_LEGACY_TOOLS"] = "1"
        
        import agentdecompile_cli.registry
        importlib.reload(agentdecompile_cli.registry)
        
        from agentdecompile_cli.registry import ADVERTISED_TOOLS as ADVERTISED_WITH_ENABLE
        
        # Clear and test with only SHOW set
        os.environ.pop("AGENTDECOMPILE_ENABLE_LEGACY_TOOLS")
        os.environ["AGENTDECOMPILE_SHOW_LEGACY_TOOLS"] = "1"
        
        importlib.reload(agentdecompile_cli.registry)
        
        from agentdecompile_cli.registry import ADVERTISED_TOOLS as ADVERTISED_WITH_SHOW
        
        assert len(ADVERTISED_WITH_ENABLE) == len(ADVERTISED_WITH_SHOW), "Both env vars should produce identical results"
    
    def test_gui_only_tools_never_advertised(self, clean_env):
        """GUI-only tools should never be advertised, even with legacy tools enabled."""
        os.environ["AGENTDECOMPILE_ENABLE_LEGACY_TOOLS"] = "1"
        
        import agentdecompile_cli.registry
        importlib.reload(agentdecompile_cli.registry)
        
        from agentdecompile_cli.registry import ADVERTISED_TOOLS, DISABLED_GUI_ONLY_TOOLS
        
        advertised_set = set(ADVERTISED_TOOLS)
        for gui_tool in DISABLED_GUI_ONLY_TOOLS:
            assert gui_tool not in advertised_set, f"GUI-only tool '{gui_tool}' should never be advertised"


class TestLegacyToolsProviderIntegration:
    """Validate UnifiedToolProvider respects environment variable configuration."""
    
    def test_provider_respects_default_advertisement(self, clean_env):
        """UnifiedToolProvider should advertise minimal set by default."""
        from agentdecompile_cli.mcp_server.tool_providers import UnifiedToolProvider
        from agentdecompile_cli.registry import ADVERTISED_TOOLS, to_snake_case
        
        provider = UnifiedToolProvider()
        advertised_tools = provider.list_tools()
        advertised_names = {tool.name for tool in advertised_tools}
        
        expected_names = {to_snake_case(name) for name in ADVERTISED_TOOLS}
        assert advertised_names == expected_names, "Provider should match registry advertisement"
    
    def test_provider_respects_legacy_tools_enabled(self, clean_env):
        """UnifiedToolProvider should advertise all tools when legacy enabled."""
        os.environ["AGENTDECOMPILE_ENABLE_LEGACY_TOOLS"] = "1"
        
        # Must reload registry before creating provider
        import agentdecompile_cli.registry
        importlib.reload(agentdecompile_cli.registry)
        
        from agentdecompile_cli.mcp_server.tool_providers import UnifiedToolProvider
        
        # Reload provider module to pick up updated registry
        import agentdecompile_cli.mcp_server.tool_providers
        importlib.reload(agentdecompile_cli.mcp_server.tool_providers)
        
        from agentdecompile_cli.registry import DISABLED_GUI_ONLY_TOOLS, TOOLS
        
        provider = UnifiedToolProvider()
        advertised_tools = provider.list_tools()
        
        expected_count = len([t for t in TOOLS if t not in DISABLED_GUI_ONLY_TOOLS])
        assert len(advertised_tools) == expected_count, "Provider should advertise all non-GUI tools"


class TestIsTruthyEnvFunction:
    """Validate _is_truthy_env() helper function behavior."""
    
    @pytest.mark.parametrize("truthy_value", ["1", "true", "True", "TRUE", "yes", "Yes", "On", "ON", " 1 ", " yes "])
    def test_recognizes_truthy_values(self, truthy_value):
        """_is_truthy_env should recognize standard truthy values."""
        from agentdecompile_cli.registry import _is_truthy_env
        
        assert _is_truthy_env(truthy_value) is True, f"'{truthy_value}' should be truthy"
    
    @pytest.mark.parametrize("falsy_value", [None, "", "0", "false", "no", "off", "random", " ", "2"])
    def test_recognizes_falsy_values(self, falsy_value):
        """_is_truthy_env should treat non-truthy values as falsy."""
        from agentdecompile_cli.registry import _is_truthy_env
        
        assert _is_truthy_env(falsy_value) is False, f"'{falsy_value}' should be falsy"


class TestAdvertisedToolsConsistency:
    """Validate consistency between different advertisement mechanisms."""
    
    def test_advertised_tools_subset_of_all_tools(self, clean_env):
        """ADVERTISED_TOOLS should always be a subset of TOOLS."""
        from agentdecompile_cli.registry import ADVERTISED_TOOLS, TOOLS
        
        advertised_set = set(ADVERTISED_TOOLS)
        all_tools_set = set(TOOLS)
        
        assert advertised_set.issubset(all_tools_set), "Advertised tools must be subset of all tools"
    
    def test_advertised_tool_params_matches_advertised_tools(self, clean_env):
        """ADVERTISED_TOOL_PARAMS keys should match ADVERTISED_TOOLS."""
        from agentdecompile_cli.registry import ADVERTISED_TOOL_PARAMS, ADVERTISED_TOOLS
        
        params_tools = set(ADVERTISED_TOOL_PARAMS.keys())
        advertised = set(ADVERTISED_TOOLS)
        
        assert params_tools == advertised, "ADVERTISED_TOOL_PARAMS should match ADVERTISED_TOOLS"


class TestExplicitEnableTools:
    """Validate AGENTDECOMPILE_ENABLE_TOOLS env var behavior."""

    def test_enable_tools_restricts_to_exact_list(self, clean_env):
        """AGENTDECOMPILE_ENABLE_TOOLS=a,b should advertise exactly those tools."""
        os.environ["AGENTDECOMPILE_ENABLE_TOOLS"] = "checkin-program,decompile-function"

        import agentdecompile_cli.registry
        importlib.reload(agentdecompile_cli.registry)

        from agentdecompile_cli.registry import ADVERTISED_TOOLS, normalize_identifier

        advertised_normalized = {normalize_identifier(t) for t in ADVERTISED_TOOLS}
        assert advertised_normalized == {"checkinprogram", "decompilefunction"}, (
            "AGENTDECOMPILE_ENABLE_TOOLS should restrict advertisement to exactly the listed tools"
        )

    def test_enable_tools_overrides_disable_tools(self, clean_env):
        """AGENTDECOMPILE_ENABLE_TOOLS overrides AGENTDECOMPILE_DISABLE_TOOLS."""
        os.environ["AGENTDECOMPILE_ENABLE_TOOLS"] = "decompile-function,list-functions"
        os.environ["AGENTDECOMPILE_DISABLE_TOOLS"] = "decompile-function"

        import agentdecompile_cli.registry
        importlib.reload(agentdecompile_cli.registry)

        from agentdecompile_cli.registry import ADVERTISED_TOOLS, normalize_identifier

        advertised_normalized = {normalize_identifier(t) for t in ADVERTISED_TOOLS}
        assert "decompilefunction" in advertised_normalized, (
            "ENABLE_TOOLS should override DISABLE_TOOLS — explicitly enabled tool must appear"
        )

    def test_empty_enable_tools_falls_back_to_defaults(self, clean_env):
        """Empty AGENTDECOMPILE_ENABLE_TOOLS should fall back to normal behavior."""
        os.environ["AGENTDECOMPILE_ENABLE_TOOLS"] = ""

        import agentdecompile_cli.registry
        importlib.reload(agentdecompile_cli.registry)

        from agentdecompile_cli.registry import ADVERTISED_TOOLS, DEFAULT_ADVERTISED_TOOLS

        assert len(ADVERTISED_TOOLS) >= len(DEFAULT_ADVERTISED_TOOLS) - 5, (
            "Empty ENABLE_TOOLS should fall back to default advertisement count"
        )

    def test_enable_tools_can_expose_legacy_tool(self, clean_env):
        """A legacy tool can be included via AGENTDECOMPILE_ENABLE_TOOLS without ENABLE_LEGACY_TOOLS."""
        os.environ["AGENTDECOMPILE_ENABLE_TOOLS"] = "suggest,decompile-function"

        import agentdecompile_cli.registry
        importlib.reload(agentdecompile_cli.registry)

        from agentdecompile_cli.registry import ADVERTISED_TOOLS, normalize_identifier

        advertised_normalized = {normalize_identifier(t) for t in ADVERTISED_TOOLS}
        assert "suggest" in advertised_normalized, (
            "Legacy tool 'suggest' should be advertised when explicitly listed in ENABLE_TOOLS"
        )

    def test_enable_tools_whitespace_tolerance(self, clean_env):
        """AGENTDECOMPILE_ENABLE_TOOLS should tolerate spaces around tool names."""
        os.environ["AGENTDECOMPILE_ENABLE_TOOLS"] = " decompile-function , list-functions "

        import agentdecompile_cli.registry
        importlib.reload(agentdecompile_cli.registry)

        from agentdecompile_cli.registry import ADVERTISED_TOOLS, normalize_identifier

        advertised_normalized = {normalize_identifier(t) for t in ADVERTISED_TOOLS}
        assert advertised_normalized == {"decompilefunction", "listfunctions"}, (
            "Tool names with surrounding whitespace should still be recognized"
        )
