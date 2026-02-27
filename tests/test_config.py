"""Test AgentDecompile configuration file loading and options.

Verifies that:
- Configuration files can be loaded
- Options are applied correctly
- Invalid configs are handled gracefully
"""

from __future__ import annotations

import sys

from pathlib import Path

import pytest

from tests.helpers import assert_int_invariants, assert_text_block_invariants

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="PyGhidra JVM crashes on Windows (JPype access violation)",
)


class TestConfigurationLoading:
    """Test configuration file loading"""

    def test_default_configuration(self, ghidra_initialized: bool):
        """Launcher works with default in-memory configuration"""
        from agentdecompile.plugin import ConfigManager  # pyright: ignore[reportMissingImports]

        # Create default config manager
        config = ConfigManager()

        # Should have default port
        port = config.getPort()
        assert port == 8080
        assert_int_invariants(port, min_value=1, max_value=65535)

    def test_file_configuration_loading(self, ghidra_initialized: bool, tmp_path: Path):
        """Configuration can be loaded from properties file"""
        from agentdecompile.plugin import ConfigManager  # pyright: ignore[reportMissingImports]

        # Create config file
        config_file = tmp_path / "test.properties"
        config_file.write_text("agentdecompile.server.options.server.port=7777\nagentdecompile.server.options.server.host=localhost\n")
        assert_text_block_invariants(config_file.read_text(), must_contain=["server.port", "server.host"])

        # Load config from file
        config = ConfigManager(str(config_file))

        # Should use configured port
        port = config.getPort()
        assert port == 7777
        assert_int_invariants(port, min_value=1, max_value=65535)

    def test_config_file_with_multiple_options(self, ghidra_initialized: bool, tmp_path: Path):
        """Configuration file supports multiple options"""
        from agentdecompile.plugin import ConfigManager  # pyright: ignore[reportMissingImports]

        config_file = tmp_path / "full.properties"
        config_file.write_text("""
# Server options
agentdecompile.server.options.server.port=8888
agentdecompile.server.options.server.host=127.0.0.1

# Debug options
agentdecompile.server.options.debug.mode=true
""")
        assert_text_block_invariants(config_file.read_text(), must_contain=["server.port", "server.host", "debug.mode"])

        config = ConfigManager(str(config_file))

        # Verify port loaded correctly
        assert config.getPort() == 8888
        assert_int_invariants(config.getPort(), min_value=1, max_value=65535)


class TestConfigurationEdgeCases:
    """Test configuration edge cases"""

    def test_missing_config_file(self, ghidra_initialized: bool, tmp_path: Path):
        """Missing config file falls back to defaults gracefully"""
        from agentdecompile.plugin import ConfigManager  # pyright: ignore[reportMissingImports]

        nonexistent = tmp_path / "missing.properties"

        # Should not raise - gracefully falls back to defaults
        config = ConfigManager(str(nonexistent))

        # Should use default port
        port = config.getPort()
        assert port == 8080
        assert_int_invariants(port, min_value=1, max_value=65535)

    def test_empty_config_file(self, ghidra_initialized: bool, tmp_path: Path):
        """Empty config file uses defaults"""
        from agentdecompile.plugin import ConfigManager  # pyright: ignore[reportMissingImports]

        config_file = tmp_path / "empty.properties"
        config_file.write_text("")

        config = ConfigManager(str(config_file))

        # Should use default port
        port = config.getPort()
        assert port == 8080
        assert_int_invariants(port, min_value=1, max_value=65535)

    def test_config_file_with_comments(self, ghidra_initialized: bool, tmp_path: Path):
        """Config file handles comments correctly"""
        from agentdecompile.plugin import ConfigManager  # pyright: ignore[reportMissingImports]

        config_file = tmp_path / "commented.properties"
        config_file.write_text("""
# This is a comment
agentdecompile.server.options.server.port=6666
# Another comment
""")
        assert_text_block_invariants(config_file.read_text(), must_contain=["server.port"])

        config = ConfigManager(str(config_file))

        # Should parse port despite comments
        assert config.getPort() == 6666
        assert_int_invariants(config.getPort(), min_value=1, max_value=65535)


class TestEnvironmentVariableConfiguration:
    """Test environment variable configuration - manual verification needed"""

    def test_env_var_logic_compiles(self):
        """Verify that the environment variable logic compiles correctly"""
        # This test just verifies the Java code compiles and imports work
        # The actual environment variable functionality requires manual testing
        # because PyGhidra initialization captures environment variables at startup

        # Test that we can import and create ConfigManager
        import pyghidra

        pyghidra.start(verbose=False)

        try:
            from agentdecompile.plugin import ConfigManager  # pyright: ignore[reportMissingImports]

            # Create config manager - should work without errors
            config = ConfigManager()
            assert config.getServerPort() is not None
            assert config.getServerHost() is not None
            assert_int_invariants(config.getServerPort(), min_value=1, max_value=65535)

        finally:
            # Note: PyGhidra doesn't have a shutdown method, just let it clean up
            pass
