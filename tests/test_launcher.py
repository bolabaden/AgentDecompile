"""Test AgentDecompileLauncher lifecycle management.

Verifies that:
- Launcher can start and stop
- Server becomes ready within timeout
- Configuration options are respected
- Multiple start/stop cycles work
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentdecompile_cli.launcher import AgentDecompileLauncher

from tests.helpers import assert_bool_invariants, assert_int_invariants


class TestLauncherLifecycle:
    """Test AgentDecompile launcher lifecycle"""

    def test_launcher_starts_and_stops(self, ghidra_initialized: bool):
        """Launcher can start and stop cleanly"""
        from agentdecompile_cli.launcher import AgentDecompileLauncher

        launcher = AgentDecompileLauncher()

        # Should not be running initially
        assert not launcher.isRunning()
        assert not launcher.isServerReady()
        assert_bool_invariants(launcher.isRunning())
        assert_bool_invariants(launcher.isServerReady())

        # Start server
        launcher.start()

        # Wait for server to be ready
        ready = launcher.waitForServer(30000)
        assert ready, "Server failed to become ready within 30 seconds"

        # Verify status
        assert launcher.isRunning()
        assert launcher.isServerReady()
        assert_bool_invariants(launcher.isRunning())
        assert_bool_invariants(launcher.isServerReady())

        # Should have valid port
        port = launcher.getPort()
        assert port is not None
        assert 1024 < port < 65535
        assert_int_invariants(port, min_value=1, max_value=65535)

        # Stop server
        launcher.stop()

        # Should not be running after stop
        assert not launcher.isRunning()
        assert_bool_invariants(launcher.isRunning())

    def test_launcher_timeout_on_wait(self, ghidra_initialized: bool):
        """WaitForServer returns False if called before start"""
        from agentdecompile_cli.launcher import AgentDecompileLauncher

        launcher = AgentDecompileLauncher()

        # Should timeout immediately since server not started
        ready = launcher.waitForServer(1000)
        assert not ready
        assert_bool_invariants(ready)

    def test_server_fixture_provides_ready_server(self, server: AgentDecompileLauncher):
        """Server fixture provides a running and ready server"""
        assert server.isRunning()
        assert server.isServerReady()
        assert_bool_invariants(server.isRunning())
        assert_bool_invariants(server.isServerReady())

        port = server.getPort()
        assert port is not None
        assert 1024 < port < 65535
        assert_int_invariants(port, min_value=1, max_value=65535)


class TestLauncherConfiguration:
    """Test launcher configuration options"""

    def test_launcher_with_default_config(
        self,
        ghidra_initialized: bool,
    ):
        """Launcher works with default configuration"""
        from agentdecompile_cli.launcher import AgentDecompileLauncher

        launcher = AgentDecompileLauncher()
        launcher.start()

        assert launcher.waitForServer(30000)

        # Default port should be 8080
        port = launcher.getPort()
        assert port == 8080
        assert_int_invariants(port, min_value=1, max_value=65535)

        launcher.stop()

    def test_launcher_with_custom_config(
        self,
        ghidra_initialized: bool,
        tmp_path: Path,
    ):
        """Launcher respects configuration file"""
        from agentdecompile_cli.launcher import AgentDecompileLauncher

        # Create config file with custom port
        config_file = tmp_path / "test.properties"
        config_file.write_text("agentdecompile.server.options.server.port=9999\nagentdecompile.server.options.server.host=127.0.0.1\n")

        # Create launcher with config file
        launcher = AgentDecompileLauncher(config_file)
        launcher.start()

        assert launcher.waitForServer(30000)

        # Should use configured port
        port = launcher.getPort()
        assert port == 9999
        assert_int_invariants(port, min_value=1, max_value=65535)

        launcher.stop()

    def test_launcher_with_missing_config_file(
        self,
        ghidra_initialized: bool,
        tmp_path: Path,
    ):
        """Launcher handles missing config file gracefully with defaults"""
        from agentdecompile_cli.launcher import AgentDecompileLauncher

        # Create launcher with non-existent config - should use defaults
        nonexistent = tmp_path / "does_not_exist.properties"
        launcher = AgentDecompileLauncher(nonexistent)

        # Should start successfully with default config
        launcher.start()
        assert launcher.waitForServer(30000)

        # Should use default port
        port = launcher.getPort()
        assert port == 8080
        assert_int_invariants(port, min_value=1, max_value=65535)

        launcher.stop()
