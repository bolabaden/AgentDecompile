"""Configuration manager for AgentDecompile Python implementation.

Provides configuration management for headless operation, .
"""

from __future__ import annotations

import json
import logging
import os

from pathlib import Path
from typing import Any

from agentdecompile_cli.mcp_utils.debug_logger import DebugLogger

logger = logging.getLogger(__name__)


class ConfigChangeListener:
    """Interface for configuration change listeners."""

    def on_config_changed(self, category: str, name: str, old_value: Any, new_value: Any) -> None:
        """Called when a configuration value changes."""


class ConfigManager:
    """Configuration manager for AgentDecompile headless operation."""

    # Configuration option categories
    SERVER_OPTIONS = "AgentDecompile Server Options"

    # Option names
    SERVER_PORT = "Server Port"
    SERVER_HOST = "Server Host"
    SERVER_ENABLED = "Server Enabled"
    DEBUG_MODE = "Debug Mode"
    REQUEST_LOGGING_ENABLED = "Request Logging Enabled"
    MAX_DECOMPILER_SEARCH_FUNCTIONS = "Max Decompiler Search Functions"
    DECOMPILER_TIMEOUT_SECONDS = "Decompiler Timeout Seconds"
    IMPORT_ANALYSIS_TIMEOUT_SECONDS = "Import Analysis Timeout Seconds"
    WAIT_FOR_ANALYSIS_ON_IMPORT = "Wait For Analysis On Import"
    IMPORT_MAX_DEPTH = "Import Max Depth"

    # Default values
    DEFAULT_PORT = 8080
    DEFAULT_HOST = "127.0.0.1"
    DEFAULT_SERVER_ENABLED = True
    DEFAULT_DEBUG_MODE = False
    DEFAULT_REQUEST_LOGGING_ENABLED = False
    DEFAULT_MAX_DECOMPILER_SEARCH_FUNCTIONS = 1000
    DEFAULT_DECOMPILER_TIMEOUT_SECONDS = 10
    DEFAULT_IMPORT_ANALYSIS_TIMEOUT_SECONDS = 600
    DEFAULT_WAIT_FOR_ANALYSIS_ON_IMPORT = True
    DEFAULT_IMPORT_MAX_DEPTH = 10

    def __init__(self, config_file: Path | None = None):
        """Initialize configuration manager.

        Args:
            config_file: Optional path to configuration file
        """
        self.config_file = config_file
        self._config: dict[str, dict[str, Any]] = {}
        self._change_listeners: set[ConfigChangeListener] = set()

        # Load configuration
        self._load_config()

        # Apply environment variable overrides
        self._apply_env_overrides()

    def _load_config(self) -> None:
        """Load configuration from file if available."""
        if self.config_file and self.config_file.exists():
            try:
                with open(self.config_file) as f:
                    self._config = json.load(f)
                DebugLogger.debug(self, f"Loaded configuration from {self.config_file}")
            except Exception as e:
                logger.warning(f"Failed to load config file {self.config_file}: {e}")
                self._config = {}
        else:
            self._config = {}

        # Ensure default categories exist
        if self.SERVER_OPTIONS not in self._config:
            self._config[self.SERVER_OPTIONS] = {}

    def _apply_env_overrides(self) -> None:
        """Apply environment variable overrides."""
        # Server configuration
        if "AGENT_DECOMPILE_PORT" in os.environ:
            try:
                port = int(os.environ["AGENT_DECOMPILE_PORT"])
                self.set_server_port(port)
            except ValueError:
                logger.warning("Invalid AGENT_DECOMPILE_PORT value")

        if "AGENT_DECOMPILE_HOST" in os.environ:
            host = os.environ["AGENT_DECOMPILE_HOST"].strip()
            if host:
                self.set_server_host(host)

        # Debug configuration
        if "AGENT_DECOMPILE_DEBUG" in os.environ:
            debug_value = os.environ["AGENT_DECOMPILE_DEBUG"].lower()
            debug_enabled = debug_value in ("true", "1", "yes", "on")
            self.set_debug_mode(debug_enabled)
            DebugLogger.set_debug_enabled(debug_enabled)

    def save_config(self) -> None:
        """Save configuration to file."""
        if self.config_file:
            try:
                self.config_file.parent.mkdir(parents=True, exist_ok=True)
                with open(self.config_file, "w") as f:
                    json.dump(self._config, f, indent=2)
                DebugLogger.debug(self, f"Saved configuration to {self.config_file}")
            except Exception as e:
                logger.error(f"Failed to save config file {self.config_file}: {e}")

    def add_change_listener(self, listener: ConfigChangeListener) -> None:
        """Add a configuration change listener."""
        self._change_listeners.add(listener)

    def remove_change_listener(self, listener: ConfigChangeListener) -> None:
        """Remove a configuration change listener."""
        self._change_listeners.discard(listener)

    def _notify_change_listeners(self, category: str, name: str, old_value: Any, new_value: Any) -> None:
        """Notify all change listeners."""
        for listener in self._change_listeners:
            try:
                listener.on_config_changed(category, name, old_value, new_value)
            except Exception as e:
                logger.error(f"Error notifying config change listener: {e}")

    def _get_option(self, category: str, name: str, default_value: Any = None) -> Any:
        """Get a configuration option value."""
        category_config = self._config.get(category, {})
        return category_config.get(name, default_value)

    def _set_option(self, category: str, name: str, value: Any) -> None:
        """Set a configuration option value."""
        if category not in self._config:
            self._config[category] = {}

        old_value = self._config[category].get(name)
        self._config[category][name] = value

        # Notify listeners
        self._notify_change_listeners(category, name, old_value, value)

        # Auto-save if we have a config file
        if self.config_file:
            self.save_config()

    # Server configuration methods
    def get_server_port(self) -> int:
        """Get the server port."""
        return self._get_option(self.SERVER_OPTIONS, self.SERVER_PORT, self.DEFAULT_PORT)

    def set_server_port(self, port: int) -> None:
        """Set the server port."""
        if port < 1 or port > 65535:
            raise ValueError("Port must be between 1 and 65535")
        self._set_option(self.SERVER_OPTIONS, self.SERVER_PORT, port)

    def get_server_host(self) -> str:
        """Get the server host."""
        return self._get_option(self.SERVER_OPTIONS, self.SERVER_HOST, self.DEFAULT_HOST)

    def set_server_host(self, host: str) -> None:
        """Set the server host."""
        if not host or not host.strip():
            raise ValueError("Host cannot be empty")
        self._set_option(self.SERVER_OPTIONS, self.SERVER_HOST, host.strip())

    def is_server_enabled(self) -> bool:
        """Check if the server is enabled."""
        return self._get_option(self.SERVER_OPTIONS, self.SERVER_ENABLED, self.DEFAULT_SERVER_ENABLED)

    def set_server_enabled(self, enabled: bool) -> None:
        """Set whether the server is enabled."""
        self._set_option(self.SERVER_OPTIONS, self.SERVER_ENABLED, bool(enabled))

    # Debug configuration methods
    def is_debug_mode(self) -> bool:
        """Check if debug mode is enabled."""
        return self._get_option(self.SERVER_OPTIONS, self.DEBUG_MODE, self.DEFAULT_DEBUG_MODE)

    def set_debug_mode(self, enabled: bool) -> None:
        """Set debug mode."""
        self._set_option(self.SERVER_OPTIONS, self.DEBUG_MODE, bool(enabled))
        DebugLogger.set_debug_enabled(enabled)

    def is_request_logging_enabled(self) -> bool:
        """Check if request logging is enabled."""
        return self._get_option(self.SERVER_OPTIONS, self.REQUEST_LOGGING_ENABLED, self.DEFAULT_REQUEST_LOGGING_ENABLED)

    def set_request_logging_enabled(self, enabled: bool) -> None:
        """Set request logging."""
        self._set_option(self.SERVER_OPTIONS, self.REQUEST_LOGGING_ENABLED, bool(enabled))

    # Decompiler configuration methods
    def get_max_decompiler_search_functions(self) -> int:
        """Get the maximum number of functions to search in decompiler."""
        return self._get_option(self.SERVER_OPTIONS, self.MAX_DECOMPILER_SEARCH_FUNCTIONS, self.DEFAULT_MAX_DECOMPILER_SEARCH_FUNCTIONS)

    def set_max_decompiler_search_functions(self, max_functions: int) -> None:
        """Set the maximum number of functions to search in decompiler."""
        if max_functions < 1:
            raise ValueError("Max functions must be positive")
        self._set_option(self.SERVER_OPTIONS, self.MAX_DECOMPILER_SEARCH_FUNCTIONS, max_functions)

    def get_decompiler_timeout_seconds(self) -> int:
        """Get the decompiler timeout in seconds."""
        return self._get_option(self.SERVER_OPTIONS, self.DECOMPILER_TIMEOUT_SECONDS, self.DEFAULT_DECOMPILER_TIMEOUT_SECONDS)

    def set_decompiler_timeout_seconds(self, timeout: int) -> None:
        """Set the decompiler timeout in seconds."""
        if timeout < 1:
            raise ValueError("Timeout must be positive")
        self._set_option(self.SERVER_OPTIONS, self.DECOMPILER_TIMEOUT_SECONDS, timeout)

    # Import/analysis configuration methods
    def get_import_analysis_timeout_seconds(self) -> int:
        """Get the import analysis timeout in seconds."""
        return self._get_option(self.SERVER_OPTIONS, self.IMPORT_ANALYSIS_TIMEOUT_SECONDS, self.DEFAULT_IMPORT_ANALYSIS_TIMEOUT_SECONDS)

    def set_import_analysis_timeout_seconds(self, timeout: int) -> None:
        """Set the import analysis timeout in seconds."""
        if timeout < 1:
            raise ValueError("Timeout must be positive")
        self._set_option(self.SERVER_OPTIONS, self.IMPORT_ANALYSIS_TIMEOUT_SECONDS, timeout)

    def should_wait_for_analysis_on_import(self) -> bool:
        """Check if we should wait for analysis on import."""
        return self._get_option(self.SERVER_OPTIONS, self.WAIT_FOR_ANALYSIS_ON_IMPORT, self.DEFAULT_WAIT_FOR_ANALYSIS_ON_IMPORT)

    def set_wait_for_analysis_on_import(self, wait: bool) -> None:
        """Set whether to wait for analysis on import."""
        self._set_option(self.SERVER_OPTIONS, self.WAIT_FOR_ANALYSIS_ON_IMPORT, bool(wait))

    def get_import_max_depth(self) -> int:
        """Get the maximum import depth."""
        return self._get_option(self.SERVER_OPTIONS, self.IMPORT_MAX_DEPTH, self.DEFAULT_IMPORT_MAX_DEPTH)

    def set_import_max_depth(self, depth: int) -> None:
        """Set the maximum import depth."""
        if depth < 1:
            raise ValueError("Depth must be positive")
        self._set_option(self.SERVER_OPTIONS, self.IMPORT_MAX_DEPTH, depth)

    def get_all_options(self) -> dict[str, dict[str, Any]]:
        """Get all configuration options."""
        return self._config.copy()

    def reset_to_defaults(self) -> None:
        """Reset all options to defaults."""
        old_config = self._config.copy()
        self._config = {self.SERVER_OPTIONS: {}}
        self._notify_change_listeners(self.SERVER_OPTIONS, "*", old_config, self._config)

        if self.config_file:
            self.save_config()

    def __str__(self) -> str:
        """String representation of configuration."""
        return f"ConfigManager(config_file={self.config_file}, options={len(self._config)})"
