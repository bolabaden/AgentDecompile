"""Configuration-aware debug logging helpers.

DebugLogger is a static helper: set_debug_enabled(True/False) then call debug(),
timing(), etc. Messages are only emitted when debug is enabled; _source_name
produces a stable label (class name or type name) for log prefixes.
"""

from __future__ import annotations

import logging
import time

from typing import Any

logger = logging.getLogger(__name__)


class DebugLogger:
    """Debug logger utility that respects debug configuration settings."""

    _debug_enabled: bool = False

    @staticmethod
    def set_debug_enabled(enabled: bool) -> None:
        """Set whether debug logging is enabled."""
        logger.debug("diag.enter %s", "mcp_utils/debug_logger.py:DebugLogger.set_debug_enabled")
        DebugLogger._debug_enabled = enabled

    @staticmethod
    def is_debug_enabled() -> bool:
        """Check if debug mode is currently enabled."""
        logger.debug("diag.enter %s", "mcp_utils/debug_logger.py:DebugLogger.is_debug_enabled")
        return DebugLogger._debug_enabled

    @staticmethod
    def _source_name(source: Any) -> str:
        """Return a stable source label for log messages."""
        logger.debug("diag.enter %s", "mcp_utils/debug_logger.py:DebugLogger._source_name")
        if source is None:
            return "unknown"
        if isinstance(source, type):
            return source.__name__
        return source.__class__.__name__

    @classmethod
    def _log(cls, prefix: str, message: str, source: Any = None) -> None:
        """Emit a prefixed debug line when debug logging is enabled."""
        logger.debug("diag.enter %s", "mcp_utils/debug_logger.py:DebugLogger._log")
        if not cls._debug_enabled:
            return
        source_name = cls._source_name(source)
        logger.info("[%s] [%s] %s", prefix, source_name, message)

    @staticmethod
    def debug(source: Any, message: str) -> None:
        """Log a debug message if debug mode is enabled.

        Args:
            source: The source object for the log message
            message: The message to log
        """
        logger.debug("diag.enter %s", "mcp_utils/debug_logger.py:DebugLogger.debug")
        DebugLogger._log("DEBUG", message, source)

    @staticmethod
    def debug_with_exception(source: Any, message: str, exception: Exception) -> None:
        """Log a debug message with an exception if debug mode is enabled.

        Args:
            source: The source object for the log message
            message: The message to log
            exception: The exception to include
        """
        logger.debug("diag.enter %s", "mcp_utils/debug_logger.py:DebugLogger.debug_with_exception")
        DebugLogger._log("DEBUG", f"{message}: {exception}", source)

    @staticmethod
    def debug_connection(source: Any, message: str) -> None:
        """Log a connection-related debug message if debug mode is enabled.

        Args:
            source: The source object for the log message
            message: The message to log
        """
        logger.debug("diag.enter %s", "mcp_utils/debug_logger.py:DebugLogger.debug_connection")
        DebugLogger._log("DEBUG-CONNECTION", message, source)

    @staticmethod
    def debug_performance(source: Any, operation: str, duration_ms: int) -> None:
        """Log a performance-related debug message if debug mode is enabled.

        Args:
            source: The source object for the log message
            operation: The operation being timed
            duration_ms: The duration in milliseconds
        """
        logger.debug("diag.enter %s", "mcp_utils/debug_logger.py:DebugLogger.debug_performance")
        DebugLogger._log("DEBUG-PERF", f"{operation} took {duration_ms}ms", source)

    @staticmethod
    def debug_tool_execution(source: Any, tool_name: str, status: str, details: str | None = None) -> None:
        """Log a tool execution debug message if debug mode is enabled.

        Args:
            source: The source object for the log message
            tool_name: The name of the tool being executed
            status: The status (START, END, ERROR, etc.)
            details: Additional details (optional)
        """
        logger.debug("diag.enter %s", "mcp_utils/debug_logger.py:DebugLogger.debug_tool_execution")
        message = f"{tool_name} - {status}"
        if details:
            message += f": {details}"
        DebugLogger._log("DEBUG-TOOL", message, source)

    @classmethod
    def time_operation(cls, source: Any, operation_name: str):
        """Context manager to time an operation and log the duration.

        Args:
            source: The source object for logging
            operation_name: Name of the operation being timed

        Example:
            with DebugLogger.time_operation(self, "decompile_function"):
                result = decompile_function()
        """

        class Timer:
            def __init__(self, src: Any, op: str):
                logger.debug("diag.enter %s", "mcp_utils/debug_logger.py:DebugLogger.Timer.__init__")
                self.source = src
                self.operation = op
                self.start_time: float | None = None

            def __enter__(self):
                logger.debug("diag.enter %s", "mcp_utils/debug_logger.py:DebugLogger.Timer.__enter__")
                self.start_time = time.time()
                cls.debug_tool_execution(self.source, self.operation, "START")
                return self

            def __exit__(self, exc_type, exc_val, exc_tb):
                logger.debug("diag.enter %s", "mcp_utils/debug_logger.py:DebugLogger.Timer.__exit__")
                if self.start_time is not None:
                    duration_ms = int((time.time() - self.start_time) * 1000)
                    status = "ERROR" if exc_type else "SUCCESS"
                    cls.debug_performance(self.source, self.operation, duration_ms)
                    cls.debug_tool_execution(self.source, self.operation, status)

        logger.debug("diag.enter %s", "mcp_utils/debug_logger.py:DebugLogger.time_operation")
        return Timer(source, operation_name)
