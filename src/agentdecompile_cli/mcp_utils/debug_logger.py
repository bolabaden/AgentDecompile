"""Debug logger utility for AgentDecompile Python implementation.

Provides configuration-aware debug logging, .
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
        DebugLogger._debug_enabled = enabled

    @staticmethod
    def is_debug_enabled() -> bool:
        """Check if debug mode is currently enabled."""
        return DebugLogger._debug_enabled

    @staticmethod
    def debug(source: Any, message: str) -> None:
        """Log a debug message if debug mode is enabled.

        Args:
            source: The source object for the log message
            message: The message to log
        """
        if DebugLogger._debug_enabled:
            logger.info(f"[DEBUG] {message}")

    @staticmethod
    def debug_with_exception(source: Any, message: str, exception: Exception) -> None:
        """Log a debug message with an exception if debug mode is enabled.

        Args:
            source: The source object for the log message
            message: The message to log
            exception: The exception to include
        """
        if DebugLogger._debug_enabled:
            logger.info(f"[DEBUG] {message}: {exception}")

    @staticmethod
    def debug_connection(source: Any, message: str) -> None:
        """Log a connection-related debug message if debug mode is enabled.

        Args:
            source: The source object for the log message
            message: The message to log
        """
        if DebugLogger._debug_enabled:
            logger.info(f"[DEBUG-CONNECTION] {message}")

    @staticmethod
    def debug_performance(source: Any, operation: str, duration_ms: int) -> None:
        """Log a performance-related debug message if debug mode is enabled.

        Args:
            source: The source object for the log message
            operation: The operation being timed
            duration_ms: The duration in milliseconds
        """
        if DebugLogger._debug_enabled:
            logger.info(f"[DEBUG-PERF] {operation} took {duration_ms}ms")

    @staticmethod
    def debug_tool_execution(source: Any, tool_name: str, status: str, details: str | None = None) -> None:
        """Log a tool execution debug message if debug mode is enabled.

        Args:
            source: The source object for the log message
            tool_name: The name of the tool being executed
            status: The status (START, END, ERROR, etc.)
            details: Additional details (optional)
        """
        if DebugLogger._debug_enabled:
            message = f"[DEBUG-TOOL] {tool_name} - {status}"
            if details:
                message += f": {details}"
            logger.info(message)

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
                self.source = src
                self.operation = op
                self.start_time: float | None = None

            def __enter__(self):
                self.start_time = time.time()
                cls.debug_tool_execution(self.source, self.operation, "START")
                return self

            def __exit__(self, exc_type, exc_val, exc_tb):
                if self.start_time is not None:
                    duration_ms = int((time.time() - self.start_time) * 1000)
                    status = "ERROR" if exc_type else "SUCCESS"
                    cls.debug_performance(self.source, self.operation, duration_ms)
                    cls.debug_tool_execution(self.source, self.operation, status)

        return Timer(source, operation_name)
