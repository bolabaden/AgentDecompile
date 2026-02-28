#!/usr/bin/env python3
"""AgentDecompile CLI - Main entry point.

Provides stdio MCP transport for AgentDecompile, enabling integration with Claude CLI.
Usage: claude mcp add AgentDecompile -- mcp-agentdecompile [--config PATH] [--verbose]

Connect mode (1:1 with Python MCP server): --server-url or --host/--port.
Defaults for host/port come from AGENT_DECOMPILE_SERVER_HOST and AGENT_DECOMPILE_SERVER_PORT.
Project path (when spawning local server): AGENT_DECOMPILE_PROJECT_PATH.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import signal
import sys

from pathlib import Path
from typing import TYPE_CHECKING, Any, TextIO

from agentdecompile_cli.bridge import _apply_mcp_session_fix

# Apply MCP SDK fix before any ClientSession use (list() snapshot for _response_streams iteration)
_apply_mcp_session_fix()

from agentdecompile_cli.bridge import AgentDecompileStdioBridge  # noqa: E402
from agentdecompile_cli.executor import (  # noqa: E402
    handle_command_error,
    resolve_backend_url,
    run_async,
)
from agentdecompile_cli.launcher import (
    AgentDecompileLauncher,  # noqa: E402
    ProjectManager,  # noqa: E402
)

try:
    from agentdecompile_cli import __version__
except ImportError:
    __version__ = "0.0.0.dev0"  # noqa: F811

if TYPE_CHECKING:
    from types import FrameType


def _redirect_java_outputs():
    """Best-effort JVM output redirection setup.

    The previous implementation depended on removed extension-side classes.
    Stdout/stderr filters already protect the MCP stream, so this hook now
    becomes a no-op when no redirect bridge is available.
    """
    try:
        from jpype import isJVMStarted  # pyright: ignore[reportMissingImports]

        if not isJVMStarted():
            return
    except Exception as e:
        sys.stderr.write(f"Warning: JVM output redirection setup skipped: {e}\n")


class StderrFilter:
    """Wraps stderr writes in JSON-RPC notification messages to ensure all output is valid JSON.

    All writes to stderr are wrapped in JSON-RPC notifications with method "_log" so they
    can be safely read by MCP clients without causing JSON parsing errors.
    """

    def __init__(self, real_stderr: TextIO):
        self.real_stderr: TextIO = real_stderr
        self._buffer: str = ""
        self._closed: bool = False

    def write(self, s: str) -> int:
        """Write to stderr, wrapping in JSON-RPC notification if needed."""
        if self._closed or not s:
            return 0

        # Add to buffer
        self._buffer += s

        # Flush when we see a newline (complete log message) or buffer gets too large
        if "\n" in self._buffer or len(self._buffer) > 4096:
            # Extract complete lines
            lines: list[str] = self._buffer.split("\n")
            # Keep the last incomplete line in buffer
            self._buffer = lines[-1]
            # Process complete lines
            for line in lines[:-1]:
                if line.strip():  # Only wrap non-empty lines
                    self._write_jsonrpc_log(line)
            # If buffer is too large, flush it too
            if len(self._buffer) > 4096:
                if self._buffer.strip():
                    self._write_jsonrpc_log(self._buffer)
                self._buffer = ""

        return len(s)

    def _write_jsonrpc_log(self, message: str):
        """Write a log message wrapped in a JSON-RPC notification."""
        # Escape the message for JSON
        escaped_message: str = json.dumps(message)
        # Create JSON-RPC notification
        # Format: {"jsonrpc":"2.0","method":"_log","params":{"message":"..."}}
        jsonrpc_msg: str = '{"jsonrpc":"2.0","method":"_log","params":{"message":' + escaped_message + "}}\n"
        self.real_stderr.write(jsonrpc_msg)
        self.real_stderr.flush()

    def flush(self):
        """Flush any remaining buffer."""
        if self._buffer:
            if self._buffer.strip():
                self._write_jsonrpc_log(self._buffer)
            self._buffer = ""
        self.real_stderr.flush()

    def close(self):
        """Close the filter (but not the underlying stream)."""
        if not self._closed:
            self.flush()
            self._closed = True

    def __getattr__(self, name: str) -> Any:
        """Delegate other attributes to real stderr."""
        return getattr(self.real_stderr, name)


class StdoutFilter:
    """Filters stdout writes to prevent non-JSON output from interfering with MCP stdio protocol.

    Writes that look like JSON-RPC messages (start with '{' and contain "jsonrpc") are passed
    through to the real stdout. All other writes are redirected to stderr (which is wrapped
    to ensure JSON-RPC format) to prevent them from corrupting the MCP JSON-RPC stream.

    This handles the case where PyGhidra/Java code writes log messages to stdout, which would
    otherwise corrupt the JSON-RPC protocol stream used by MCP stdio transport.
    """

    def __init__(self, real_stdout: TextIO):
        self.real_stdout: TextIO = real_stdout
        self._buffer: str = ""
        self._closed: bool = False

    def write(self, s: str) -> int:
        """Write to stdout if JSON-RPC, otherwise redirect to wrapped stderr."""
        if self._closed or not s:
            return 0

        # Add to buffer
        self._buffer += s
        buffer_stripped: str = self._buffer.lstrip()

        # CRITICAL: Immediately redirect anything that doesn't start with '{'
        # This prevents Java log messages (like "INFO  Using...") from corrupting JSON-RPC
        if buffer_stripped and not buffer_stripped.startswith("{"):
            # Definitely not JSON-RPC - redirect immediately to wrapped stderr
            # Don't wait for newline - redirect character by character if needed
            written = sys.stderr.write(self._buffer)
            sys.stderr.flush()
            self._buffer = ""
            return written

        # Might be JSON-RPC - check if we have a complete message
        if buffer_stripped.startswith("{") and '"jsonrpc"' in self._buffer:
            # Check if we have a complete JSON-RPC message
            # JSON-RPC messages are typically on a single line and end with }\n
            if "\n" in self._buffer:
                # We have a complete line - check if it's valid JSON-RPC
                lines = self._buffer.split("\n", 1)
                first_line = lines[0]
                if first_line.rstrip().endswith("}") and '"jsonrpc"' in first_line:
                    # This is JSON-RPC - pass through to real stdout
                    written = self.real_stdout.write(lines[0] + "\n")
                    self.real_stdout.flush()
                    # Keep any remaining content in buffer
                    self._buffer = lines[1] if len(lines) > 1 else ""
                    return written
                # Not valid JSON-RPC - redirect to stderr
                written = sys.stderr.write(self._buffer)
                sys.stderr.flush()
                self._buffer = ""
                return written

        # Buffer is growing - if it gets too large, assume it's not JSON-RPC
        if len(self._buffer) > 8192:
            # Buffer too large - likely not JSON-RPC, redirect to stderr
            written = sys.stderr.write(self._buffer)
            sys.stderr.flush()
            self._buffer = ""
            return written

        # Keep buffering (waiting for newline to determine if it's JSON)
        return len(s)

    def flush(self):
        """Flush both streams."""
        if self._buffer:
            # Check if remaining buffer is JSON-RPC
            buffer_stripped = self._buffer.lstrip()
            if buffer_stripped.startswith("{") and '"jsonrpc"' in self._buffer and self._buffer.rstrip().endswith("}"):
                # Complete JSON-RPC message - write to stdout
                self.real_stdout.write(self._buffer)
                self.real_stdout.flush()
            else:
                # Not JSON-RPC - redirect to wrapped stderr
                sys.stderr.write(self._buffer)
                sys.stderr.flush()
            self._buffer = ""
        self.real_stdout.flush()
        sys.stderr.flush()

    def close(self):
        """Close the filter (but not the underlying streams)."""
        if not self._closed:
            self.flush()
            self._closed = True

    def __getattr__(self, name: str) -> Any:
        """Delegate other attributes to real stdout."""
        return getattr(self.real_stdout, name)


class AgentDecompileCLI:
    """Main CLI application."""

    def __init__(
        self,
        launcher: AgentDecompileLauncher | None,
        project_manager: ProjectManager | None,
        backend: int | str,
    ):
        """Initialize AgentDecompile CLI with pre-initialized components.

        Args:
            launcher: Pre-initialized AgentDecompile server launcher (local mode)
            project_manager: Pre-initialized project manager (local mode)
            backend: Backend port (int) or URL (str)
        """
        self.launcher: AgentDecompileLauncher | None = launcher
        self.project_manager: ProjectManager | None = project_manager
        self.backend: int | str = backend
        self.bridge: AgentDecompileStdioBridge | None = None
        self.cleanup_done: bool = False

    def setup_signal_handlers(self):
        """Setup signal handlers for clean shutdown."""

        def signal_handler(sig: int, frame: FrameType | None):
            if not self.cleanup_done:
                sys.stderr.write(
                    f"\nReceived signal {sig}, shutting down gracefully...\n",
                )
                self.cleanup()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # Handle SIGHUP on Unix systems
        if hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, signal_handler)

    def cleanup(self):
        """Clean up all resources."""
        if self.cleanup_done:
            return

        self.cleanup_done = True
        sys.stderr.write("Cleaning up resources...\n")

        if self.bridge is not None:
            try:
                self.bridge.stop()
            except Exception:
                pass

        if self.project_manager is not None:
            try:
                self.project_manager.cleanup()
            except Exception:
                pass

        if self.launcher is not None:
            try:
                self.launcher.stop()
            except Exception:
                pass

        sys.stderr.write("Cleanup complete\n")

    async def run(self):
        """Run the async stdio bridge (all initialization already done)."""
        try:
            # Setup signal handlers
            self.setup_signal_handlers()

            # Start stdio bridge
            if isinstance(self.backend, int):
                sys.stderr.write(f"Starting stdio bridge on local backend port {self.backend}...\n")
            else:
                sys.stderr.write(f"Starting stdio bridge to remote backend {self.backend}...\n")
            self.bridge = AgentDecompileStdioBridge(self.backend)

            # Run the bridge (this blocks until stopped)
            await self.bridge.run()

        except KeyboardInterrupt:
            sys.stderr.write("\nInterrupted by user\n")
        except Exception:
            raise
        finally:
            # Clean up json stream
            if self.bridge and hasattr(self.bridge, "_current_json_stream") and self.bridge._current_json_stream:
                try:
                    # Note: aclose is async, but we can't await here
                    # The async context managers should have handled cleanup already
                    pass
                except Exception:
                    pass
            self.cleanup()


def main():
    """Main entry point for mcp-agentdecompile command."""
    parser = argparse.ArgumentParser(
        description="AgentDecompile MCP server with stdio transport for Claude CLI integration",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="Path to AgentDecompile configuration file",
        required=False,
    )
    parser.add_argument(
        "--server-url",
        type=str,
        help="Connect to an existing AgentDecompile MCP server (http(s)://host:port[/mcp/message])",
        required=False,
    )
    parser.add_argument(
        "--host",
        type=str,
        default=None,
        metavar="HOST",
        help="Server host for connect mode (default: 127.0.0.1 or AGENT_DECOMPILE_SERVER_HOST)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        metavar="PORT",
        help="Server port for connect mode (default: 8080 or AGENT_DECOMPILE_SERVER_PORT)",
    )
    parser.add_argument(
        "-f",
        "--format",
        dest="output_format",
        type=str,
        choices=["json", "table", "text"],
        default="text",
        help="Output format for human-readable messages (default: text)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging",
        default=False,
        required=False,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    args = parser.parse_args()

    backend_url: str | None = resolve_backend_url(
        args.server_url,
        args.host,
        args.port,
    )

    # Validate config file if provided
    if args.config and not args.config.exists():
        sys.stderr.write(f"Error: Configuration file not found: {args.config}\n")
        sys.exit(1)

    # Connect mode: strictly bridge to existing Python-hosted MCP server.
    if backend_url is not None and backend_url.strip():
        if args.config:
            sys.stderr.write(
                "Note: --config is ignored when connecting to an existing MCP server.\n",
            )
        cli = AgentDecompileCLI(
            launcher=None,
            project_manager=None,
            backend=backend_url,
        )
        try:
            run_async(cli.run())
        except KeyboardInterrupt:
            sys.stderr.write("\nShutdown complete\n")
            sys.exit(0)
        except (asyncio.exceptions.CancelledError, Exception) as e:
            handle_command_error(e)
            sys.exit(1)
        return

    # =========================================================================
    # BLOCKING INITIALIZATION (before async event loop)
    # =========================================================================
    # All blocking operations happen here to avoid blocking the event loop
    # This ensures the stdio bridge can start immediately when asyncio.run() is called
    #
    # CRITICAL: PyGhidra and Python code may write log messages to stdout during both
    # initialization and runtime. We install a stdout filter that intercepts all writes:
    # - JSON-RPC messages (for MCP protocol) are passed through to real stdout
    # - All other output (logs, prints, etc.) is redirected to stderr
    # This prevents non-JSON text from corrupting the MCP stdio JSON-RPC stream.

    # Save original stdout/stderr
    original_stdout = sys.stdout
    original_stderr = sys.stderr

    try:
        # Install filters BEFORE PyGhidra initializes
        # - stdout: Only allows JSON-RPC messages through
        # - stderr: Wraps all writes in JSON-RPC notifications
        # This ensures ALL output is valid JSON and won't corrupt the MCP stdio stream
        # IMPORTANT: Install stderr filter first, then stdout filter (which uses sys.stderr)
        stderr_filter = StderrFilter(original_stderr)
        sys.stderr = stderr_filter  # type: ignore[assignment]
        stdout_filter = StdoutFilter(original_stdout)
        sys.stdout = stdout_filter  # type: ignore[assignment]

        # Initialize PyGhidra (blocking, 3-5 seconds)
        # Any stdout writes from PyGhidra will be caught by the filter and sent to stderr
        sys.stderr.write("Initializing PyGhidra...\n")
        try:
            import pyghidra
        except ImportError:
            sys.stdout = original_stdout
            sys.stderr = original_stderr
            sys.stderr.write(
                "PyGhidra is not installed for local spawn mode.\n"
                'Install with the local extra (e.g. `pip install "agentdecompile[local]"`) '
                "or connect to an existing server using --server-url.\n",
            )
            sys.exit(1)

        pyghidra.start(verbose=args.verbose)

        # CRITICAL: Redirect Java's System.out/System.err AFTER PyGhidra starts (for compatibility)
        # This ensures Java/Ghidra log messages go through our Python filters
        _redirect_java_outputs()

        sys.stderr.write("PyGhidra initialized\n")

        # Force garbage collection to clean up any lingering references
        import gc

        gc.collect()

        project_manager = ProjectManager()
        launcher = AgentDecompileLauncher(config_file=args.config, use_random_port=True)
        port = launcher.start()
        sys.stderr.write(f"AgentDecompile server ready on port {port}\n")

        # NOTE: stdout filter remains in place - do NOT restore original_stdout
        # The filter will allow JSON-RPC messages through while redirecting everything else

    except Exception as e:
        # Restore stdout/stderr even on error
        sys.stdout = original_stdout
        sys.stderr = original_stderr
        sys.stderr.write(f"Initialization error: {e.__class__.__name__}: {e}\n")
        import traceback

        traceback.print_exc(file=sys.stderr)
        sys.exit(1)

    # =========================================================================
    # ASYNC EXECUTION (stdio bridge only)
    # =========================================================================
    # Create CLI with pre-initialized components
    cli = AgentDecompileCLI(
        launcher=launcher,
        project_manager=project_manager,
        backend=port,
    )

    try:
        run_async(cli.run())
    except KeyboardInterrupt:
        sys.stderr.write("\nShutdown complete\n")
        sys.exit(0)
    except (asyncio.exceptions.CancelledError, Exception) as e:
        handle_command_error(e)
        sys.exit(1)


if __name__ == "__main__":
    main()
