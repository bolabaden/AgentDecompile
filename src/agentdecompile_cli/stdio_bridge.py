"""
Stdio to HTTP MCP bridge using official MCP SDK Server abstraction.

Provides a proper MCP Server that forwards all requests to AgentDecompile's StreamableHTTP endpoint.
Uses the MCP SDK's stdio transport and Pydantic serialization - no manual JSON-RPC handling.

The bridge acts as a transparent proxy - all tool calls, resources, and prompts are
forwarded to the Java AgentDecompile backend running on localhost.

Stability features:
- Concurrency limiting via asyncio.Semaphore to prevent overwhelming the backend
- Comprehensive error handling for BrokenResourceError, ClosedResourceError, and HTTP errors
- Automatic reconnection when the backend connection is lost
- Circuit breaker pattern to prevent cascading failures
- Graceful degradation: returns empty/error responses instead of crashing
"""

from __future__ import annotations

import asyncio
import sys
import time
from typing import TYPE_CHECKING, Any, Iterable

try:
    from anyio import BrokenResourceError, ClosedResourceError
except ImportError:
    # Fallback when anyio is unavailable - use distinct classes so except
    # (BrokenResourceError, ClosedResourceError) does not shadow except Exception
    class _PlaceholderConnectionError(Exception):  # noqa: B903
        """Placeholder; never raised when anyio is not available."""

    BrokenResourceError = _PlaceholderConnectionError
    ClosedResourceError = _PlaceholderConnectionError

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.shared.exceptions import McpError
from mcp.shared.message import SessionMessage
from mcp.types import (
    JSONRPCMessage,
    JSONRPCNotification,
    TextContent,
)

if TYPE_CHECKING:
    from mcp.server.lowlevel.helper_types import ReadResourceContents
    from mcp.server.lowlevel.server import (
        CombinationContent,
        StructuredContent,
        UnstructuredContent,
    )
    from mcp.types import (
        CallToolResult,
        Prompt,
        Resource,
        Tool,
    )
    from pydantic import AnyUrl


class JsonEnvelopeStream:
    """
    Wraps the MCP stream to handle parsing errors gracefully.
    The stream yields SessionMessage objects or Exception objects.
    When the MCP SDK fails to parse a log message as JSON-RPC, it creates an Exception.
    We catch those exceptions and convert them to valid SessionMessage objects.
    """

    def __init__(self, original_stream):
        self.original_stream = original_stream

    async def __aenter__(self):
        # If original stream supports context manager, enter it
        if hasattr(self.original_stream, "__aenter__"):
            return await self.original_stream.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        # If original stream supports context manager, exit it
        if hasattr(self.original_stream, "__aexit__"):
            return await self.original_stream.__aexit__(exc_type, exc_val, exc_tb)
        return None

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            item = await self.original_stream.__anext__()
        except StopAsyncIteration:
            raise

        # The stream yields SessionMessage | Exception
        # If it's an Exception (parsing error from log message), convert it to a valid SessionMessage
        if isinstance(item, Exception):
            # Extract the log message from the exception
            error_msg = str(item)
            # Create a valid JSON-RPC notification message for the log
            # Use a notification (no id) so it doesn't break request/response flow
            notification = JSONRPCNotification(
                jsonrpc="2.0",
                method="_log",
                params={"message": error_msg},
            )
            return SessionMessage(JSONRPCMessage(notification))

        # If it's already a SessionMessage, pass it through unchanged
        return item

    async def aclose(self):
        """Close the stream if it supports it."""
        if hasattr(self.original_stream, "aclose"):
            await self.original_stream.aclose()


def _is_connection_error(error: Exception) -> bool:
    """Check if an exception indicates a lost or broken connection.
    
    This centralizes connection error detection so all handlers behave consistently.
    Returns True for errors that indicate the backend connection is broken and 
    may need reconnection.
    """
    error_type = type(error).__name__
    error_str = str(error).lower()
    
    # Check by exception type
    connection_error_types = {
        "BrokenResourceError",
        "ClosedResourceError",
        "BrokenPipeError",
        "ConnectionError",
        "ConnectionResetError",
        "ConnectionRefusedError",
        "ConnectionAbortedError",
        "HTTPStatusError",
    }
    if error_type in connection_error_types:
        return True
    
    # Check by isinstance for imported types
    if isinstance(error, (BrokenResourceError, ClosedResourceError)):
        return True
    if isinstance(error, (ConnectionError, OSError)):
        return True
    
    # Check by error message content
    connection_keywords = [
        "session terminated",
        "connection closed",
        "connection lost",
        "connection refused",
        "connection reset",
        "broken pipe",
        "broken resource",
        "closed resource",
        "server error",
        "500 server error",
        "502 bad gateway",
        "503 service unavailable",
    ]
    for keyword in connection_keywords:
        if keyword in error_str:
            return True
    
    return False


class AgentDecompileStdioBridge:
    """
    MCP Server that bridges stdio to AgentDecompile's StreamableHTTP endpoint.

    Acts as a transparent proxy - forwards all MCP requests to the AgentDecompile backend
    and returns responses. The MCP SDK handles all JSON-RPC serialization.
    
    Stability features:
    - Request concurrency limiting via asyncio.Semaphore
    - Automatic retry with exponential backoff for transient errors
    - Circuit breaker to prevent cascading failures
    - Graceful error responses instead of crashes
    """

    # Maximum number of concurrent requests to send to the backend.
    # This prevents overwhelming the Java MCP server with too many simultaneous
    # requests (which causes HTTP 500 errors and connection crashes).
    MAX_CONCURRENT_REQUESTS = 3

    # Maximum retries for transient connection errors
    MAX_RETRIES = 3

    # Circuit breaker: max consecutive failures before backing off
    CIRCUIT_BREAKER_THRESHOLD = 5
    CIRCUIT_BREAKER_RESET_TIME = 10.0  # seconds

    def __init__(self, port: int):
        """
        Initialize the stdio bridge.

        Args:
            port: AgentDecompile server port to connect to
        """
        self.port = port
        self.url = f"http://localhost:{port}/mcp/message"
        self.server = Server("AgentDecompile")
        self.backend_session: ClientSession | None = None
        self._connection_context = None  # Store the connection context for reconnection
        self._current_json_stream = None  # Store current JsonEnvelopeStream for cleanup
        self._connection_params = {
            "timeout": 120.0,  # 2 minutes for connect/overall
            "read_timeout": 60.0,  # 1 minute for read operations
        }

        # Concurrency limiter - prevents overwhelming the backend
        self._request_semaphore = asyncio.Semaphore(self.MAX_CONCURRENT_REQUESTS)

        # Circuit breaker state
        self._consecutive_failures = 0
        self._circuit_open_until = 0.0
        self._circuit_lock = asyncio.Lock()

        # Register handlers
        self._register_handlers()

    async def _check_circuit_breaker(self) -> bool:
        """Check if the circuit breaker allows requests.
        
        Returns True if requests are allowed, False if the circuit is open (too many failures).
        When the circuit is open, waits for the reset time before allowing requests again.
        """
        async with self._circuit_lock:
            if self._consecutive_failures >= self.CIRCUIT_BREAKER_THRESHOLD:
                now = time.monotonic()
                if now < self._circuit_open_until:
                    # Circuit is still open - wait a bit
                    wait_time = self._circuit_open_until - now
                    sys.stderr.write(
                        f"Circuit breaker open: {self._consecutive_failures} consecutive failures. "
                        f"Waiting {wait_time:.1f}s before retry.\n"
                    )
                    return False
                else:
                    # Reset period expired - allow a probe request
                    sys.stderr.write("Circuit breaker: attempting recovery probe...\n")
            return True

    async def _record_success(self):
        """Record a successful operation - resets the circuit breaker."""
        async with self._circuit_lock:
            if self._consecutive_failures > 0:
                sys.stderr.write(
                    f"Backend recovered after {self._consecutive_failures} consecutive failures.\n"
                )
            self._consecutive_failures = 0

    async def _record_failure(self):
        """Record a failed operation - increments the circuit breaker counter."""
        async with self._circuit_lock:
            self._consecutive_failures += 1
            if self._consecutive_failures >= self.CIRCUIT_BREAKER_THRESHOLD:
                self._circuit_open_until = time.monotonic() + self.CIRCUIT_BREAKER_RESET_TIME
                sys.stderr.write(
                    f"Circuit breaker tripped: {self._consecutive_failures} consecutive failures. "
                    f"Backing off for {self.CIRCUIT_BREAKER_RESET_TIME}s.\n"
                )

    async def _ensure_backend_connected(self) -> ClientSession:
        """
        Ensure backend session is connected.

        Returns:
            ClientSession: Active backend session

        Raises:
            RuntimeError: If backend session is not available
        """
        if self.backend_session is None:
            raise RuntimeError("Backend session not initialized - connection lost")
        return self.backend_session

    async def _call_with_retry(self, operation_name: str, operation, *args, **kwargs):
        """
        Call a backend operation with automatic retry on transient errors.
        
        Handles all known connection error types including BrokenResourceError,
        ClosedResourceError, HTTP errors, and McpError.

        Args:
            operation_name: Name of the operation for logging
            operation: Async callable to execute
            *args, **kwargs: Arguments to pass to operation

        Returns:
            Result of the operation
        """
        # Check circuit breaker first
        if not await self._check_circuit_breaker():
            # Circuit is open - wait for reset time then try
            await asyncio.sleep(self.CIRCUIT_BREAKER_RESET_TIME)

        last_error = None
        for attempt in range(self.MAX_RETRIES):
            try:
                # Acquire concurrency slot
                async with self._request_semaphore:
                    result = await operation(*args, **kwargs)
                
                # Success - reset circuit breaker
                await self._record_success()
                return result

            except McpError as e:
                last_error = e
                if _is_connection_error(e):
                    await self._record_failure()
                    if attempt < self.MAX_RETRIES - 1:
                        wait_time = 0.5 * (2 ** attempt)  # Exponential backoff
                        sys.stderr.write(
                            f"WARNING: {operation_name} failed with MCP error, "
                            f"retrying in {wait_time:.1f}s (attempt {attempt + 1}/{self.MAX_RETRIES}): {e}\n"
                        )
                        await asyncio.sleep(wait_time)
                        if self.backend_session is None:
                            raise RuntimeError(
                                "Backend session lost and cannot recover within current connection."
                            )
                        continue
                    else:
                        sys.stderr.write(
                            f"ERROR: {operation_name} failed after {self.MAX_RETRIES} attempts: {e}\n"
                        )
                        raise
                else:
                    # Non-connection MCP error - don't retry, just raise
                    raise

            except asyncio.TimeoutError:
                last_error = asyncio.TimeoutError(f"{operation_name} timed out")
                await self._record_failure()
                raise
            except (BrokenResourceError, ClosedResourceError) as e:
                last_error = e
                await self._record_failure()
                error_type = type(e).__name__
                if attempt < self.MAX_RETRIES - 1:
                    wait_time = 0.5 * (2 ** attempt)
                    sys.stderr.write(
                        f"WARNING: {operation_name} failed with {error_type}, "
                        f"retrying in {wait_time:.1f}s (attempt {attempt + 1}/{self.MAX_RETRIES})\n"
                    )
                    await asyncio.sleep(wait_time)
                    if self.backend_session is None:
                        raise RuntimeError(
                            f"Backend connection broken ({error_type}). "
                            "Cannot recover within current connection."
                        )
                    continue
                else:
                    sys.stderr.write(
                        f"ERROR: {operation_name} permanently failed with {error_type} "
                        f"after {self.MAX_RETRIES} attempts\n"
                    )
                    raise

            except Exception as e:
                last_error = e
                if _is_connection_error(e):
                    await self._record_failure()
                    if attempt < self.MAX_RETRIES - 1:
                        wait_time = 0.5 * (2 ** attempt)
                        sys.stderr.write(
                            f"WARNING: {operation_name} failed with {type(e).__name__}, "
                            f"retrying in {wait_time:.1f}s (attempt {attempt + 1}/{self.MAX_RETRIES}): {e}\n"
                        )
                        await asyncio.sleep(wait_time)
                        if self.backend_session is None:
                            raise RuntimeError(
                                f"Backend connection lost ({type(e).__name__}). "
                                "Cannot recover within current connection."
                            )
                        continue
                # Non-connection error - don't retry
                raise

        # Should not reach here, but just in case
        if last_error:
            raise last_error
        raise RuntimeError(f"{operation_name} failed after {self.MAX_RETRIES} retries")

    def _register_handlers(self):
        """Register MCP protocol handlers that forward to AgentDecompile backend."""

        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            """Forward list_tools request to AgentDecompile backend with retry logic."""
            try:
                await self._ensure_backend_connected()
            except RuntimeError:
                return []

            async def _list_tools_operation():
                return await asyncio.wait_for(
                    self.backend_session.list_tools(),  # type: ignore
                    timeout=30.0,
                )

            try:
                result = await self._call_with_retry("list_tools", _list_tools_operation)
                if result is None:
                    return []
                return result.tools
            except asyncio.TimeoutError:
                sys.stderr.write("ERROR: list_tools timed out\n")
                return []
            except Exception as e:
                sys.stderr.write(
                    f"ERROR: list_tools failed: {e.__class__.__name__}: {e}\n"
                )
                return []

        @self.server.call_tool()
        async def call_tool(
            name: str,
            arguments: dict[str, Any],
        ) -> (
            UnstructuredContent
            | StructuredContent
            | CombinationContent
            | CallToolResult
        ):
            """Forward call_tool request to AgentDecompile backend with retry logic."""
            try:
                await self._ensure_backend_connected()
            except RuntimeError as e:
                return [TextContent(type="text", text=f"Error: Backend connection lost: {e}. The server may need to be restarted.")]

            async def _call_tool_operation():
                return await asyncio.wait_for(
                    self.backend_session.call_tool(name, arguments),  # type: ignore
                    timeout=300.0,  # 5 minutes for tool execution
                )

            try:
                result = await self._call_with_retry(
                    f"call_tool({name})", _call_tool_operation
                )
                if result is None:
                    return [
                        TextContent(
                            type="text", text=f"Error: Tool '{name}' returned no result"
                        )
                    ]
                return result.content
            except asyncio.TimeoutError:
                error_msg = f"Tool '{name}' timed out after 5 minutes"
                sys.stderr.write(f"ERROR: {error_msg}\n")
                return [TextContent(type="text", text=f"Error: {error_msg}. Please retry with a simpler query.")]
            except Exception as e:
                error_msg = f"Tool '{name}' failed: {e.__class__.__name__}: {e}"
                sys.stderr.write(f"ERROR: {error_msg}\n")
                # Return a helpful error message instead of crashing
                if _is_connection_error(e):
                    return [TextContent(
                        type="text",
                        text=f"Error: {error_msg}. The backend connection was lost. "
                             "This may be due to server overload from too many concurrent requests. "
                             "Please wait a moment and retry."
                    )]
                return [TextContent(type="text", text=f"Error: {error_msg}")]

        @self.server.list_resources()
        async def list_resources() -> list[Resource]:
            """Forward list_resources request to AgentDecompile backend with retry logic."""
            try:
                await self._ensure_backend_connected()
            except RuntimeError:
                return []

            async def _list_resources_operation():
                return await asyncio.wait_for(
                    self.backend_session.list_resources(),  # type: ignore
                    timeout=30.0,
                )

            try:
                result = await self._call_with_retry("list_resources", _list_resources_operation)
                if result is None:
                    return []
                return result.resources
            except asyncio.TimeoutError:
                sys.stderr.write("ERROR: list_resources timed out\n")
                return []
            except Exception as e:
                sys.stderr.write(
                    f"ERROR: list_resources failed: {e.__class__.__name__}: {e}\n"
                )
                return []

        @self.server.read_resource()
        async def read_resource(
            uri: AnyUrl,
        ) -> str | bytes | Iterable[ReadResourceContents]:
            """Forward read_resource request to AgentDecompile backend with retry logic."""
            try:
                await self._ensure_backend_connected()
            except RuntimeError:
                return ""

            async def _read_resource_operation():
                return await asyncio.wait_for(
                    self.backend_session.read_resource(uri),  # type: ignore
                    timeout=60.0,
                )

            try:
                result = await self._call_with_retry("read_resource", _read_resource_operation)
                if result is None:
                    return ""
                # Return the first content item's text or blob
                if result.contents and len(result.contents) > 0:
                    content = result.contents[0]
                    if hasattr(content, "text") and content.text:  # pyright: ignore[reportAttributeAccessIssue]
                        return content.text  # pyright: ignore[reportAttributeAccessIssue]
                    elif hasattr(content, "blob") and content.blob:  # pyright: ignore[reportAttributeAccessIssue]
                        return content.blob  # pyright: ignore[reportAttributeAccessIssue]
                return ""
            except asyncio.TimeoutError:
                sys.stderr.write(f"ERROR: read_resource timed out for URI: {uri}\n")
                return ""
            except Exception as e:
                sys.stderr.write(
                    f"ERROR: read_resource failed for URI {uri}: {e.__class__.__name__}: {e}\n"
                )
                return ""

        @self.server.list_prompts()
        async def list_prompts() -> list[Prompt]:
            """Forward list_prompts request to AgentDecompile backend with retry logic."""
            try:
                await self._ensure_backend_connected()
            except RuntimeError:
                return []

            async def _list_prompts_operation():
                return await asyncio.wait_for(
                    self.backend_session.list_prompts(),  # type: ignore
                    timeout=30.0,
                )

            try:
                result = await self._call_with_retry("list_prompts", _list_prompts_operation)
                if result is None:
                    return []
                return result.prompts
            except asyncio.TimeoutError:
                sys.stderr.write("ERROR: list_prompts timed out\n")
                return []
            except Exception as e:
                sys.stderr.write(
                    f"ERROR: list_prompts failed: {e.__class__.__name__}: {e}\n"
                )
                return []

    async def run(self):
        """
        Run the stdio bridge.

        Connects to AgentDecompile backend via StreamableHTTP, initializes the session,
        then exposes the MCP server via stdio transport.
        
        Features automatic reconnection on connection loss with exponential backoff.
        """
        sys.stderr.write(f"Connecting to AgentDecompile backend at {self.url}...\n")

        # Increased timeout for long-running operations (Ghidra operations can take time)
        timeout = 3600.0  # 1 hour for overall timeout (prevents premature disconnection)

        max_retries = 5
        retry_delay = 2.0

        for attempt in range(max_retries):
            try:
                async with streamablehttp_client(self.url, timeout=timeout) as (
                    read_stream,
                    write_stream,
                    get_session_id,
                ):
                    # Wrap read_stream to convert non-JSON messages to valid JSON
                    # This prevents JSON parsing errors while preserving all log messages
                    json_stream = JsonEnvelopeStream(read_stream)
                    self._current_json_stream = json_stream

                    # Enter the wrapper's context manager
                    async with json_stream:
                        async with ClientSession(json_stream, write_stream) as session:  # pyright: ignore[reportArgumentType]
                            self.backend_session = session

                            # Reset circuit breaker on successful connection
                            self._consecutive_failures = 0
                            self._circuit_open_until = 0.0

                            # Initialize backend session with timeout
                            sys.stderr.write(
                                "Initializing AgentDecompile backend session...\n"
                            )
                            try:
                                init_result = await asyncio.wait_for(
                                    session.initialize(), timeout=120.0
                                )
                                sys.stderr.write(
                                    f"Connected to {init_result.serverInfo.name} v{init_result.serverInfo.version}\n"
                                )
                            except asyncio.TimeoutError:
                                sys.stderr.write(
                                    "Timeout initializing backend session (>120s)\n"
                                )
                                if attempt < max_retries - 1:
                                    sys.stderr.write(
                                        f"Retrying in {retry_delay} seconds... (attempt {attempt + 1}/{max_retries})\n"
                                    )
                                    await asyncio.sleep(retry_delay)
                                    retry_delay = min(retry_delay * 2, 30.0)
                                    continue
                                raise

                            # Run MCP server with stdio transport
                            sys.stderr.write("Bridge ready - stdio transport active\n")
                            try:
                                async with stdio_server() as (stdio_read, stdio_write):
                                    await self.server.run(
                                        stdio_read,
                                        stdio_write,
                                        self.server.create_initialization_options(),
                                    )
                                # If we get here, the server ran successfully
                                break
                            except ClosedResourceError:
                                # Handle closed resource errors gracefully
                                # This happens when the client disconnects while a response is being sent
                                # It's a normal shutdown condition, not an error
                                sys.stderr.write("Client disconnected\n")
                                break
                            except BrokenResourceError:
                                # Handle broken resource errors gracefully
                                # Similar to ClosedResourceError - client disconnected
                                sys.stderr.write("Client connection broken - disconnecting\n")
                                break
                            except Exception as stdio_error:
                                # Check if this is an ExceptionGroup containing ClosedResourceError or BrokenResourceError
                                # ExceptionGroup is available in Python 3.11+
                                if hasattr(stdio_error, "exceptions") and isinstance(stdio_error, BaseException):
                                    try:
                                        if stdio_error.__class__.__name__ == "ExceptionGroup":
                                            exceptions = stdio_error.exceptions  # type: ignore[attr-defined]
                                            # Check if all exceptions in the group are connection-related
                                            all_connection = all(
                                                isinstance(exc, (ClosedResourceError, BrokenResourceError))
                                                or (_is_connection_error(exc) if isinstance(exc, Exception) else False)
                                                for exc in exceptions
                                            )
                                            if all_connection:
                                                sys.stderr.write("Client disconnected (ExceptionGroup)\n")
                                                break
                                    except (AttributeError, TypeError):
                                        pass
                                # If stdio server fails, check if backend connection is still alive
                                # and attempt to reconnect if needed
                                sys.stderr.write(
                                    f"Stdio server error: {type(stdio_error).__name__}: {stdio_error}\n"
                                )
                                # Check if this is a connection error that warrants retry
                                if isinstance(stdio_error, (ConnectionError, OSError)):
                                    if attempt < max_retries - 1:
                                        sys.stderr.write(
                                            f"Connection error in stdio bridge, retrying... (attempt {attempt + 1}/{max_retries})\n"
                                        )
                                        await asyncio.sleep(retry_delay)
                                        retry_delay = min(retry_delay * 2, 30.0)
                                        continue
                                # For other errors, re-raise to be handled by outer exception handler
                                raise

            except asyncio.TimeoutError as e:
                sys.stderr.write(
                    f"Timeout error (attempt {attempt + 1}/{max_retries}): {e}\n"
                )
                if attempt < max_retries - 1:
                    sys.stderr.write(f"Retrying in {retry_delay} seconds...\n")
                    await asyncio.sleep(retry_delay)
                    retry_delay = min(retry_delay * 2, 30.0)
                    continue
                raise
            except (ConnectionError, OSError) as e:
                sys.stderr.write(
                    f"Connection error (attempt {attempt + 1}/{max_retries}): {e}\n"
                )
                if attempt < max_retries - 1:
                    sys.stderr.write(f"Retrying in {retry_delay} seconds...\n")
                    await asyncio.sleep(retry_delay)
                    retry_delay = min(retry_delay * 2, 30.0)
                    continue
                raise
            except (BrokenResourceError, ClosedResourceError) as e:
                sys.stderr.write(
                    f"Resource error (attempt {attempt + 1}/{max_retries}): {type(e).__name__}: {e}\n"
                )
                if attempt < max_retries - 1:
                    sys.stderr.write(f"Retrying in {retry_delay} seconds...\n")
                    await asyncio.sleep(retry_delay)
                    retry_delay = min(retry_delay * 2, 30.0)
                    continue
                raise
            except Exception as e:
                # For other exceptions, log and re-raise immediately
                sys.stderr.write(f"Bridge error: {e.__class__.__name__}: {e}\n")
                import traceback

                traceback.print_exc(file=sys.stderr)
                raise
            finally:
                # Clean up backend session and json stream
                self.backend_session = None
                if self._current_json_stream:
                    try:
                        await self._current_json_stream.aclose()
                    except Exception:
                        pass  # Ignore errors during cleanup
                    self._current_json_stream = None
                if attempt == max_retries - 1:
                    sys.stderr.write("Bridge stopped\n")

    def stop(self):
        """Stop the bridge and cleanup resources."""
        # Clean up json stream
        if self._current_json_stream:
            try:
                # Note: aclose is async, but this is called from synchronous cleanup
                # The async context managers will handle the actual cleanup
                pass
            except Exception:
                pass
            self._current_json_stream = None
        pass
