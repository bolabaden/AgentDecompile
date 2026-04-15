"""Local headless PyGhidra backend for AgentDecompile CLI.

Provides ``LocalToolBackend``, an async context manager that runs tool calls
in-process via PyGhidra and ``ToolProviderManager`` — no MCP HTTP server or stdio
transport required.

Usage::

    async with LocalToolBackend(project_path="/tmp/my-proj") as backend:
        result = await backend.call_tool("list-functions", {"programPath": "mybinary"})

The returned ``dict`` has the same shape as ``RawMcpHttpBackend.call_tool()`` so all
existing CLI formatting/error-detection helpers work unchanged::

    {
        "content": [{"type": "text", "text": '{"functions": [...]}'}],
        "isError": False,
    }

PyGhidra is imported lazily (only inside ``initialize()``) so this module is safe
to import even when PyGhidra is not installed; it raises ``ImportError`` only when
``--local`` is actually used without PyGhidra available.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time

from contextvars import ContextVar
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mcp import types

    from agentdecompile_cli.context import PyGhidraContext, ProgramInfo
    from agentdecompile_cli.mcp_server.resource_providers import ResourceProviderManager
    from agentdecompile_cli.mcp_server.tool_providers import ToolProviderManager

logger = logging.getLogger(__name__)

_LOCAL_SESSION_ID = "local"


class LocalToolBackend:
    """In-process tool executor that uses PyGhidra + ToolProviderManager.

    Provides the same ``call_tool(name, arguments) -> dict`` interface as the
    HTTP-backed ``AgentDecompileMcpClient`` so CLI routing code handles both
    transparently.

    Args:
        project_path: Path to the Ghidra project directory (will be created if it
            does not exist).  Defaults to ``agentdecompile_projects`` relative to
            the current working directory, or to ``AGENT_DECOMPILE_PROJECT_PATH``
            env var when set.
        project_name: Name for the Ghidra project (default: ``"agentdecompile"``).
        input_paths: Optional list of binary paths to import into the project at
            initialisation time.
        force_analysis: Re-run auto-analysis even if the binary was already analysed.
        verbose: Log verbose PyGhidra output (JVM analysis messages).
    """

    def __init__(
        self,
        project_path: str | Path | None = None,
        project_name: str = "agentdecompile",
        input_paths: list[str | Path] | None = None,
        force_analysis: bool = False,
        verbose: bool = False,
    ) -> None:
        logger.debug("diag.enter %s", "local_backend.py:LocalToolBackend.__init__")
        # Resolve project path from arg > env > default
        if project_path is not None:
            self._project_path = Path(project_path)
        else:
            env_path = (os.environ.get("AGENT_DECOMPILE_PROJECT_PATH") or os.environ.get("AGENTDECOMPILE_PROJECT_PATH") or "").strip()
            if env_path:
                p = Path(env_path)
                # If AGENT_DECOMPILE_PROJECT_PATH is a .gpr file, use the parent directory
                if p.suffix.lower() == ".gpr":
                    self._project_path = p.parent
                    project_name = p.stem
                else:
                    self._project_path = p
            else:
                self._project_path = Path("agentdecompile_projects")

        self._project_name = project_name
        self._input_paths: list[Path] = [Path(p) for p in (input_paths or [])]
        self._force_analysis = force_analysis
        self._verbose = verbose

        self._initialized: bool = False
        self._context: PyGhidraContext | None = None
        self._tool_manager: ToolProviderManager | None = None
        self._resource_manager: ResourceProviderManager | None = None

    # ------------------------------------------------------------------
    # Context manager interface (matches AgentDecompileMcpClient)
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "LocalToolBackend":
        logger.debug("diag.enter %s", "local_backend.py:LocalToolBackend.__aenter__")
        await self.initialize()
        return self

    async def __aexit__(self, *_: Any) -> None:
        logger.debug("diag.enter %s", "local_backend.py:LocalToolBackend.__aexit__")
        self.close()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(self) -> None:
        """Start PyGhidra, open/create the Ghidra project, and register all tool providers.

        Safe to call multiple times; subsequent calls are no-ops.
        """
        logger.debug("diag.enter %s", "local_backend.py:LocalToolBackend.initialize")
        if self._initialized:
            return

        # Run the blocking initialisation in a thread so it doesn't block the event loop.
        await asyncio.get_event_loop().run_in_executor(None, self._do_initialize)

    def _do_initialize(self) -> None:
        """Blocking initialisation: PyGhidra start + project open + provider registration."""
        logger.debug("diag.enter %s", "local_backend.py:LocalToolBackend._do_initialize")
        _t0 = time.monotonic()

        # --- PyGhidra ---
        try:
            import pyghidra  # pyright: ignore[reportMissingImports]
        except ImportError as exc:
            raise ImportError(
                "PyGhidra is not installed.  Install with: pip install 'agentdecompile[local]'\n"
                "Or set GHIDRA_INSTALL_DIR and install from the bundled pypkg:\n"
                "  pip install $GHIDRA_INSTALL_DIR/Ghidra/Features/PyGhidra/pypkg"
            ) from exc

        ghidra_install = os.environ.get("GHIDRA_INSTALL_DIR", "").strip()
        if not ghidra_install:
            raise EnvironmentError(
                "GHIDRA_INSTALL_DIR is not set.  Point it to your Ghidra installation directory, e.g.:\n"
                "  export GHIDRA_INSTALL_DIR=/opt/ghidra-install/ghidra_12.0.4_PUBLIC"
            )

        logger.info("local_backend init pyghidra start project_path=%s project_name=%s", self._project_path, self._project_name)
        sys.stderr.write("Initializing PyGhidra (local mode)...\n")
        pyghidra.start(verbose=self._verbose)
        sys.stderr.write("PyGhidra initialized.\n")

        # --- Ghidra project ---
        from agentdecompile_cli.context import PyGhidraContext  # pyright: ignore[reportMissingImports]

        self._project_path.mkdir(parents=True, exist_ok=True)
        self._context = PyGhidraContext(
            project_name=self._project_name,
            project_path=str(self._project_path),
            force_analysis=self._force_analysis,
            verbose_analysis=self._verbose,
        )

        # --- Import requested input binaries ---
        for binary_path in self._input_paths:
            if not binary_path.exists():
                logger.warning("local_backend input_path_missing path=%s", binary_path)
                sys.stderr.write(f"Warning: binary path does not exist: {binary_path}\n")
                continue
            try:
                sys.stderr.write(f"Importing binary: {binary_path}\n")
                self._context.import_binary(str(binary_path))
                sys.stderr.write(f"Imported: {binary_path.name}\n")
            except Exception as exc:
                logger.warning("local_backend import_failed path=%s exc=%s", binary_path, exc)
                sys.stderr.write(f"Warning: import failed for {binary_path}: {exc}\n")

        # --- Tool provider manager ---
        from agentdecompile_cli.mcp_server.resource_providers import ResourceProviderManager  # pyright: ignore[reportMissingImports]
        from agentdecompile_cli.mcp_server.tool_providers import ToolProviderManager  # pyright: ignore[reportMissingImports]

        self._tool_manager = ToolProviderManager()
        self._tool_manager.register_all_providers()
        self._resource_manager = ResourceProviderManager()
        self._resource_manager.set_tool_provider_manager(self._tool_manager)

        # Seed manager + session with already-open programs from the project
        from agentdecompile_cli.mcp_server.session_context import SESSION_CONTEXTS  # pyright: ignore[reportMissingImports]

        session = SESSION_CONTEXTS.get_or_create(_LOCAL_SESSION_ID)
        if self._context.programs:
            first_key: str | None = None
            for key, prog_info in self._context.programs.items():
                # set_active_program_info stores the program and sets the active key
                if first_key is None:
                    SESSION_CONTEXTS.set_active_program_info(_LOCAL_SESSION_ID, key, prog_info)
                    first_key = key
                else:
                    # For subsequent programs, add directly to open_programs without
                    # overwriting the active key (access session via get_or_create).
                    ctx = SESSION_CONTEXTS.get_or_create(_LOCAL_SESSION_ID)
                    ctx.open_programs[key] = prog_info

            # Set manager's program_info to the first available program
            first_prog_info = next(iter(self._context.programs.values()))
            self._tool_manager.set_program_info(first_prog_info)
            self._resource_manager.set_program_info(first_prog_info)

        # Store GhidraProject reference so providers can checkout/checkin
        if hasattr(self._context, "project") and self._context.project is not None:
            self._tool_manager.set_ghidra_project(self._context.project)

        self._initialized = True
        elapsed = time.monotonic() - _t0
        sys.stderr.write(f"Local backend ready in {elapsed:.1f}s. Session: {_LOCAL_SESSION_ID!r}\n")
        logger.info("local_backend_init_done elapsed_s=%.2f programs=%d", elapsed, len(self._context.programs))

    def close(self) -> None:
        """Close the Ghidra project context (save changes)."""
        logger.debug("diag.enter %s", "local_backend.py:LocalToolBackend.close")
        if self._context is not None:
            try:
                self._context.close()
            except Exception as exc:
                logger.warning("local_backend close_error exc=%s", exc)
        self._initialized = False

    # ------------------------------------------------------------------
    # Core tool execution
    # ------------------------------------------------------------------

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Execute a tool in-process via ToolProviderManager.

        Returns a dict matching the ``RawMcpHttpBackend.call_tool()`` shape::

            {"content": [{"type": "text", "text": "..."}], "isError": False}

        This matches what ``_call_raw`` and all CLI formatting helpers expect.
        """
        logger.debug("diag.enter %s", "local_backend.py:LocalToolBackend.call_tool")
        if not self._initialized:
            await self.initialize()

        if self._tool_manager is None:
            return _error_response("Local backend not initialized (tool_manager is None)")

        from agentdecompile_cli.mcp_server.session_context import CURRENT_MCP_SESSION_ID  # pyright: ignore[reportMissingImports]

        # Set session context var so providers that call get_current_mcp_session_id()
        # resolve to our fixed "local" session.
        token = CURRENT_MCP_SESSION_ID.set(_LOCAL_SESSION_ID)
        try:
            result: list[types.TextContent] = await self._tool_manager.call_tool(name, dict(arguments or {}))
        except Exception as exc:
            logger.warning("local_backend call_tool_exc tool=%s exc=%s", name, exc)
            return _error_response(f"Tool '{name}' raised an exception: {exc}")
        finally:
            CURRENT_MCP_SESSION_ID.reset(token)

        return _text_content_to_response(result)

    async def list_tools(self) -> list[dict[str, Any]]:
        """Return a list of available tools (same keys as MCP tools/list response)."""
        logger.debug("diag.enter %s", "local_backend.py:LocalToolBackend.list_tools")
        if not self._initialized:
            await self.initialize()

        if self._tool_manager is None:
            return []

        from mcp import types as mcp_types  # pyright: ignore[reportMissingImports]

        tools: list[mcp_types.Tool] = self._tool_manager.list_tools()
        return [
            {
                "name": t.name,
                "description": t.description or "",
                "inputSchema": t.inputSchema or {},
            }
            for t in tools
        ]

    async def list_prompts(self) -> list[dict[str, Any]]:
        """Return available prompts in a browser-friendly shape."""
        logger.debug("diag.enter %s", "local_backend.py:LocalToolBackend.list_prompts")
        if not self._initialized:
            await self.initialize()

        from agentdecompile_cli.mcp_server import prompt_providers  # pyright: ignore[reportMissingImports]

        prompts = prompt_providers.list_prompts()
        return [
            {
                "name": prompt.name,
                "description": prompt.description or "",
                "arguments": [
                    {
                        "name": argument.name,
                        "description": argument.description or "",
                        "required": bool(argument.required),
                    }
                    for argument in (prompt.arguments or [])
                ],
            }
            for prompt in prompts
        ]

    async def list_resources(self) -> list[dict[str, Any]]:
        """Return available resources in a browser-friendly shape."""
        logger.debug("diag.enter %s", "local_backend.py:LocalToolBackend.list_resources")
        if not self._initialized:
            await self.initialize()

        if self._resource_manager is None:
            return []

        resources = self._resource_manager.list_resources()
        return [
            {
                "name": getattr(resource, "name", "") or getattr(resource, "uri", ""),
                "uri": str(getattr(resource, "uri", "")),
                "description": getattr(resource, "description", "") or "",
                "mimeType": getattr(resource, "mimeType", None),
            }
            for resource in resources
        ]

    async def read_resource(self, uri: str) -> dict[str, Any]:
        """Read an MCP resource and preserve both raw and parsed content when possible."""
        logger.debug("diag.enter %s", "local_backend.py:LocalToolBackend.read_resource")
        if not self._initialized:
            await self.initialize()

        if self._resource_manager is None:
            return {"uri": uri, "raw": "", "parsed": None}

        from agentdecompile_cli.mcp_server.session_context import CURRENT_MCP_SESSION_ID  # pyright: ignore[reportMissingImports]

        token = CURRENT_MCP_SESSION_ID.set(_LOCAL_SESSION_ID)
        try:
            raw = await self._resource_manager.read_resource(uri)
        finally:
            CURRENT_MCP_SESSION_ID.reset(token)

        parsed: Any = None
        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = None

        return {"uri": uri, "raw": raw, "parsed": parsed}

    # ------------------------------------------------------------------
    # Session / program helpers
    # ------------------------------------------------------------------

    def get_session_id(self) -> str:
        """Return the fixed local session identifier."""
        logger.debug("diag.enter %s", "local_backend.py:LocalToolBackend.get_session_id")
        return _LOCAL_SESSION_ID

    def get_open_programs(self) -> dict[str, Any]:
        """Return the currently open programs in the local session."""
        logger.debug("diag.enter %s", "local_backend.py:LocalToolBackend.get_open_programs")
        from agentdecompile_cli.mcp_server.session_context import SESSION_CONTEXTS  # pyright: ignore[reportMissingImports]

        ctx = SESSION_CONTEXTS.get_or_create(_LOCAL_SESSION_ID)
        return {k: {"name": v.name or k} for k, v in (ctx.open_programs or {}).items()}


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _text_content_to_response(result: list[Any]) -> dict[str, Any]:
    """Convert a list[TextContent] from ToolProviderManager into the HTTP backend dict shape."""
    logger.debug("diag.enter %s", "local_backend.py:_text_content_to_response")
    content: list[dict[str, Any]] = []
    is_error = False
    for item in result or []:
        text = item.text if isinstance(item, types.TextContent) else None
        item_type = item.type if isinstance(item, types.TextContent) else "text"
        if text is not None:
            content.append({"type": str(item_type), "text": str(text)})
            # Check if the tool returned an error payload
            try:
                parsed = json.loads(text)
                if isinstance(parsed, dict) and parsed.get("success") is False:
                    is_error = True
            except (json.JSONDecodeError, TypeError):
                pass
    return {"content": content, "isError": is_error}


def _error_response(message: str) -> dict[str, Any]:
    """Build an error response dict matching the HTTP backend shape."""
    logger.debug("diag.enter %s", "local_backend.py:_error_response")
    return {
        "content": [{"type": "text", "text": json.dumps({"success": False, "error": message})}],
        "isError": True,
    }
