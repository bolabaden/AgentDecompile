"""Project Tool Provider - open, list-project-files, import/export, checkout/checkin, etc.

Handles project and program lifecycle: open (local or shared Ghidra server),
analyze-program, list-project-files, import-binary, delete/remove program binary,
checkout-program, checkin-program, checkout-status, sync-project. Also export and
open-in-code-browser. Session state (open programs, active program) is stored in
SessionContext keyed by MCP session ID; project_handle may be a local ProjectManager
or a shared-server adapter.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shlex
import socket
import subprocess
import sys
import time

from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from mcp import types

from agentdecompile_cli.app_logger import basename_hint, redact_session_id
from agentdecompile_cli.mcp_server.domain_folder_listing import (
    list_project_tree_from_ghidra,
    walk_domain_folder_tree,
)
from agentdecompile_cli.mcp_server.repository_adapter_listing import (
    list_repository_adapter_items,
    repository_adapter_folder_candidates,
)
from agentdecompile_cli.mcp_server.session_context import (
    SESSION_CONTEXTS,
    SessionContext,
    get_current_mcp_session_id,
    is_shared_server_handle,
)
from agentdecompile_cli.mcp_server.tool_providers import (
    ActionableError,
    ToolProvider,
    create_success_response,
    filter_recommendations,
    n,
    recommend_tool,
)
from agentdecompile_cli.registry import Tool

if TYPE_CHECKING:
    from ghidra.app.decompiler import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        DecompInterface as GhidraDecompInterface,
    )
    from ghidra.base.project import GhidraProject  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
    from ghidra.framework.client import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        RepositoryAdapter as GhidraRepositoryAdapter,
    )
    from ghidra.framework.model import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        DomainFile as GhidraDomainFile,
        DomainFolder as GhidraDomainFolder,
        DomainObject as GhidraDomainObject,
        ProjectData as GhidraProjectData,
    )
    from ghidra.framework.remote import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]  # noqa: F401
        RepositoryItem as GhidraRepositoryItem,
    )
    from ghidra.framework.store import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]  # noqa: F401
        CheckoutType as GhidraCheckoutType,
    )
    from ghidra.program.model.listing import (  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
        Function as GhidraFunction,
        FunctionManager as GhidraFunctionManager,
        Program as GhidraProgram,
    )
    from ghidra.util.task import TaskMonitor as GhidraTaskMonitor  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
    from jpype import JArray

    from agentdecompile_cli.context import ProgramInfo


logger = logging.getLogger(__name__)


def _shared_connection_context(
    *,
    stage: str,
    server_host: str,
    server_port: int,
    auth_provided: bool,
    server_username: str | None = None,
    repository_name: str | None = None,
    requested_path: str | None = None,
    server_reachable: bool | None = None,
    wrapper_error: str | None = None,
    adapter_error: str | None = None,
    adapter_error_type: str | None = None,
) -> dict[str, Any]:
    """Build a structured dict for shared-server connection errors and diagnostics (included in tool response)."""
    logger.debug("diag.enter %s", "mcp_server/providers/project.py:_shared_connection_context")
    context: dict[str, Any] = {
        "mode": "shared-server",
        "connectionStage": stage,
        "serverHost": server_host,
        "serverPort": server_port,
        "authProvided": auth_provided,
    }
    if server_username:
        context["serverUsername"] = server_username
    if repository_name:
        context["repository"] = repository_name
    if requested_path:
        context["requestedPath"] = requested_path
    if server_reachable is not None:
        context["serverReachable"] = server_reachable
    if wrapper_error:
        context["wrapperError"] = wrapper_error
    if adapter_error:
        context["adapterError"] = adapter_error
    if adapter_error_type:
        context["adapterErrorType"] = adapter_error_type
    return context


def _shared_adapter_error(server_adapter: GhidraRepositoryAdapter) -> tuple[str | None, str | None]:
    logger.debug("diag.enter %s", "mcp_server/providers/project.py:_shared_adapter_error")
    getter = getattr(server_adapter, "getLastConnectError", None)
    if getter is None:
        return None, None
    try:
        last_error = getter()
    except Exception:
        return None, None
    if last_error is None:
        return None, None
    return type(last_error).__name__, str(last_error)


def _shared_auth_failed(adapter_error_type: str | None, adapter_error: str | None) -> bool:
    logger.debug("diag.enter %s", "mcp_server/providers/project.py:_shared_auth_failed")
    combined = " ".join(part for part in (adapter_error_type, adapter_error) if part).lower()
    return any(
        token in combined
        for token in (
            "failedloginexception",
            "authentication failed",
            "login failed",
            "invalid credentials",
            "not authorized",
            "permission denied",
        )
    )


class ProjectToolProvider(ToolProvider):
    HANDLERS: ClassVar[dict[str, str]] = {
        "open": "_handle_open_project",
        "listprojectfiles": "_handle_list",
        "syncproject": "_handle_sync_project",
        "managefiles": "_handle_manage",
        "connectsharedproject": "_handle_connect_shared_project",
        "removeprogrambinary": "_handle_remove_program_binary",
        "getcurrentaddress": "_handle_get_current_address",
        "getcurrentfunction": "_handle_get_current_function",
        "getcurrentprogram": "_handle_get_current_program",
        "openprogramincodebrowser": "_handle_gui_unsupported",
        "openallprogramsincodebrowser": "_handle_gui_unsupported",
        "svradmin": "_handle_svr_admin",
        "listfallbackprojects": "_handle_list_fallback_projects",
        "reintegratefallbackprojects": "_handle_reintegrate_fallback_projects",
    }

    def list_tools(self) -> list[types.Tool]:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider.list_tools")
        return [
            types.Tool(
                name=Tool.OPEN.value,
                description="Open a local .gpr project or connect to a shared Ghidra repository server. Use import-binary for local binaries.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": ".gpr path, project directory, or repository name."},
                        "shared": {"type": "boolean", "default": False, "description": "Force shared Ghidra repository mode for this open request."},
                        "serverHost": {"type": "string", "description": "Ghidra server host (shared project mode)."},
                        "serverPort": {"type": "integer", "description": "Ghidra server port (default: 13100)."},
                        "serverUsername": {"type": "string", "description": "Repository authentication username."},
                        "serverPassword": {"type": "string", "description": "Repository authentication password."},
                        "repositoryName": {"type": "string", "description": "Shared repository name (optional, auto-detected from server)."},
                        "analyzeAfterImport": {"type": "boolean", "default": True, "description": "Run analysis after import (optional, defaults to true)."},
                        "openAllPrograms": {"type": "boolean", "default": False, "description": "Open all programs in project."},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name=Tool.SVR_ADMIN.value,
                description="Run Ghidra server administration commands via the bundled svrAdmin script with full argument passthrough.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "args": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Raw argv tokens forwarded directly to svrAdmin.",
                        },
                        "command": {
                            "type": "string",
                            "description": "Optional command string split into argv and forwarded to svrAdmin.",
                        },
                        "timeoutSeconds": {
                            "type": "integer",
                            "default": 120,
                            "description": "Timeout in seconds for the svrAdmin subprocess.",
                        },
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="connect-shared-project",
                description="Connect to a shared Ghidra repository server and list available binaries.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "serverHost": {"type": "string", "description": "Ghidra server host address."},
                        "serverPort": {"type": "integer", "description": "Ghidra server port (default: 13100)."},
                        "serverUsername": {"type": "string", "description": "Repository authentication username."},
                        "serverPassword": {"type": "string", "description": "Repository authentication password."},
                        "path": {"type": "string", "description": "Repository name or program path within repository."},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name=Tool.LIST_PROJECT_FILES.value,
                description="List project files.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "Program path."},
                        "binary": {"type": "string", "description": "Program path."},
                        "folder": {"type": "string", "default": "/", "description": "Project folder."},
                        "path": {"type": "string", "description": "Filesystem path (non-project mode)."},
                        "maxResults": {
                            "type": "integer",
                            "default": 100,
                            "description": "Number of project file results to return. Typical values are 100–500.",
                        },
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name=Tool.SYNC_PROJECT.value,
                description="Sync with local or shared repository. Supports pull, push, and bidirectional modes between local projects and shared Ghidra server repositories.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "mode": {
                            "type": "string",
                            "description": "Sync direction.",
                            "enum": ["pull", "push", "bidirectional"],
                            "default": "pull",
                        },
                        "path": {"type": "string", "default": "/", "description": "Path to sync."},
                        "sourcePath": {"type": "string", "description": "Source path."},
                        "newPath": {"type": "string", "default": "/", "description": "Target path."},
                        "destinationPath": {"type": "string", "description": "Destination path."},
                        "destinationFolder": {"type": "string", "description": "Destination folder."},
                        "recursive": {"type": "boolean", "default": True, "description": "Include subfolders."},
                        "maxResults": {
                            "type": "integer",
                            "default": 100000,
                            "description": "Total number of items to return in a full listing. Default covers entire large projects; do not reduce this unless the user explicitly wants a partial list.",
                        },
                        "force": {"type": "boolean", "default": False, "description": "Overwrite conflicts."},
                        "dryRun": {"type": "boolean", "default": False, "description": "Simulate only."},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name=Tool.MANAGE_FILES.value,
                description="Manage project files and open programs.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "mode": {
                            "type": "string",
                            "description": "Operation mode (aliases: action, operation).",
                            "enum": [
                                "open",
                                "change-processor",
                                "rename",
                                "delete",
                                "move",
                                "list",
                                "import",
                                "export",
                                "download-shared",
                                "pull-shared",
                                "push-shared",
                                "sync-shared",
                                "checkout",
                                "uncheckout",
                                "unhijack",
                            ],
                        },
                        "filePath": {"type": "string", "description": "Target file."},
                        "path": {"type": "string", "description": "Target file or program path."},
                        "sourcePath": {"type": "string", "description": "Source path."},
                        "programPath": {"type": "string", "description": "Program path."},
                        "extensions": {"type": "array", "items": {"type": "string"}, "description": "File extensions filter (for mode=open)."},
                        "processor": {"type": "string", "description": "Processor."},
                        "languageId": {"type": "string", "description": "Language ID."},
                        "compilerSpecId": {"type": "string", "description": "Compiler spec ID."},
                        "endian": {"type": "string", "description": "Endianness."},
                        "syncDirection": {
                            "type": "string",
                            "description": "Sync direction.",
                            "enum": ["pull", "push", "bidirectional"],
                        },
                        "newPath": {"type": "string", "description": "New path."},
                        "destinationPath": {"type": "string", "description": "Destination path."},
                        "destinationFolder": {"type": "string", "description": "Destination folder."},
                        "newName": {"type": "string", "description": "New name."},
                        "content": {"type": "string", "description": "File content."},
                        "encoding": {"type": "string", "default": "utf-8", "description": "Text encoding."},
                        "createParents": {"type": "boolean", "default": True, "description": "Create missing parent folders."},
                        "keep": {"type": "boolean", "default": False, "description": "Keep original file."},
                        "force": {"type": "boolean", "default": False, "description": "Force overwrite."},
                        "exclusive": {"type": "boolean", "default": False, "description": "Exclusive checkout."},
                        "recursive": {"type": "boolean", "default": False, "description": "Recursive mode."},
                        "dryRun": {"type": "boolean", "default": False, "description": "Simulate only."},
                        "maxResults": {
                            "type": "integer",
                            "default": 200,
                            "description": "Number of results to return. Typical values are 100–500.",
                        },
                        "maxDepth": {"type": "integer", "default": 16, "description": "Max depth."},
                        "analyzeAfterImport": {"type": "boolean", "default": True, "description": "Run analysis after import (optional, defaults to true)."},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name=Tool.REMOVE_PROGRAM_BINARY.value,
                description="Remove a program from the current Ghidra project (shared repository or local project). This uses Ghidra's DomainFile API and does not delete source binaries from the host filesystem.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "Path or name of the active program to remove (e.g. /K1/swkotor.exe or test_x86_64)."},
                        "confirm": {"type": "boolean", "default": False, "description": "Must be true to confirm removal."},
                    },
                    "required": ["confirm"],
                },
            ),
            types.Tool(
                name="list-open-programs",
                description="List open programs (GUI/headless compatible)",
                inputSchema={"type": "object", "properties": {}, "required": []},
            ),
            types.Tool(
                name=Tool.GET_CURRENT_ADDRESS.value,
                description="Get current address (GUI-only, headless-safe)",
                inputSchema={"type": "object", "properties": {}, "required": []},
            ),
            types.Tool(
                name=Tool.GET_CURRENT_FUNCTION.value,
                description="Get current function (GUI-only, headless-safe)",
                inputSchema={"type": "object", "properties": {}, "required": []},
            ),
            types.Tool(
                name=Tool.OPEN_PROGRAM_IN_CODE_BROWSER.value,
                description="Open program in Code Browser (GUI-only)",
                inputSchema={"type": "object", "properties": {"programPath": {"type": "string"}}, "required": []},
            ),
            types.Tool(
                name=Tool.GET_CURRENT_PROGRAM.value,
                description="Retrieve metadata for the currently active program, including name, path, language, compiler, and analysis status.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "Program path to verify (uses current if omitted)."},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name=Tool.LIST_FALLBACK_PROJECTS.value,
                description=(
                    "List temporary fallback projects that were created when the original project was locked. "
                    "Shows reintegration status, creation time, and program count for each fallback. "
                    "Use reintegrate-fallback-projects to merge changes back into the original."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "projectsDir": {
                            "type": "string",
                            "description": "Override the projects directory (auto-derived from current project if omitted).",
                        },
                        "originalProjectName": {
                            "type": "string",
                            "description": "Filter by original project name (default: current project).",
                        },
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name=Tool.REINTEGRATE_FALLBACK_PROJECTS.value,
                description=(
                    "Merge changes from fallback projects back into the original project. "
                    "Use this after the original project unlocks to restore programs and analysis "
                    "that were added or modified during the fallback session(s). "
                    "Supports overwrite, skip, and new-only merge modes. Use dryRun=true to preview."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "projectsDir": {
                            "type": "string",
                            "description": "Override the projects directory (auto-derived from current project if omitted).",
                        },
                        "originalProjectName": {
                            "type": "string",
                            "description": "Original project name to merge into (default: current project).",
                        },
                        "fallbackProjectNames": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Specific fallback project names to reintegrate (default: all unintegrated fallbacks).",
                        },
                        "mergeMode": {
                            "type": "string",
                            "enum": ["overwrite_existing", "skip_existing", "new_only"],
                            "default": "overwrite_existing",
                            "description": (
                                "overwrite_existing (default): copy all domain files, replacing existing程序 in the original; "
                                "skip_existing: copy only files not already in the original; "
                                "new_only: alias for skip_existing."
                            ),
                        },
                        "deleteAfterMerge": {
                            "type": "boolean",
                            "default": False,
                            "description": "Delete the fallback project files after successful reintegration.",
                        },
                        "dryRun": {
                            "type": "boolean",
                            "default": False,
                            "description": "Simulate only — report what would be merged without changing anything.",
                        },
                    },
                    "required": [],
                },
            ),
        ]

    @staticmethod
    def _is_foreign_os_path(path: str) -> bool:
        """Return True when *path* looks like a Windows absolute path on a non-Windows host (or vice-versa).

        The main case: an MCP client running on Windows sends ``C:/foo/bar``
        to a Linux backend where ``Path.resolve()`` would produce nonsense
        like ``/ghidra/C:/foo/bar``.
        """
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._is_foreign_os_path")
        if sys.platform != "win32" and re.match(r"^[A-Za-z]:[/\\]", path):
            return True
        return False

    def _get_shared_server_host(self) -> str:
        """Return a shared Ghidra server host from env vars or the current auth context."""
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._get_shared_server_host")
        env_host = os.getenv(
            "AGENT_DECOMPILE_GHIDRA_SERVER_HOST",
            os.getenv(
                "AGENTDECOMPILE_HTTP_GHIDRA_SERVER_HOST",
                os.getenv("AGENT_DECOMPILE_SERVER_HOST", os.getenv("AGENTDECOMPILE_SERVER_HOST", "")),
            ),
        ).strip()
        if env_host:
            return env_host
        # Fall back to the per-request auth context (set by AuthMiddleware from
        # X-Ghidra-Server-Host / X-Agent-Server-* HTTP headers).
        try:
            from agentdecompile_cli.mcp_server.auth import get_current_auth_context  # noqa: PLC0415

            _auth_ctx = get_current_auth_context()
            if _auth_ctx is not None and _auth_ctx.server_host:
                return _auth_ctx.server_host
        except Exception:
            pass
        return ""

    def _build_shared_args(self, args: dict[str, Any], env_host: str) -> dict[str, Any]:
        """Build shared-server connection args from env vars / auth context."""
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._build_shared_args")
        shared_args = dict(args)
        shared_args["serverhost"] = env_host
        shared_args.setdefault(
            "serverport",
            os.getenv(
                "AGENT_DECOMPILE_GHIDRA_SERVER_PORT",
                os.getenv(
                    "AGENTDECOMPILE_HTTP_GHIDRA_SERVER_PORT",
                    os.getenv("AGENT_DECOMPILE_SERVER_PORT", os.getenv("AGENTDECOMPILE_SERVER_PORT", "13100")),
                ),
            ).strip()
            or "13100",
        )
        shared_args.setdefault(
            "serverusername",
            os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME", os.getenv("AGENT_DECOMPILE_SERVER_USERNAME", os.getenv("AGENTDECOMPILE_SERVER_USERNAME", ""))).strip(),
        )
        shared_args.setdefault(
            "serverpassword",
            os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD", os.getenv("AGENT_DECOMPILE_SERVER_PASSWORD", os.getenv("AGENTDECOMPILE_SERVER_PASSWORD", ""))).strip(),
        )
        shared_args.setdefault(
            "path",
            os.getenv(
                "AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY",
                os.getenv(
                    "AGENTDECOMPILE_HTTP_GHIDRA_SERVER_REPOSITORY",
                    os.getenv("AGENTDECOMPILE_GHIDRA_SERVER_REPOSITORY", os.getenv("AGENT_DECOMPILE_REPOSITORY", os.getenv("AGENTDECOMPILE_REPOSITORY", ""))),
                ),
            ).strip(),
        )
        return shared_args

    def _infer_requested_shared_repository_name(self, args: dict[str, Any], path: str) -> str | None:
        """Infer the shared repository name from explicit args or a repository-like path."""
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._infer_requested_shared_repository_name")
        requested_repository = self._get_str(args, "repositoryname", "path")
        if requested_repository and requested_repository.strip():
            return requested_repository.strip().strip("/")

        if not path or not path.strip():
            return None

        normalized_path = path.strip().rstrip("/")
        if not normalized_path or "/" in normalized_path:
            return None

        return normalized_path

    def _ensure_shared_repository_exists(
        self,
        *,
        server_adapter: GhidraRepositoryAdapter,
        repository_names: list[str],
        requested_repository: str | None,
        auth_provided: bool,
        server_host: str,
        server_port: int,
    ) -> tuple[list[str], bool]:
        """Ensure the requested shared repository exists, creating it when needed."""
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._ensure_shared_repository_exists")
        if requested_repository and requested_repository in repository_names:
            return repository_names, False

        if requested_repository is None:
            if repository_names:
                return repository_names, False
            raise ActionableError(
                f"No repositories found on {server_host}:{server_port}",
                context={"mode": "shared-server", "serverHost": server_host, "serverPort": server_port},
                next_steps=[
                    "Confirm the account has at least one visible repository on the server.",
                    "Retry with a repository name in `path` or `repositoryName` once access is granted.",
                ],
            )

        if not auth_provided:
            raise ActionableError(
                f"Shared repository '{requested_repository}' was not found on {server_host}:{server_port}",
                context={
                    "mode": "shared-server",
                    "serverHost": server_host,
                    "serverPort": server_port,
                    "repository": requested_repository,
                    "authProvided": auth_provided,
                },
                next_steps=[
                    "Provide `serverUsername` and `serverPassword` so the backend can create the repository.",
                    "Or create the repository manually, then retry `open`.",
                ],
            )

        try:
            logger.info("[connect-shared-project] Creating missing repository %r", requested_repository)
            created_repository = server_adapter.createRepository(requested_repository)
            if created_repository is None and server_adapter.getRepository(requested_repository) is None:
                raise RuntimeError(f"Repository server returned None for '{requested_repository}'")
        except Exception as exc:
            if server_adapter.getRepository(requested_repository) is None:
                raise ActionableError(
                    f"Shared repository '{requested_repository}' was not found on {server_host}:{server_port}, and automatic creation failed: {exc}",
                    context={
                        "mode": "shared-server",
                        "serverHost": server_host,
                        "serverPort": server_port,
                        "repository": requested_repository,
                    },
                    next_steps=[
                        "Verify the user is allowed to create shared repositories on this Ghidra server.",
                        "Create the repository manually or retry with a user that has repository creation rights.",
                    ],
                ) from exc

        if requested_repository not in repository_names:
            repository_names = [*repository_names, requested_repository]
        return repository_names, True

    async def _handle_open_project(self, args: dict[str, Any]) -> list[types.TextContent]:
        """Unified open dispatcher: handles local binaries, .gpr projects, AND shared servers.

        Routing logic:
        1. If `shared=true` or serverHost is explicitly provided → shared server mode
        2. If no explicit shared flag/serverHost but shared server is discoverable (env vars OR auth
           context from HTTP headers) and no local path given → shared server mode
        3. Otherwise → local mode (binary import, .gpr project, directory)
        """
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._handle_open_project")
        server_host: str | None = self._get_str(args, "serverhost")
        shared_mode_requested: bool = self._get_bool(args, "shared", default=False)
        path: str | None = self._get_str(args, "path", "programpath", "filepath")
        logger.info(
            "[open] dispatcher: shared=%s, server_host=%r, path=%r, raw_args_keys=%s",
            shared_mode_requested,
            server_host,
            path,
            list(args.keys()) if isinstance(args, dict) else "N/A",
        )

        # Explicit shared server mode
        if shared_mode_requested or server_host:
            if shared_mode_requested and not server_host:
                env_host = self._get_shared_server_host()
                if env_host:
                    logger.info("[open] shared=true with implicit env/auth host %r", env_host)
                    return await self._handle_connect_shared_project(self._build_shared_args(args, env_host))
            logger.info(
                "[open] ROUTE: explicit shared server (shared=%s, serverHost in args=%s)",
                shared_mode_requested,
                bool(server_host),
            )
            return await self._handle_connect_shared_project(args)

        # Auto-detect shared server from environment variables **or** auth context
        # (AuthMiddleware populates auth context from X-Ghidra-Server-Host and
        # related HTTP headers sent by remote MCP clients).
        if not server_host:
            env_host = self._get_shared_server_host()
            logger.info("[open] env_host=%r (from _get_shared_server_host)", env_host)
            if env_host:
                # If no path or path doesn't exist locally, try shared mode
                if not path:
                    # No path at all — connect to shared server and list programs
                    logger.info("[open] ROUTE: shared server (no path, env_host set)")
                    shared_args = self._build_shared_args(args, env_host)
                    repo = os.getenv(
                        "AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY",
                        os.getenv(
                            "AGENTDECOMPILE_HTTP_GHIDRA_SERVER_REPOSITORY",
                            os.getenv("AGENTDECOMPILE_GHIDRA_SERVER_REPOSITORY", ""),
                        ),
                    ).strip()
                    if repo and "path" not in args:
                        shared_args["path"] = repo
                        logger.info("[open] Injecting repo=%r from env", repo)
                    return await self._handle_connect_shared_project(shared_args)

                # Path is given — check if it's a local file/dir that exists.
                # Detect Windows-style absolute paths (e.g. "C:/foo") on Linux;
                # Path.resolve() would mangle them into "/cwd/C:/foo".
                if self._is_foreign_os_path(path):
                    # Certainly not a local path — route to shared mode.
                    # Drop the foreign path; let _handle_connect_shared_project
                    # pick up the repository from auth context instead.
                    logger.info("[open] ROUTE: shared server (foreign OS path detected)")
                    shared_args = self._build_shared_args(args, env_host)
                    shared_args.pop("path", None)
                    shared_args.pop("programpath", None)
                    shared_args.pop("filepath", None)
                    return await self._handle_connect_shared_project(shared_args)

                resolved_path = Path(path).expanduser().resolve()
                if not resolved_path.exists():
                    # Path doesn't exist locally → try shared mode with this as the program path
                    logger.info("[open] ROUTE: shared server (path %r doesn't exist locally)", resolved_path)
                    shared_args = self._build_shared_args(args, env_host)
                    return await self._handle_connect_shared_project(shared_args)

        logger.info("[open] ROUTE: local mode (fallthrough)")
        return await self._handle_open(args)

    async def _handle_svr_admin(self, args: dict[str, Any]) -> list[types.TextContent]:
        """Execute Ghidra repository server administration commands via svrAdmin."""
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._handle_svr_admin")
        ghidra_install_dir: str = os.getenv("GHIDRA_INSTALL_DIR", "").strip()
        if not ghidra_install_dir:
            raise ActionableError(
                "GHIDRA_INSTALL_DIR is required for svr-admin.",
                context={"action": "svr-admin", "state": "missing-ghidra-install-dir"},
                next_steps=[
                    "Set GHIDRA_INSTALL_DIR to a valid Ghidra installation root.",
                    "Retry svr-admin with the desired arguments.",
                ],
            )

        server_dir: Path = Path(ghidra_install_dir) / "server"
        script_path: Path | None = next(
            (
                candidate
                for candidate in (
                    server_dir / "svrAdmin.bat",
                    server_dir / "svrAdmin.cmd",
                    server_dir / "svrAdmin.sh",
                    server_dir / "svrAdmin",
                )
                if candidate.exists()
            ),
            None,
        )
        if script_path is None:
            raise ActionableError(
                f"svrAdmin script not found under '{server_dir}'.",
                context={"action": "svr-admin", "state": "missing-svradmin", "serverDir": str(server_dir)},
                next_steps=[
                    "Verify GHIDRA_INSTALL_DIR points to a full Ghidra install containing server tools.",
                    "Install or mount Ghidra server components, then retry.",
                ],
            )

        argv: list[str] = [str(item) for item in (self._get_list(args, "args", "arguments") or []) if str(item).strip()]
        command: str | None = self._get_str(args, "command")
        if command:
            argv.extend(shlex.split(command, posix=(os.name != "nt")))
        if not argv:
            raise ActionableError(
                "svr-admin requires `args` (array) or `command` (string).",
                context={"action": "svr-admin", "state": "missing-arguments"},
                next_steps=[
                    "Provide raw argument tokens, for example args=['-list'].",
                    "Use command='...' when tokenized args are not convenient.",
                ],
            )

        timeout_seconds: int | None = self._get_int(args, "timeoutseconds", "timeout", default=120)
        command_line: list[str] = [str(script_path), *argv]

        try:
            result = subprocess.run(
                command_line,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ActionableError(
                f"svr-admin timed out after {timeout_seconds} seconds.",
                context={
                    "action": "svr-admin",
                    "state": "timeout",
                    "timeoutSeconds": timeout_seconds,
                    "argv": argv,
                    "stdout": exc.stdout or "",
                    "stderr": exc.stderr or "",
                },
                next_steps=[
                    "Retry with a higher timeoutSeconds value.",
                    "Verify server reachability and credentials for the requested operation.",
                ],
            ) from exc

        return create_success_response(
            {
                "action": "svr-admin",
                "scriptPath": str(script_path),
                "argv": argv,
                "timeoutSeconds": timeout_seconds,
                "exitCode": int(result.returncode),
                "stdout": result.stdout,
                "stderr": result.stderr,
                "success": result.returncode == 0,
            },
        )

    # ------------------------------------------------------------------
    # Fallback-project discovery and reintegration
    # ------------------------------------------------------------------

    def _derive_projects_dir(self, args: dict[str, Any]) -> Path | None:
        """Return the projects directory from args or from the current ghidra project."""
        override: str | None = self._get_str(args, "projectsdir", "projectsdirectory")
        if override:
            return Path(override)
        ghidra_project = self._manager.ghidra_project if self._manager else None
        if ghidra_project is None:
            return None
        try:
            locator = ghidra_project.getProject().getProjectLocator()
            proj_dir = Path(str(locator.getProjectDir()))
            # projects_dir is the *parent* of <project_name>.rep
            return proj_dir.parent
        except Exception as exc:
            logger.warning("Could not derive projects_dir from ghidra_project: %s", exc)
            return None

    async def _handle_list_fallback_projects(self, args: dict[str, Any]) -> list[types.TextContent]:
        """List fallback projects and their reintegration status."""
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._handle_list_fallback_projects")
        from agentdecompile_cli.launcher import (  # noqa: PLC0415
            _iter_domain_items,
            _patch_project_owner,
            _read_fallback_origins,
        )

        projects_dir = self._derive_projects_dir(args)
        if projects_dir is None:
            raise ActionableError(
                "Cannot determine projects directory. Provide projectsDir or open a local project first.",
                context={"action": "list-fallback-projects"},
                next_steps=["Pass projectsDir='/path/to/projects' as an argument."],
            )

        # Filter by original project name (default: current project name)
        original_filter: str | None = self._get_str(args, "originalprojectname")
        if original_filter is None:
            ghidra_project = self._manager.ghidra_project if self._manager else None
            if ghidra_project is not None:
                try:
                    original_filter = str(ghidra_project.getProject().getName())
                except Exception:
                    pass

        data = _read_fallback_origins(projects_dir)
        if not data:
            return create_success_response(
                {
                    "action": "list-fallback-projects",
                    "projectsDir": str(projects_dir),
                    "fallbacks": [],
                    "message": "No fallback project records found.",
                }
            )

        rows: list[dict[str, Any]] = []
        for fallback_name, entry in data.items():
            orig = entry.get("original_project", "?")
            if original_filter and orig != original_filter:
                continue
            rep_exists = (projects_dir / f"{fallback_name}.rep").is_dir()
            reintegrated = entry.get("reintegrated", False)

            # Count programs in fallback (best-effort: open project briefly)
            program_count: int | str = "unknown"
            if rep_exists and not reintegrated:
                try:
                    from ghidra.base.project import GhidraProject  # pyright: ignore[reportMissingImports, reportMissingModuleSource]  # noqa: PLC0415

                    _patch_project_owner(str(projects_dir), fallback_name)
                    fb_proj = GhidraProject.openProject(str(projects_dir), fallback_name, False)
                    try:
                        program_count = sum(1 for _ in _iter_domain_items(fb_proj.getRootFolder()))
                    finally:
                        try:
                            fb_proj.close()
                        except Exception:
                            pass
                except Exception as exc:
                    program_count = f"error: {type(exc).__name__}"

            rows.append(
                {
                    "fallbackName": fallback_name,
                    "originalProject": orig,
                    "createdAt": entry.get("created_at", ""),
                    "reintegrated": reintegrated,
                    "reintegratedAt": entry.get("reintegrated_at", ""),
                    "filesOnDisk": rep_exists,
                    "domainFileCount": program_count,
                }
            )

        # Build a markdown table
        lines: list[str] = [
            "| Fallback Name | Original | Created | Reintegrated | Files on Disk | Domain Files |",
            "|---|---|---|---|---|---|",
        ]
        for row in rows:
            lines.append(
                f"| `{row['fallbackName']}` | `{row['originalProject']}` | {row['createdAt']} "
                f"| {'✓' if row['reintegrated'] else '✗'} {row.get('reintegratedAt', '')} "
                f"| {'yes' if row['filesOnDisk'] else 'no'} | {row['domainFileCount']} |"
            )

        return create_success_response(
            {
                "action": "list-fallback-projects",
                "projectsDir": str(projects_dir),
                "originalFilter": original_filter,
                "count": len(rows),
                "fallbacks": rows,
                "table": "\n".join(lines),
            }
        )

    async def _handle_reintegrate_fallback_projects(self, args: dict[str, Any]) -> list[types.TextContent]:
        """Merge fallback projects back into the original project."""
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._handle_reintegrate_fallback_projects")
        import shutil as _shutil  # noqa: PLC0415
        from datetime import datetime, timezone  # noqa: PLC0415

        from agentdecompile_cli.launcher import (  # noqa: PLC0415
            _iter_domain_items,
            _patch_project_owner,
            _read_fallback_origins,
            _write_fallback_origins,
        )

        projects_dir = self._derive_projects_dir(args)
        if projects_dir is None:
            raise ActionableError(
                "Cannot determine projects directory. Provide projectsDir or open a local project first.",
                context={"action": "reintegrate-fallback-projects"},
                next_steps=["Pass projectsDir='/path/to/projects' as an argument."],
            )

        # Determine the original project (destination)
        original_name: str | None = self._get_str(args, "originalprojectname")
        ghidra_project = self._manager.ghidra_project if self._manager else None
        if original_name is None:
            if ghidra_project is not None:
                try:
                    original_name = str(ghidra_project.getProject().getName())
                except Exception:
                    pass
        if not original_name:
            raise ActionableError(
                "Cannot determine original project name. Provide originalProjectName or open the original project first.",
                context={"action": "reintegrate-fallback-projects"},
                next_steps=["Pass originalProjectName='my_project' as an argument."],
            )

        merge_mode: str = (self._get_str(args, "mergemode") or "overwrite_existing").lower()
        if merge_mode in ("new_only", "newonly"):
            merge_mode = "skip_existing"
        delete_after: bool = self._get_bool(args, "deleteaftermerge", default=False)
        dry_run: bool = self._get_bool(args, "dryrun", default=False)
        requested_fallbacks: list[str] = [
            str(v) for v in (self._get_list(args, "fallbackprojectnames") or []) if v
        ]

        data = _read_fallback_origins(projects_dir)
        candidates = [
            (name, entry)
            for name, entry in data.items()
            if entry.get("original_project") == original_name
            and not entry.get("reintegrated", False)
            and (projects_dir / f"{name}.rep").is_dir()
        ]
        if requested_fallbacks:
            candidates = [(n, e) for n, e in candidates if n in requested_fallbacks]
        # Process oldest-first
        candidates.sort(key=lambda x: x[1].get("created_at", ""))

        if not candidates:
            return create_success_response(
                {
                    "action": "reintegrate-fallback-projects",
                    "originalProject": original_name,
                    "message": "No unintegrated fallback projects found for this original project.",
                    "dryRun": dry_run,
                }
            )

        # Get the live original GhidraProject handle (must already be open)
        if ghidra_project is None:
            raise ActionableError(
                f"Original project '{original_name}' is not open. Open it first, then reintegrate.",
                context={"action": "reintegrate-fallback-projects", "originalProject": original_name},
                next_steps=[f"Call open-project with path to {original_name}, then retry."],
            )

        summary: list[dict[str, Any]] = []
        from ghidra.base.project import GhidraProject as _GhidraProject  # pyright: ignore[reportMissingImports, reportMissingModuleSource]  # noqa: PLC0415
        from ghidra.util.task import TaskMonitor  # pyright: ignore[reportMissingImports, reportMissingModuleSource]  # noqa: PLC0415

        for fallback_name, entry in candidates:
            fb_summary: dict[str, Any] = {
                "fallbackName": fallback_name,
                "copied": 0,
                "skipped": 0,
                "failed": 0,
                "errors": [],
            }
            try:
                _patch_project_owner(str(projects_dir), fallback_name)
                fb_proj = _GhidraProject.openProject(str(projects_dir), fallback_name, False)
            except Exception as exc:
                fb_summary["errors"].append(f"Failed to open fallback project: {exc}")
                summary.append(fb_summary)
                continue

            try:
                fb_root = fb_proj.getRootFolder()

                for domain_file in _iter_domain_items(fb_root):
                    file_path: str = str(domain_file.getPathname())
                    file_name: str = str(domain_file.getName())
                    parent_path: str = str(domain_file.getParent().getPathname())

                    # Check existence in original
                    already_exists = False
                    try:
                        orig_pd = ghidra_project.getProject().getProjectData()
                        check_folder = orig_pd.getFolder(parent_path)
                        if check_folder is not None:
                            already_exists = check_folder.getFile(file_name) is not None
                    except Exception:
                        pass

                    if already_exists and merge_mode == "skip_existing":
                        fb_summary["skipped"] += 1
                        continue

                    if dry_run:
                        action = "would overwrite" if already_exists else "would create"
                        fb_summary["copied"] += 1
                        fb_summary.setdefault("dry_run_actions", []).append(f"{action}: {file_path}")
                        continue

                    # Open domain object from fallback and saveAs into original
                    try:
                        domain_obj = domain_file.getDomainObject(None, True, False, TaskMonitor.DUMMY)
                        try:
                            ghidra_project.saveAs(domain_obj, parent_path, file_name, True)
                            fb_summary["copied"] += 1
                        finally:
                            try:
                                domain_obj.release(None)
                            except Exception:
                                pass
                    except Exception as exc:
                        fb_summary["failed"] += 1
                        fb_summary["errors"].append(f"{file_path}: {type(exc).__name__}: {exc}")
            finally:
                try:
                    fb_proj.close()
                except Exception:
                    pass

            # Update manifest
            if not dry_run:
                data[fallback_name]["reintegrated"] = True
                data[fallback_name]["reintegrated_at"] = datetime.now(timezone.utc).isoformat()
                _write_fallback_origins(projects_dir, data)

                if delete_after and fb_summary["failed"] == 0:
                    try:
                        rep_path = projects_dir / f"{fallback_name}.rep"
                        gpr_path = projects_dir / f"{fallback_name}.gpr"
                        if rep_path.is_dir():
                            _shutil.rmtree(rep_path, ignore_errors=True)
                        if gpr_path.exists():
                            gpr_path.unlink(missing_ok=True)
                        fb_summary["deleted"] = True
                    except Exception as exc:
                        fb_summary["deleteError"] = str(exc)

            summary.append(fb_summary)

        total_copied = sum(s["copied"] for s in summary)
        total_skipped = sum(s["skipped"] for s in summary)
        total_failed = sum(s["failed"] for s in summary)

        return create_success_response(
            {
                "action": "reintegrate-fallback-projects",
                "originalProject": original_name,
                "projectsDir": str(projects_dir),
                "mergeMode": merge_mode,
                "dryRun": dry_run,
                "deleteAfterMerge": delete_after,
                "fallbacksProcessed": len(summary),
                "totalCopied": total_copied,
                "totalSkipped": total_skipped,
                "totalFailed": total_failed,
                "results": summary,
            }
        )

    async def _handle_connect_shared_project(self, args: dict[str, Any]) -> list[types.TextContent]:
        """Connect to shared Ghidra repository server and list available binaries."""
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._handle_connect_shared_project")
        session_id: str = get_current_mcp_session_id()
        # Log incoming args (redact password)
        _safe_args = {k: ("***" if "password" in k.lower() else v) for k, v in (args if isinstance(args, dict) else {}).items()}
        # Security: do not log full session id (log redacted hint only)
        _sid_hint = (session_id[:12] + "…") if session_id and len(session_id) > 12 else (session_id or "—")
        logger.info("[connect-shared-project] session=%s, incoming args=%s", _sid_hint, _safe_args)

        # Populate defaults from HTTP auth context (set by AuthMiddleware when the
        # client authenticates via Authorization + optional X-Ghidra-* headers).
        # Tool arguments always take precedence over auth-context defaults.
        try:
            from agentdecompile_cli.mcp_server.auth import get_current_auth_context  # noqa: PLC0415

            _auth_ctx = get_current_auth_context()
            if _auth_ctx is not None:
                args = dict(args)  # shallow copy so we don't mutate the original
                if "serverhost" not in args and _auth_ctx.server_host:
                    args["serverhost"] = _auth_ctx.server_host
                if "serverport" not in args and _auth_ctx.server_port:
                    args["serverport"] = _auth_ctx.server_port
                if "serverusername" not in args and _auth_ctx.username:
                    args["serverusername"] = _auth_ctx.username
                if "serverpassword" not in args and _auth_ctx.password is not None:
                    args["serverpassword"] = _auth_ctx.password
                # repository → used as the `path` arg to auto-select the right repo
                if "path" not in args and _auth_ctx.repository:
                    args["path"] = _auth_ctx.repository
        except Exception:
            pass  # auth injection is best-effort; never block the tool call

        server_host = (self._require_str(args, "serverhost", name="serverHost") or "").strip()
        if not server_host:
            raise ActionableError(
                "serverHost is required and must be non-empty for shared project connection.",
                context={"action": "connect-shared-project", "mode": "shared-server"},
                next_steps=["Pass a valid serverHost (e.g. 127.0.0.1 or the Ghidra server hostname)."],
            )
        _port_raw = self._get_int(args, "serverport", "port", default=13100)
        try:
            server_port = int(_port_raw) if _port_raw is not None else 13100
        except (TypeError, ValueError):
            server_port = 13100
        if not (0 < server_port <= 65535):
            server_port = 13100
        server_username: str = self._get_str(args, "serverusername", "username")
        server_password: str = self._get_str(args, "serverpassword", "password")
        path: str = self._get_str(args, "path", "programpath", "repositoryname", "binaryname", "binary", default="")
        # Ensure path is set from repositoryName if path is empty
        if not path or not path.strip():
            repo_name = self._get_str(args, "repositoryname", "path", default="")
            if repo_name and repo_name.strip():
                path = repo_name.strip()
                logger.info("[connect-shared-project] Using repositoryName=%r as path", path)

        auth_provided = bool(server_username and server_password)
        server_reachable = False
        logger.info(
            "[connect-shared-project] resolved: host=%s, port=%d, username=%s, path=%r, auth=%s",
            server_host,
            server_port,
            server_username or "(none)",
            path,
            auth_provided,
        )

        try:
            logger.info("[connect-shared-project] TCP connect check %s:%d ...", server_host, server_port)
            with socket.create_connection((str(server_host), server_port), timeout=5):
                server_reachable = True
            logger.info("[connect-shared-project] TCP connect OK")
        except OSError as exc:
            logger.warning("[connect-shared-project] TCP connect FAILED: %s", exc)
            errno_22_hint = ""
            if getattr(exc, "errno", None) == 22:
                errno_22_hint = " (Ensure serverHost is a valid hostname/IP and serverPort is an integer, e.g. 13100.)"
            raise ActionableError(
                f"Ghidra server not reachable at {server_host}:{server_port}: {exc}{errno_22_hint}",
                context={
                    "action": "connect-shared-project",
                    "mode": "shared-server",
                    "serverHost": server_host,
                    "serverPort": server_port,
                    "serverReachable": False,
                    "authProvided": auth_provided,
                },
                next_steps=[
                    "Verify the Ghidra server is running and reachable from this backend runtime.",
                    "Retry with valid `serverHost`, `serverPort`, and optional authentication.",
                ],
            )

        try:
            from ghidra.framework.client import ClientUtil, PasswordClientAuthenticator  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
        except Exception:
            raise ActionableError(
                "Connected to shared server endpoint, but local Ghidra runtime is unavailable for repository browsing.",
                context={
                    "action": "connect-shared-project",
                    "mode": "shared-server",
                    "serverHost": server_host,
                    "serverPort": server_port,
                    "serverReachable": server_reachable,
                    "authProvided": auth_provided,
                },
                next_steps=[
                    "Start the backend with a Ghidra runtime and retry.",
                    "If running in a container, verify PyGhidra/Ghidra classes are available in that image.",
                ],
            )

        original_user_name: str | None = None
        if server_username:
            logger.info("[connect-shared-project] Setting Java user.name = %s", server_username)
            try:
                from java.lang import System as JavaSystem  # pyright: ignore[reportMissingImports]

                original_user_name = JavaSystem.getProperty("user.name")
                JavaSystem.setProperty("user.name", server_username)
                logger.info("[connect-shared-project] Java user.name set (was %s)", original_user_name)
            except Exception:
                original_user_name = None

            try:
                from ghidra.util import SystemUtilities  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

                field = SystemUtilities.class_.getDeclaredField("userName")
                field.setAccessible(True)
                field.set(None, server_username)
                logger.info("[connect-shared-project] SystemUtilities.userName patched")
            except Exception:
                pass

        if server_username and server_password:
            logger.info("[connect-shared-project] Setting PasswordClientAuthenticator")
            ClientUtil.setClientAuthenticator(PasswordClientAuthenticator(server_username, server_password))

        try:
            logger.info("[connect-shared-project] Clearing existing adapter for %s:%d", server_host, server_port)
            ClientUtil.clearRepositoryAdapter(server_host, server_port)
        except Exception:
            pass

        logger.info("[connect-shared-project] Getting repository server adapter for %s:%d", server_host, server_port)
        server_adapter = ClientUtil.getRepositoryServer(server_host, server_port, True)
        if server_adapter is None:
            logger.warning("[connect-shared-project] getRepositoryServer returned None")
            raise ActionableError(
                f"Failed to connect to repository server: {server_host}:{server_port}",
                context={"mode": "shared-server", "serverHost": server_host, "serverPort": server_port},
                next_steps=[
                    "Verify repository server endpoint and network reachability.",
                    "Retry with valid server credentials.",
                ],
            )
        logger.info("[connect-shared-project] adapter obtained, isConnected=%s", server_adapter.isConnected())

        if not server_adapter.isConnected():
            try:
                server_adapter.connect()
            except Exception as exc:
                exc_text = str(exc)
                adapter_error_type, adapter_error = _shared_adapter_error(server_adapter)
                if auth_provided and _shared_auth_failed(adapter_error_type, adapter_error):
                    raise ActionableError(
                        (f"Authentication failed for {server_username}@{server_host}:{server_port} while connecting to the repository server. Wrapper exception: {exc_text}. Adapter reported {adapter_error_type or 'unknown'}: {adapter_error or 'no additional detail'}."),
                        context=_shared_connection_context(
                            stage="server-adapter-connect",
                            server_host=server_host,
                            server_port=server_port,
                            server_username=server_username,
                            requested_path=path or None,
                            auth_provided=auth_provided,
                            server_reachable=server_reachable,
                            wrapper_error=exc_text,
                            adapter_error=adapter_error,
                            adapter_error_type=adapter_error_type,
                        ),
                        next_steps=[
                            "Verify `serverUsername` and `serverPassword` for the Ghidra repository server.",
                            "If the credentials should be valid, verify the same account can log in with a native Ghidra client against this server.",
                            "Retry after confirming the user has access.",
                        ],
                    ) from exc
                raise ActionableError(
                    (f"Repository connection failed for {server_host}:{server_port} during repository-server connect. Wrapper exception: {exc_text}." + (f" Adapter reported {adapter_error_type}: {adapter_error}." if adapter_error else "")),
                    context=_shared_connection_context(
                        stage="server-adapter-connect",
                        server_host=server_host,
                        server_port=server_port,
                        server_username=server_username or None,
                        requested_path=path or None,
                        auth_provided=auth_provided,
                        server_reachable=server_reachable,
                        wrapper_error=exc_text,
                        adapter_error=adapter_error,
                        adapter_error_type=adapter_error_type,
                    ),
                    next_steps=[
                        "Verify server availability and repository service status.",
                        "Retry after server-side issues are resolved.",
                    ],
                ) from exc

            if not server_adapter.isConnected():
                adapter_error_type, adapter_error = _shared_adapter_error(server_adapter)
                message = adapter_error or "unknown authentication/connection failure"
                if auth_provided and _shared_auth_failed(adapter_error_type, adapter_error):
                    raise ActionableError(
                        (f"Authentication failed for {server_username}@{server_host}:{server_port} while connecting to the repository server. Adapter reported {adapter_error_type or 'unknown'}: {message}."),
                        context=_shared_connection_context(
                            stage="server-adapter-connect",
                            server_host=server_host,
                            server_port=server_port,
                            server_username=server_username,
                            requested_path=path or None,
                            auth_provided=auth_provided,
                            server_reachable=server_reachable,
                            adapter_error=adapter_error,
                            adapter_error_type=adapter_error_type,
                        ),
                        next_steps=[
                            "Verify server credentials and account permissions.",
                            "If the credentials should be valid, verify the same account can log in with a native Ghidra client against this server.",
                            "Retry once credentials are corrected.",
                        ],
                    )
                raise ActionableError(
                    (f"Repository connection failed for {server_host}:{server_port} during repository-server connect. Adapter reported {adapter_error_type or 'unknown'}: {message}."),
                    context=_shared_connection_context(
                        stage="server-adapter-connect",
                        server_host=server_host,
                        server_port=server_port,
                        server_username=server_username or None,
                        requested_path=path or None,
                        auth_provided=auth_provided,
                        server_reachable=server_reachable,
                        adapter_error=adapter_error,
                        adapter_error_type=adapter_error_type,
                    ),
                    next_steps=[
                        "Check repository server health/logs and network routing.",
                        "Retry after connectivity is restored.",
                    ],
                )

        try:
            logger.info("[connect-shared-project] Listing repository names...")
            repository_names_raw = server_adapter.getRepositoryNames() or []
            logger.info("[connect-shared-project] Found %d repository name(s): %s", len(list(repository_names_raw)), list(repository_names_raw) if repository_names_raw else [])
        except Exception as exc:
            exc_text = str(exc)
            adapter_error_type, adapter_error = _shared_adapter_error(server_adapter)
            if auth_provided and _shared_auth_failed(adapter_error_type, adapter_error):
                raise ActionableError(
                    (f"Authentication failed for {server_username}@{server_host}:{server_port} after the repository server connection opened. Wrapper exception: {exc_text}. Adapter reported {adapter_error_type or 'unknown'}: {adapter_error or 'no additional detail'}."),
                    context=_shared_connection_context(
                        stage="repository-list",
                        server_host=server_host,
                        server_port=server_port,
                        server_username=server_username,
                        requested_path=path or None,
                        auth_provided=auth_provided,
                        server_reachable=server_reachable,
                        wrapper_error=exc_text,
                        adapter_error=adapter_error,
                        adapter_error_type=adapter_error_type,
                    ),
                    next_steps=[
                        "Verify credentials and repository visibility permissions.",
                        "Retry with a repository name in `path.`",
                    ],
                ) from exc
            raise ActionableError(
                (f"Repository server connection failed for {server_host}:{server_port} while listing repositories. Wrapper exception: {exc_text}." + (f" Adapter reported {adapter_error_type}: {adapter_error}." if adapter_error else "")),
                context=_shared_connection_context(
                    stage="repository-list",
                    server_host=server_host,
                    server_port=server_port,
                    server_username=server_username or None,
                    requested_path=path or None,
                    auth_provided=auth_provided,
                    server_reachable=server_reachable,
                    wrapper_error=exc_text,
                    adapter_error=adapter_error,
                    adapter_error_type=adapter_error_type,
                ),
                next_steps=[
                    "Verify shared repository service status on the server.",
                    "Retry once repository listing is available.",
                ],
            ) from exc
        finally:
            if server_username and original_user_name is not None:
                try:
                    from java.lang import System as JavaSystem  # pyright: ignore[reportMissingImports]

                    JavaSystem.setProperty("user.name", original_user_name)
                except Exception:
                    pass
                try:
                    from ghidra.util import SystemUtilities  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

                    field: Any = SystemUtilities.class_.getDeclaredField("userName")
                    field.setAccessible(True)
                    field.set(None, original_user_name)
                except Exception:
                    pass

        repository_names: list[str] = [str(name) for name in repository_names_raw]
        requested_repository_name = self._infer_requested_shared_repository_name(args, path)
        # Fallback: if inference failed but path looks like a repo name, use it
        # This handles cases where the old code doesn't have the inference fix
        if requested_repository_name is None:
            # Try to get from args directly (normalized keys)
            repo_from_args = self._get_str(args, "repositoryname", "path", default="")
            if repo_from_args and repo_from_args.strip() and "/" not in repo_from_args.strip().rstrip("/"):
                requested_repository_name = repo_from_args.strip().rstrip("/")
                logger.info("[connect-shared-project] Using repositoryName/path from args=%r as repository name", requested_repository_name)
            elif path and path.strip() and "/" not in path.strip().rstrip("/"):
                requested_repository_name = path.strip().rstrip("/")
                logger.info("[connect-shared-project] Using path parameter=%r as repository name (inference returned None)", requested_repository_name)
        allow_repo_creation = bool(server_username or server_password)
        repository_names, repository_created = self._ensure_shared_repository_exists(
            server_adapter=server_adapter,
            repository_names=repository_names,
            requested_repository=requested_repository_name,
            auth_provided=allow_repo_creation,
            server_host=server_host,
            server_port=server_port,
        )

        repository_name: str | None = None
        checkout_program_path: str | None = None

        if requested_repository_name:
            repository_name = requested_repository_name
            if path and path.strip():
                normalized_path = path.strip().rstrip("/")
                if normalized_path and normalized_path != requested_repository_name:
                    checkout_program_path = normalized_path
            logger.info(
                "[connect-shared-project] using requested repository=%r checkout_target=%r",
                repository_name,
                checkout_program_path,
            )
        elif path and path.strip():
            if path in repository_names:
                repository_name = path
                logger.info("[connect-shared-project] path=%r matched a repository name", path)
            else:
                checkout_program_path = path
                repository_name = repository_names[0]
                logger.info("[connect-shared-project] path=%r is a checkout target, using repo=%r", path, repository_name)
        else:
            repository_name = repository_names[0]
            logger.info("[connect-shared-project] No path specified, using first repo=%r", repository_name)

        logger.info("[connect-shared-project] Opening repository %r ...", repository_name)
        repository_adapter: GhidraRepositoryAdapter = server_adapter.getRepository(repository_name)
        if repository_adapter is None:
            raise ActionableError(
                f"Failed to get repository handle for '{repository_name}'",
                context=_shared_connection_context(
                    stage="repository-open",
                    server_host=server_host,
                    server_port=server_port,
                    server_username=server_username or None,
                    repository_name=repository_name,
                    requested_path=path or None,
                    auth_provided=auth_provided,
                    server_reachable=server_reachable,
                ),
                next_steps=[
                    "Call with a valid repository name in `path`.",
                    "Call without `path` to list `availableRepositories`, then retry with one of them.",
                ],
            )

        if not repository_adapter.isConnected():
            try:
                repository_adapter.connect()
            except Exception as exc:
                exc_text = str(exc)
                if auth_provided:
                    raise ActionableError(
                        (f"Authentication failed while opening repository '{repository_name}'. Wrapper exception: {exc_text}."),
                        context=_shared_connection_context(
                            stage="repository-open",
                            server_host=server_host,
                            server_port=server_port,
                            server_username=server_username or None,
                            repository_name=repository_name,
                            requested_path=path or None,
                            auth_provided=auth_provided,
                            server_reachable=server_reachable,
                            wrapper_error=exc_text,
                        ),
                        next_steps=[
                            "Verify credentials and repository-level permissions.",
                            "Retry after confirming access to this repository.",
                        ],
                    ) from exc
                raise ActionableError(
                    f"Failed to connect repository '{repository_name}': {exc_text}",
                    context=_shared_connection_context(
                        stage="repository-open",
                        server_host=server_host,
                        server_port=server_port,
                        server_username=server_username or None,
                        repository_name=repository_name,
                        requested_path=path or None,
                        auth_provided=auth_provided,
                        server_reachable=server_reachable,
                        wrapper_error=exc_text,
                    ),
                    next_steps=[
                        "Verify repository service health and access controls.",
                        "Retry with a known-good repository.",
                    ],
                ) from exc

            if not repository_adapter.isConnected():
                if auth_provided:
                    raise ActionableError(
                        f"Authentication failed while opening repository '{repository_name}'",
                        context=_shared_connection_context(
                            stage="repository-open",
                            server_host=server_host,
                            server_port=server_port,
                            server_username=server_username or None,
                            repository_name=repository_name,
                            requested_path=path or None,
                            auth_provided=auth_provided,
                            server_reachable=server_reachable,
                        ),
                        next_steps=[
                            "Verify credentials and repository membership.",
                            "Retry after credentials are corrected.",
                        ],
                    )
                raise ActionableError(
                    f"Failed to connect repository '{repository_name}'",
                    context=_shared_connection_context(
                        stage="repository-open",
                        server_host=server_host,
                        server_port=server_port,
                        server_username=server_username or None,
                        repository_name=repository_name,
                        requested_path=path or None,
                        auth_provided=auth_provided,
                        server_reachable=server_reachable,
                    ),
                    next_steps=[
                        "Check repository server status and endpoint routing.",
                        "Retry after connectivity is restored.",
                    ],
                )

        logger.info("[connect-shared-project] Listing repository items...")
        binaries: list[dict[str, Any]] = []
        for list_attempt in range(1, 6):
            binaries = self._list_repository_items(repository_adapter)
            if binaries:
                break
            if list_attempt < 5:
                logger.info(
                    "[connect-shared-project] Repository listing empty (attempt %s/5); retrying after short delay",
                    list_attempt,
                )
                time.sleep(0.6)
        logger.info("[connect-shared-project] Found %d item(s) in repository %r", len(binaries), repository_name)

        SESSION_CONTEXTS.set_project_handle(
            session_id,
            {
                "mode": "shared-server",
                "server_host": server_host,
                "server_port": server_port,
                "server_username": server_username,
                "server_password": server_password,
                "server_adapter": server_adapter,
                "repository_name": repository_name,
                "repository_adapter": repository_adapter,
            },
        )
        SESSION_CONTEXTS.set_project_binaries(session_id, binaries)
        logger.info(
            "[connect-shared-project] Session %s is now in SHARED-SERVER mode: repository=%s, binaries=%d",
            session_id[:12],
            repository_name,
            len(binaries),
        )

        # Always use a dedicated on-disk Ghidra project for shared-server mode. If we reused the HTTP
        # server's empty --project-path project, RepositoryAdapter.checkout often leaves DomainFile handles
        # that are not version-controlled for checkin/checkout-status (stale local stubs).
        if self._manager is not None:
            try:
                import tempfile

                from ghidra.base.project import GhidraProject  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
                from ghidra.framework.model import ProjectLocator  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

                # One global temp tree per repo name caused LockException when another MCP/Ghidra
                # process already held the same .gpr; scope by PID so each server instance is isolated.
                repo_safe = repository_name.replace(os.sep, "_")
                shared_project_dir = Path(tempfile.gettempdir()) / "agentdecompile_shared" / f"{repo_safe}_p{os.getpid()}"
                shared_project_dir.mkdir(parents=True, exist_ok=True)
                project_name = "shared"
                locator = ProjectLocator(str(shared_project_dir), project_name)
                if locator.getMarkerFile().exists():
                    from agentdecompile_cli.launcher import _patch_project_owner

                    _patch_project_owner(str(shared_project_dir), project_name)
                    ghidra_project = GhidraProject.openProject(str(shared_project_dir), project_name, False)
                else:
                    ghidra_project = GhidraProject.createProject(str(shared_project_dir), project_name, False)
                self._manager.ghidra_project = ghidra_project
                logger.info("[connect-shared-project] bound ghidra_project to shared checkout tree %s", shared_project_dir)
            except Exception as exc:
                logger.warning("[connect-shared-project] could not bind shared checkout project: %s", exc)

        checked_out_program: str | None = None
        checkout_error: str | None = None
        if checkout_program_path:
            norm_target: str = checkout_program_path.strip().rstrip("/")
            matched: str | None = None
            for b in binaries:
                bp = (b.get("path") or "").strip()
                if bp == norm_target or bp.lstrip("/") == norm_target.lstrip("/"):
                    matched = bp
                    break
                if (b.get("name") or "") == norm_target.rsplit("/", maxsplit=1)[-1]:
                    matched = bp
                    break
            if matched:
                try:
                    checked_out_program = await self._checkout_shared_program(repository_adapter, matched, session_id)
                except Exception as exc:
                    checkout_error = str(exc)
                    logger.warning("Checkout of '%s' failed: %s", matched, exc)
            else:
                logger.warning(
                    "Program '%s' not found in repository '%s'. Available: %s",
                    checkout_program_path,
                    repository_name,
                    [b.get("path") for b in binaries[:10]],
                )

        # --- Collect details for the checked-out program (if any) ---
        checked_out_program_details: dict[str, Any] | None = None
        try:
            if checked_out_program:
                from agentdecompile_cli.mcp_server.program_metadata import collect_program_summary

                session = SESSION_CONTEXTS.get_or_create(session_id)
                co_info = (session.open_programs or {}).get(checked_out_program)
                if co_info is not None:
                    checked_out_program_details = collect_program_summary(co_info)
                    checked_out_program_details["programPath"] = checked_out_program
        except Exception as meta_exc:
            logger.debug("shared_program_metadata_failed: %s", meta_exc)

        return create_success_response(
            {
                "action": "connect-shared-project",
                "mode": "shared-server",
                "serverHost": server_host,
                "serverPort": server_port,
                "serverReachable": server_reachable,
                "serverConnected": bool(server_adapter.isConnected()),
                "authProvided": auth_provided,
                "serverUsername": server_username or None,
                "repository": repository_name,
                "repositoryCreated": repository_created,
                "availableRepositories": repository_names,
                "programCount": len(binaries),
                "programs": binaries,
                "checkedOutProgram": checked_out_program,
                "checkedOutProgramDetails": checked_out_program_details,
                "checkoutError": checkout_error,
                "message": (
                    (f"Created and connected to shared repository '{repository_name}' and discovered {len(binaries)} items." if repository_created else f"Connected to shared repository '{repository_name}' and discovered {len(binaries)} items.") + (f" Checked out: {checked_out_program}" if checked_out_program else "")
                ),
            },
        )

    async def _handle_open(self, args: dict[str, Any]) -> list[types.TextContent]:
        """Open a program or project from local filesystem or current project."""
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._handle_open")
        path_raw: str = self._get_str(args, "programpath", "filepath", "file", "path", "program", "binary")
        # Normalize so backend sees one path form (e.g. proxy on Windows sends forward slashes; backend may be Linux)
        path: str = (path_raw or "").replace("\\", "/").strip()

        if not path:
            raise ActionableError(
                "programPath or filePath required",
                context={"action": "open", "mode": "local-or-project"},
                next_steps=[
                    "For local binaries, call `import-binary` with `path`.",
                    "For project/repository contexts, call `open` with a `.gpr` path, project directory, or shared-server settings.",
                    "For shared server usage, use `connect-shared-project` tool instead.",
                ],
            )

        # Detect Windows-style paths on a non-Windows backend early so we
        # never feed them into Path.resolve() (which would mangle them into
        # something like "/cwd/C:/Users/..." on Linux).
        if self._is_foreign_os_path(path):
            raise ActionableError(
                f"The path '{path}' is a Windows filesystem path but this backend runs on {sys.platform}. Local Windows paths are not accessible from the remote server.",
                context={"action": "open", "path": path, "state": "path-not-found", "reason": "foreign-os-path"},
                next_steps=filter_recommendations(
                    [
                        "Verify the path exists in the backend filesystem.",
                        "Retry with an absolute path visible to the backend runtime.",
                        "Call `{}` with `mode=list` on the parent directory to verify available files.".format(recommend_tool(Tool.MANAGE_FILES.value, Tool.LIST_PROJECT_FILES.value) or Tool.LIST_PROJECT_FILES.value),
                        "Retry with an absolute path that exists in the backend filesystem.",
                    ],
                ),
            )

        resolved: Path = Path(path).expanduser().resolve()
        if not resolved.exists():
            # If path is a .gpr project path, create parent dirs and the project so open works without pre-existing dirs
            if resolved.suffix.lower() == ".gpr":
                return await self._create_and_open_gpr_project(resolved, args)
            normalized_project_path = self._normalize_repo_path(path)
            path_name = normalized_project_path.strip("/").split("/")[-1] or normalized_project_path.strip("/")
            project_data = self._get_active_project_data()
            root_folder: GhidraDomainFolder | None = None
            if project_data is None:
                ghidra_project: GhidraProject | None = getattr(self._manager, "ghidra_project", None) if self._manager else None
                if ghidra_project is not None:
                    try:
                        root_folder = ghidra_project.getRootFolder()
                        if root_folder is not None and hasattr(root_folder, "getProjectData"):
                            project_data = root_folder.getProjectData()
                    except Exception:
                        pass
            domain_file: GhidraDomainFile | None = None
            if project_data is not None:
                try:
                    domain_file = project_data.getFile(normalized_project_path)
                except Exception:
                    pass
                if domain_file is None and self._manager is not None:
                    try:
                        root_folder = project_data.getRootFolder() if root_folder is None else root_folder
                        if root_folder is not None and path_name:
                            domain_file = self._manager._find_domain_file_by_name(root_folder, path_name, 5000)
                    except Exception:
                        pass
            if domain_file is None and root_folder is not None and path_name and self._manager is not None:
                try:
                    domain_file = self._manager._find_domain_file_by_name(root_folder, path_name, 5000)
                except Exception:
                    pass
                if domain_file is None:
                    try:
                        for df in root_folder.getFiles() or []:
                            name = str(df.getName() if hasattr(df, "getName") else "")
                            pname = str(df.getPathname() if hasattr(df, "getPathname") else "")
                            if path_name in name or path_name in pname or (name and path_name.lower() in name.lower()):
                                domain_file = df
                                break
                        if domain_file is None and (root_folder.getFiles() or []):
                            domain_file = (root_folder.getFiles() or [])[0]
                    except Exception:
                        pass
            if domain_file is None and root_folder is None:
                ghidra_project: GhidraProject | None = getattr(self._manager, "ghidra_project", None) if self._manager else None
                if ghidra_project is not None and path_name and self._manager is not None:
                    try:
                        root_folder = ghidra_project.getRootFolder()
                        if root_folder is not None:
                            domain_file = self._manager._find_domain_file_by_name(root_folder, path_name, 5000)
                    except Exception:
                        pass

            if domain_file is not None:
                try:
                    program = self._open_program_from_domain_file(domain_file)
                    self._set_active_program_info(program, normalized_project_path)
                    return create_success_response(
                        {
                            "action": "open",
                            "mode": "project-domain",
                            "path": normalized_project_path,
                            "exists": True,
                            "isProjectPath": True,
                            "message": f"Opened project domain file: {normalized_project_path}",
                        },
                    )
                except Exception as exc:
                    raise ActionableError(
                        f"Failed to open project path '{normalized_project_path}': {exc}",
                        context={"action": "open", "path": normalized_project_path, "state": "project-open-failed"},
                        next_steps=[
                            "Call `list-project-files` to confirm the exact program path.",
                            "Retry with that project path.",
                        ],
                    ) from exc

            raise ActionableError(
                f"Path does not exist: {path}",
                context={"action": "open", "path": path, "state": "path-not-found"},
                next_steps=filter_recommendations(
                    [
                        "Verify the path exists in the backend filesystem.",
                        "Retry with an absolute path visible to the backend runtime.",
                        "Call `{}` with `mode=list` on the parent directory to verify available files.".format(recommend_tool(Tool.MANAGE_FILES.value, Tool.LIST_PROJECT_FILES.value) or Tool.LIST_PROJECT_FILES.value),
                        "Retry with an absolute path that exists in the backend filesystem.",
                    ],
                ),
            )

        if resolved.is_file() and resolved.suffix.lower() == ".gpr":
            return await self._open_gpr_project(resolved, args)

        if resolved.is_file():
            return await self._import_file(str(resolved), args)

        if resolved.is_dir():
            # Opening a directory must attach a concrete .gpr under that path. Otherwise the
            # GhidraProject on the manager stays on the server's default --project-path, and
            # list-project-files / import-binary mutate the wrong project (stale binaries,
            # shared-repo symbols leaking into "local" E2E).
            gpr_preferred: Path = resolved / f"{resolved.name}.gpr"
            existing_gprs: list[Path] = sorted(resolved.glob("*.gpr"))
            if gpr_preferred.exists():
                return await self._open_gpr_project(gpr_preferred, args)
            if existing_gprs:
                chosen: Path = existing_gprs[0]
                for candidate in existing_gprs:
                    if candidate.stem.lower() == resolved.name.lower():
                        chosen = candidate
                        break
                return await self._open_gpr_project(chosen, args)
            return await self._create_and_open_gpr_project(gpr_preferred, args)

        return create_success_response(
            {
                "action": "open",
                "path": str(resolved),
                "exists": True,
                "isDirectory": False,
                "filesDiscovered": 0,
                "note": "Path resolved. Use manage-files mode=import for explicit binary imports.",
            },
        )

    async def _create_and_open_gpr_project(self, gpr_path: Path, args: dict[str, Any]) -> list[types.TextContent]:
        """Create parent dirs and a new Ghidra project at the given .gpr path, then open it."""
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._create_and_open_gpr_project")
        project_dir: Path = gpr_path.parent
        project_name: str = gpr_path.stem
        try:
            project_dir.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            raise ActionableError(
                f"Failed to create project directory '{project_dir}': {exc}",
                context={"action": "open", "mode": "gpr-project", "path": str(gpr_path), "state": "create-dir-failed"},
                next_steps=["Check filesystem permissions and retry with a valid parent path."],
            ) from exc
        try:
            from ghidra.base.project import GhidraProject  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

            ghidra_project: GhidraProject = GhidraProject.createProject(str(project_dir), project_name, False)
        except Exception as exc:
            raise ActionableError(
                f"Failed to create .gpr project '{gpr_path}': {exc}",
                context={"action": "open", "mode": "gpr-project", "path": str(gpr_path), "state": "project-create-failed"},
                next_steps=["Verify the parent path is writable and retry."],
            ) from exc
        return await self._set_gpr_project_state_and_respond(gpr_path, project_dir, project_name, ghidra_project, args)

    async def _open_gpr_project(self, gpr_path: Path, args: dict[str, Any]) -> list[types.TextContent]:
        """Open an existing Ghidra .gpr project file.

        This uses GhidraProject.openProject() to open a .gpr-backed project,
        sets it as the active project on the manager, and lists available programs.
        """
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._open_gpr_project")
        project_dir: Path = gpr_path.parent
        project_name: str = gpr_path.stem  # e.g. "my_project" from "my_project.gpr"

        try:
            from ghidra.base.project import GhidraProject  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

            from agentdecompile_cli.launcher import _patch_project_owner

            _patch_project_owner(str(project_dir), project_name)
            ghidra_project: GhidraProject = GhidraProject.openProject(str(project_dir), project_name, False)
        except Exception as exc:
            raise ActionableError(
                f"Failed to open .gpr project '{gpr_path}': {exc}",
                context={"action": "open", "mode": "gpr-project", "path": str(gpr_path), "state": "project-open-failed"},
                next_steps=[
                    "Verify the .gpr file is a valid Ghidra project (check for matching .rep directory).",
                    "Retry with a valid .gpr project path.",
                ],
            ) from exc

        return await self._set_gpr_project_state_and_respond(gpr_path, project_dir, project_name, ghidra_project, args)

    async def _set_gpr_project_state_and_respond(
        self,
        gpr_path: Path,
        project_dir: Path,
        project_name: str,
        ghidra_project: GhidraProject,
        args: dict[str, Any],
    ) -> list[types.TextContent]:
        """Set manager/session state and build success response for an open/create .gpr project."""
        # Set on the manager so all providers can use it
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._set_gpr_project_state_and_respond")
        if self._manager is not None:
            self._manager.ghidra_project = ghidra_project

        # List available programs in the project
        programs_list: list[dict[str, Any]] = []
        first_program_path: str | None = None
        try:
            project_data = ghidra_project.getProject().getProjectData()
            if project_data is not None:
                root = project_data.getRootFolder()
                items = self._list_domain_files(root, 1000)
                for item in items:
                    if item.get("type") != "Folder":
                        programs_list.append(item)
                        if first_program_path is None:
                            first_program_path = item.get("path")
        except Exception as exc:
            logger.warning("Failed to list programs from .gpr project: %s", exc)

        # Store project binaries in session
        session_id: str = get_current_mcp_session_id()
        SESSION_CONTEXTS.set_project_binaries(session_id, programs_list)
        SESSION_CONTEXTS.set_project_handle(
            session_id,
            {
                "mode": "local-gpr",
                "path": str(gpr_path),
                "project_name": project_name,
                "project_dir": str(project_dir),
            },
        )

        # Auto-open first program if available, or a specific requested program
        analyze = self._get_bool(args, "analyzeafterimport", default=True)
        open_all = self._get_bool(args, "openallprograms", default=False)
        opened_program: str | None = None
        requested_program = self._get_str(args, "programpath", "binary", "binaryname")

        target_path = requested_program or first_program_path

        # Eagerly open ALL programs in the project (up to MAX_AUTO_OPEN_PROGRAMS) so they
        # are available to tools without requiring explicit open calls.  The requested/first
        # program becomes the active one; others are stored in SESSION_CONTEXTS.open_programs.
        from agentdecompile_cli.mcp_server.tool_providers import MAX_AUTO_OPEN_PROGRAMS

        eager_opened: list[str] = []
        if programs_list:
            try:
                project_data = ghidra_project.getProject().getProjectData()
                for item in programs_list[:MAX_AUTO_OPEN_PROGRAMS]:
                    item_path = item.get("path") or item.get("name") or ""
                    if not item_path:
                        continue
                    try:
                        domain_file = project_data.getFile(item_path)
                        if domain_file is None:
                            continue
                        program = self._open_program_from_domain_file(domain_file)
                        if program is None:
                            continue

                        is_primary = (item_path == target_path)

                        if is_primary:
                            # Primary program: set as active (with decompiler)
                            self._set_active_program_info(program, item_path)
                            opened_program = item_path
                            if analyze:
                                try:
                                    from ghidra.program.flatapi import FlatProgramAPI  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

                                    flat_api = FlatProgramAPI(program)  # noqa: F841
                                    from ghidra.program.util import GhidraProgramUtilities  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

                                    GhidraProgramUtilities.setAnalyzedFlag(program, True)
                                except Exception as analysis_exc:
                                    logger.warning("Post-open analysis for .gpr program failed: %s", analysis_exc)
                        else:
                            # Secondary programs: store in session with decompiler=None (lazy init)
                            from agentdecompile_cli.launcher import ProgramInfo as _ProgramInfo

                            secondary_info = _ProgramInfo(
                                name=program.getName() if hasattr(program, "getName") else Path(item_path).name,
                                program=program,
                                flat_api=None,
                                decompiler=None,
                                metadata={},
                                ghidra_analysis_complete=True,
                                file_path=None,
                                load_time=time.time(),
                            )
                            SESSION_CONTEXTS.set_active_program_info(session_id, item_path, secondary_info)
                            # Restore active key to the primary program (set_active_program_info changes it)
                            if opened_program:
                                session = SESSION_CONTEXTS.get_or_create(session_id)
                                session.active_program_key = opened_program

                        eager_opened.append(item_path)
                    except Exception as exc:
                        logger.debug(
                            "eager_open_program_skip path_tail=%s exc_type=%s",
                            basename_hint(item_path),
                            type(exc).__name__,
                        )
                        continue
            except Exception as exc:
                logger.warning("Failed to eagerly open programs from .gpr project: %s", exc)

        # If we didn't open the primary target above (it wasn't in programs_list), try it directly
        if opened_program is None and target_path and not open_all:
            try:
                project_data = ghidra_project.getProject().getProjectData()
                domain_file = project_data.getFile(target_path)
                if domain_file is not None:
                    program = self._open_program_from_domain_file(domain_file)
                    if program is not None:
                        self._set_active_program_info(program, target_path)
                        opened_program = target_path

                        if analyze:
                            try:
                                from ghidra.program.flatapi import FlatProgramAPI  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

                                flat_api = FlatProgramAPI(program)  # noqa: F841
                                from ghidra.program.util import GhidraProgramUtilities  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

                                GhidraProgramUtilities.setAnalyzedFlag(program, True)
                            except Exception as analysis_exc:
                                logger.warning("Post-open analysis for .gpr program failed: %s", analysis_exc)
            except Exception as exc:
                logger.warning("Failed to auto-open program from .gpr project: %s", exc)

        logger.info(
            "gpr_eager_open_summary session_id=%s total_programs=%s eager_opened=%s active_tail=%s",
            redact_session_id(session_id),
            len(programs_list),
            len(eager_opened),
            basename_hint(opened_program) if opened_program else "—",
        )

        # --- Collect per-program details for eagerly-opened programs ---
        program_details: list[dict[str, Any]] = []
        try:
            from agentdecompile_cli.mcp_server.program_metadata import collect_program_summary

            session = SESSION_CONTEXTS.get_or_create(session_id)
            for prog_key, prog_info in (session.open_programs or {}).items():
                try:
                    detail = collect_program_summary(prog_info)
                    detail["programPath"] = prog_key
                    detail["isActive"] = (prog_key == opened_program)
                    program_details.append(detail)
                except Exception as detail_exc:
                    logger.debug("program_detail_skip path=%s exc=%s", basename_hint(prog_key), detail_exc)
        except Exception as meta_exc:
            logger.debug("program_metadata_collection_failed: %s", meta_exc)

        return create_success_response(
            {
                "action": "open",
                "mode": "gpr-project",
                "path": str(gpr_path),
                "projectName": project_name,
                "projectDir": str(project_dir),
                "exists": True,
                "isProject": True,
                "programCount": len(programs_list),
                "programs": programs_list,
                "openedProgram": opened_program,
                "eagerOpenedCount": len(eager_opened),
                "eagerOpenedPrograms": eager_opened,
                "programDetails": program_details,
                "message": (
                    f"Opened .gpr project '{project_name}' with {len(programs_list)} programs "
                    f"({len(eager_opened)} pre-loaded)."
                    + (f" Active program: {opened_program}" if opened_program else "")
                ),
            },
        )

    async def _handle_list(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._handle_list")
        await self._ensure_program_loaded_for_stateless_request(args)

        # Use only `folder` for Ghidra project paths. The `path` argument is reserved for
        # explicit filesystem directory listing (see fs_path below); mixing the two keys
        # caused clients that send path=/ to hit OS listing or wrong folder resolution.
        folder: str = self._get_str(args, "folder", default="/")
        res = self._get_int(args, "maxresults", "limit", default=100)
        max_results: int = 100 if res is None else res
        session_id: str = get_current_mcp_session_id()
        project_handle_for_list = SESSION_CONTEXTS.get_project_handle(session_id)
        is_shared_mode: bool = is_shared_server_handle(project_handle_for_list)

        fs_path: str = self._get_str(args, "path")
        if fs_path:
            base: Path = Path(fs_path).expanduser().resolve()
            if not base.exists() or not base.is_dir():
                raise ValueError(f"Invalid folder path: {base}")
            files: list[dict[str, Any]] = []
            for item in base.rglob("*"):
                if len(files) >= max_results:
                    break
                files.append({"name": item.name, "path": str(item), "isDirectory": item.is_dir(), "size": None if item.is_dir() else item.stat().st_size})
            return create_success_response({"folder": str(base), "files": files, "count": len(files)})

        if self.program_info is None or getattr(self.program_info, "program", None) is None or not hasattr(getattr(self.program_info, "program", None), "getDomainFile"):
            session_binaries: list[dict[str, Any]] = SESSION_CONTEXTS.get_project_binaries(session_id, fallback_to_latest=False)
            if not session_binaries:
                await self._ensure_shared_listing_available(args)
                session_binaries = SESSION_CONTEXTS.get_project_binaries(session_id, fallback_to_latest=False)
            if session_binaries:
                files = []
                for item in session_binaries[:max_results]:
                    path = str(item.get("path") or "")
                    name = str(item.get("name") or Path(path).name)
                    files.append(
                        {
                            "name": name,
                            "path": path,
                            "isDirectory": False,
                            "type": item.get("type", "Program"),
                        },
                    )
                return create_success_response(
                    {
                        "folder": folder,
                        "files": files,
                        "count": len(files),
                        "source": "shared-server-session",
                    },
                )
            # Check if we're in shared-server mode - if so, NEVER fall back to local project
            if is_shared_mode:
                # In shared-server mode but no binaries: repository might be empty or listing failed
                # Try to refresh from the repository adapter if available
                repository_adapter = project_handle_for_list.get("repository_adapter") if isinstance(project_handle_for_list, dict) else None
                if repository_adapter is not None:
                    try:
                        logger.info("list-project-files: refreshing repository listing for shared-server session")
                        refreshed_binaries = self._list_repository_items(repository_adapter)
                        SESSION_CONTEXTS.set_project_binaries(session_id, refreshed_binaries)
                        if refreshed_binaries:
                            files = []
                            for item in refreshed_binaries[:max_results]:
                                path = str(item.get("path") or "")
                                name = str(item.get("name") or Path(path).name)
                                files.append(
                                    {
                                        "name": name,
                                        "path": path,
                                        "isDirectory": False,
                                        "type": item.get("type", "Program"),
                                    },
                                )
                            return create_success_response(
                                {
                                    "folder": folder,
                                    "files": files,
                                    "count": len(files),
                                    "source": "shared-server-session",
                                    "note": "Refreshed from repository",
                                },
                            )
                    except Exception as e:
                        logger.warning("list-project-files: failed to refresh shared repository listing: %s", e)
                # Shared-server mode but no binaries available (empty repo or error)
                return create_success_response(
                    {
                        "folder": folder,
                        "files": [],
                        "count": 0,
                        "source": "shared-server-session",
                        "note": "Shared repository is empty or listing unavailable. Use import-binary to add programs.",
                    },
                )
            # No program loaded and no session binaries: list from the open Ghidra project
            # on disk (local). Try every known domain root — some builds only expose files
            # under getProject().getProjectData().getRootFolder(), not ghidra_project.getRootFolder().
            ghidra_project_noload: GhidraProject | None = getattr(self._manager, "ghidra_project", None) if self._manager else None
            if ghidra_project_noload is not None:
                try:
                    normalized_folder_noload = self._normalize_repo_path(folder)
                    files_noload = list_project_tree_from_ghidra(
                        ghidra_project_noload,
                        normalized_folder=normalized_folder_noload,
                        max_results=max_results,
                    )
                    logger.info(
                        "list-project-files (no program loaded): listed %s items from local ghidra project",
                        len(files_noload),
                    )
                    payload: dict[str, Any] = {
                        "folder": folder,
                        "files": files_noload,
                        "count": len(files_noload),
                        "source": "local-ghidra-project",
                    }
                    if not files_noload:
                        payload["note"] = "Ghidra project is open but this folder has no domain files yet (try folder=/ after import, or open on your project directory)."
                    return create_success_response(payload)
                except Exception as e:
                    logger.warning("list-project-files (no program loaded): failed to list from ghidra_project: %s", e)
            return create_success_response({"folder": folder, "files": [], "count": 0, "note": "No project loaded"})

        try:
            project_data: GhidraProjectData | None = self._get_active_project_data()
            if project_data is None:
                raise ValueError("No project data available")

            target_folder: GhidraDomainFolder | None = None
            normalized_folder: str = self._normalize_repo_path(folder)
            if normalized_folder == "/":
                target_folder = project_data.getRootFolder()
            else:
                target_folder = project_data.getFolder(normalized_folder)
                if target_folder is None:
                    payload: dict[str, Any] = {"folder": normalized_folder, "files": [], "count": 0}
                    if is_shared_mode:
                        payload["source"] = "shared-server-session"
                    return create_success_response(payload)

            files = self._list_domain_files(target_folder, max_results)
            if not files:
                session_binaries = SESSION_CONTEXTS.get_project_binaries(session_id)
                if session_binaries:
                    fallback_files: list[dict[str, Any]] = []
                    for item in session_binaries[:max_results]:
                        path = str(item.get("path") or "")
                        name = str(item.get("name") or Path(path).name)
                        fallback_files.append(
                            {
                                "name": name,
                                "path": path,
                                "isDirectory": False,
                                "type": item.get("type", "Program"),
                            },
                        )
                    source_key = "shared-server-session" if is_shared_mode else "session-binaries"
                    return create_success_response(
                        {
                            "folder": folder,
                            "files": fallback_files,
                            "count": len(fallback_files),
                            "source": source_key,
                        },
                    )
            payload = {"folder": folder, "files": files, "count": len(files)}
            if is_shared_mode:
                payload["source"] = "shared-server-session"
            return create_success_response(payload)
        except Exception as e:
            session_binaries: list[dict[str, Any]] = SESSION_CONTEXTS.get_project_binaries(session_id, fallback_to_latest=False)
            if session_binaries:
                files = []
                for item in session_binaries[:max_results]:
                    path = str(item.get("path") or "")
                    name = str(item.get("name") or Path(path).name)
                    files.append(
                        {
                            "name": name,
                            "path": path,
                            "isDirectory": False,
                            "type": item.get("type", "Program"),
                        },
                    )
                return create_success_response(
                    {
                        "folder": folder,
                        "files": files,
                        "count": len(files),
                        "source": "shared-server-session",
                        "note": f"Fell back to shared repository index: {e}",
                    },
                )
            return create_success_response({"folder": folder, "files": [], "error": str(e)})

    async def _ensure_shared_listing_available(self, args: dict[str, Any]) -> None:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._ensure_shared_listing_available")
        env_host: str | None = self._get_str(args, "serverhost", "ghidraserverhost") or self._get_shared_server_host()
        if not env_host:
            return

        session_id: str = get_current_mcp_session_id()
        if SESSION_CONTEXTS.get_project_binaries(session_id, fallback_to_latest=False):
            return

        try:
            await self._handle_connect_shared_project(self._build_shared_args(args, env_host))
        except Exception as e:
            logger.debug("Shared listing bootstrap failed: %s", e)

    async def _ensure_program_loaded_for_stateless_request(self, args: dict[str, Any]) -> None:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._ensure_program_loaded_for_stateless_request")
        program: GhidraProgram | None = getattr(self.program_info, "program", None) if self.program_info is not None else None
        if program is not None:
            return

        requested_program: str | None = self._get_str(args, "programpath", "binary", "binaryname")
        if not requested_program:
            return

        open_args: dict[str, Any] = {
            "path": requested_program,
        }

        server_host: str | None = self._get_str(args, "serverhost", "ghidraserverhost") or os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_HOST", os.getenv("AGENT_DECOMPILE_SERVER_HOST", os.getenv("AGENTDECOMPILE_SERVER_HOST", ""))).strip()
        if server_host:
            open_args["serverhost"] = server_host
            open_args["serverport"] = self._get_int(
                args,
                "serverport",
                "ghidraserverport",
                default=int(os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_PORT", os.getenv("AGENT_DECOMPILE_SERVER_PORT", os.getenv("AGENTDECOMPILE_SERVER_PORT", "13100"))) or "13100"),
            )
            open_args["serverusername"] = self._get_str(args, "serverusername", "ghidraserverusername") or os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME", os.getenv("AGENT_DECOMPILE_SERVER_USERNAME", os.getenv("AGENTDECOMPILE_SERVER_USERNAME", ""))).strip()
            open_args["serverpassword"] = self._get_str(args, "serverpassword", "ghidraserverpassword") or os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD", os.getenv("AGENT_DECOMPILE_SERVER_PASSWORD", os.getenv("AGENTDECOMPILE_SERVER_PASSWORD", ""))).strip()
            repository_name: str | None = (
                self._get_str(args, "repositoryname", "ghidraserverrepository") or os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY", os.getenv("AGENTDECOMPILE_GHIDRA_SERVER_REPOSITORY", "")).strip() or os.getenv("AGENT_DECOMPILE_REPOSITORY", os.getenv("AGENTDECOMPILE_REPOSITORY", "")).strip()
            )
            if repository_name:
                open_args["repositoryname"] = repository_name

        try:
            open_result = await self._handle_open_project(open_args)
        except Exception as e:
            logger.debug("Auto-open failed for stateless request (%s): %s", requested_program, e)
            raise

        program = getattr(self.program_info, "program", None) if self.program_info is not None else None
        if program is not None:
            return

        open_error: str | None = None
        for item in open_result or []:
            text = getattr(item, "text", None)
            if not isinstance(text, str):
                continue
            try:
                payload = json.loads(text)
            except Exception:
                continue
            if isinstance(payload, dict) and payload.get("success") is False and payload.get("error"):
                open_error = str(payload["error"])
                break

        if open_error:
            raise ActionableError(open_error)

        raise ActionableError(
            f"Failed to load requested program '{requested_program}' for this stateless request",
            context={"programPath": requested_program, "openArgs": open_args},
        )

    async def _ensure_program_loaded_for_args(self, args: dict[str, Any]) -> None:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._ensure_program_loaded_for_args")
        await self._ensure_program_loaded_for_stateless_request(args)

    async def _handle_manage(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._handle_manage")
        operation: str = self._require_str(args, "mode", "action", "operation", name="mode")

        return await self._dispatch_handler(
            args,
            operation,
            {
                "open": "_handle_open",
                "changeprocessor": "_handle_change_processor",
                "import": "_handle_import",
                "export": "_handle_export",
                "downloadshared": "_handle_sync_shared",
                "downloadsharedproject": "_handle_sync_shared",
                "downloadsharedrepository": "_handle_sync_shared",
                "pullshared": "_handle_sync_shared",
                "pullsharedproject": "_handle_sync_shared",
                "pullsharedrepository": "_handle_sync_shared",
                "importtoshared": "_handle_sync_shared",
                "pushshared": "_handle_sync_shared",
                "pushsharedproject": "_handle_sync_shared",
                "pushsharedrepository": "_handle_sync_shared",
                "uploadshared": "_handle_sync_shared",
                "uploadsharedrepository": "_handle_sync_shared",
                "mirrorshared": "_handle_sync_shared",
                "syncshared": "_handle_sync_shared",
                "syncsharedproject": "_handle_sync_shared",
                "syncsharedrepository": "_handle_sync_shared",
                "syncwithshared": "_handle_sync_shared",
                "checkout": "_handle_checkout",
                "uncheckout": "_handle_uncheckout",
                "unhijack": "_handle_unhijack",
                "list": "_handle_list_files",
                "mkdir": "_handle_filesystem_operation_blocked",
                "touch": "_handle_filesystem_operation_blocked",
                "info": "_handle_filesystem_operation_blocked",
                "read": "_handle_filesystem_operation_blocked",
                "write": "_handle_filesystem_operation_blocked",
                "append": "_handle_filesystem_operation_blocked",
                "copy": "_handle_filesystem_operation_blocked",
                "rename": "_handle_rename",
                "delete": "_handle_delete",
                "move": "_handle_move",
            },
        )

    async def _handle_filesystem_operation_blocked(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._handle_filesystem_operation_blocked")
        operation: str | None = self._get_str(args, "mode", "action", "operation", default="unknown")
        if operation is None:
            operation = "unknown"
        manage_files_tool: str | None = recommend_tool(Tool.MANAGE_FILES.value)
        if manage_files_tool:
            steps: list[str] = [
                f"Use `{manage_files_tool}` `mode=list`, `mode=import`, or `mode=export` for filesystem operations.",
                "Use project paths (for example `/K1/k1_win_gog_swkotor.exe`) with `mode=rename`, `mode=move`, or `mode=delete` for project-domain changes.",
            ]
        else:
            steps = [
                "Use `list-project-files` for project listing operations.",
                "Use project paths for project-domain changes.",
            ]
        raise ActionableError(
            f"Filesystem operation '{operation}' is disabled",
            context={
                "operation": operation,
                "scope": "filesystem",
                "allowedFilesystemOperations": ["list", "import", "export"],
            },
            next_steps=filter_recommendations(steps),
        )

    async def _handle_import(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._handle_import")
        file_path: str | None = self._get_str(args, "filepath", "file", "path", "programpath")
        if not file_path:
            manage_files_tool: str | None = recommend_tool(Tool.MANAGE_FILES.value)
            if manage_files_tool:
                steps = [
                    f"Call `{manage_files_tool}` with `mode=import` and `path` pointing to an existing file or directory.",
                    f"Use `{manage_files_tool}` `mode=list` first if you need to discover valid paths.",
                ]
            else:
                steps = [
                    "Provide `path` pointing to an existing file or directory for import.",
                    "Use `list-project-files` to discover valid paths if needed.",
                ]
            raise ActionableError(
                "path/filePath is required for import",
                context={"operation": "import", "state": "missing-path"},
                next_steps=filter_recommendations(steps),
            )
        return await self._import_file(file_path, args)

    async def _handle_export(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._handle_export")
        return await self._export_current_program(args)

    async def _handle_change_processor(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._handle_change_processor")
        await self._ensure_program_loaded_for_args(args)
        self._require_program()
        assert self.program_info is not None

        language: str | None = self._get_str(args, "languageid", "language", "lang")
        processor: str | None = self._get_str(args, "processor")
        compiler: str | None = self._get_str(args, "compilerspecid", "compiler", "compilerspec")
        endian: str | None = self._get_str(args, "endian")

        if not language:
            if processor and ":" in processor:
                language = processor
            else:
                raise ActionableError(
                    "languageId is required (or provide processor as a full language ID, e.g. x86:LE:64:default)",
                    context={
                        "operation": "change-processor",
                        "state": "missing-language",
                        "processor": processor,
                        "endian": endian,
                    },
                    next_steps=[
                        "Call `change-processor` with `languageId` set to a valid Ghidra language ID.",
                        "Optionally set `compilerSpecId` to override compiler selection.",
                    ],
                )

        program: GhidraProgram = self.program_info.program
        try:
            from ghidra.program.model.lang import CompilerSpecID, LanguageID  # pyright: ignore[reportMissingModuleSource]
            from ghidra.program.util import DefaultLanguageService  # pyright: ignore[reportMissingModuleSource]
            from ghidra.util.task import TaskMonitor  # pyright: ignore[reportMissingModuleSource]

            def _change_processor() -> None:
                language_id = LanguageID(language)
                language_service = DefaultLanguageService.getLanguageService()
                language_obj = language_service.getLanguage(language_id)
                if language_obj is None:
                    raise RuntimeError(f"Unable to resolve language: {language}")

                compiler_spec_id = CompilerSpecID(compiler) if compiler else language_obj.getDefaultCompilerSpec().getCompilerSpecID()

                try:
                    program.setLanguage(language_obj, compiler_spec_id, True, TaskMonitor.DUMMY)
                except Exception:
                    compiler_spec = language_obj.getDefaultCompilerSpec()
                    if compiler:
                        try:
                            compiler_spec = language_obj.getCompilerSpecByID(compiler_spec_id)
                        except Exception:
                            compiler_spec = language_obj.getDefaultCompilerSpec()
                    program.setLanguage(language_obj, compiler_spec, True, TaskMonitor.DUMMY)

            self._run_program_transaction(program, "change-processor", _change_processor)

            return create_success_response(
                {
                    "operation": "change-processor",
                    "processor": processor,
                    "language": language,
                    "compiler": compiler or "(default)",
                    "endian": endian,
                    "success": True,
                },
            )
        except Exception as exc:
            return create_success_response(
                {
                    "operation": "change-processor",
                    "processor": processor,
                    "language": language,
                    "compiler": compiler or "(default)",
                    "endian": endian,
                    "success": False,
                    "error": str(exc),
                },
            )

    async def _handle_sync_shared(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._handle_sync_shared")
        operation: str | None = self._get_str(args, "mode", "action", "operation", default="syncshared")
        if operation is None:
            operation = "syncshared"
        op: str = n(operation)
        logger.info(
            "shared-sync dispatch start operation=%s normalized=%s arg_keys=%s",
            operation,
            op,
            sorted(list(args.keys())),
        )
        if op in {"downloadshared", "downloadsharedproject", "downloadsharedrepository", "pullshared", "pullsharedproject", "pullsharedrepository"}:
            logger.info("shared-sync dispatch routed to pull mode via operation=%s", operation)
            return await self._sync_shared_repository(args, default_mode="pull")
        if op in {"importtoshared", "pushshared", "pushsharedproject", "pushsharedrepository", "uploadshared", "uploadsharedrepository"}:
            logger.info("shared-sync dispatch routed to push mode via operation=%s", operation)
            return await self._sync_shared_repository(args, default_mode="push")
        if op in {"mirrorshared", "syncshared", "syncsharedproject", "syncsharedrepository", "syncwithshared"}:
            logger.info("shared-sync dispatch routed to bidirectional mode via operation=%s", operation)
            return await self._sync_shared_repository(args, default_mode="bidirectional")
        logger.warning("shared-sync dispatch failed unsupported operation=%s normalized=%s", operation, op)
        raise ActionableError(f"Unsupported sync operation: {operation}")

    async def _handle_checkout(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._handle_checkout")
        program_path: str | None = self._get_str(args, "programpath", "filepath", "file", "path")
        domain_file: GhidraDomainFile | None = self._resolve_domain_file(program_path)
        if domain_file is None:
            self._raise_domain_file_error("checkout", program_path)
        exclusive = self._get_bool(args, "exclusive", default=False)
        if hasattr(domain_file, "checkout"):
            from ghidra.util.task import TaskMonitor  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

            assert domain_file is not None, "domain_file should not be None here since we check and raise above"
            domain_file.checkout(exclusive, TaskMonitor.DUMMY)
        return create_success_response(
            {
                "operation": "checkout",
                "programPath": program_path,
                "exclusive": exclusive,
                "success": True,
            },
        )

    async def _handle_uncheckout(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._handle_uncheckout")
        program_path: str | None = self._get_str(args, "programpath", "filepath", "file", "path")
        domain_file: GhidraDomainFile | None = self._resolve_domain_file(program_path)
        if domain_file is None:
            self._raise_domain_file_error("uncheckout", program_path)
        keep = self._get_bool(args, "keep", default=False)
        force = self._get_bool(args, "force", default=False)
        if hasattr(domain_file, "undoCheckout"):
            assert domain_file is not None, "domain_file should not be None here since we check and raise above"
            domain_file.undoCheckout(keep, force)
        return create_success_response(
            {
                "operation": "uncheckout",
                "programPath": program_path,
                "keep": keep,
                "force": force,
                "success": True,
            },
        )

    async def _handle_unhijack(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._handle_unhijack")
        program_path: str | None = self._get_str(args, "programpath", "filepath", "file", "path")
        domain_file: GhidraDomainFile | None = self._resolve_domain_file(program_path)
        if domain_file is None:
            self._raise_domain_file_error("unhijack", program_path)
        force = self._get_bool(args, "force", default=False)
        if hasattr(domain_file, "unhijack"):
            domain_file.unhijack(force)
        return create_success_response(
            {
                "operation": "unhijack",
                "programPath": program_path,
                "force": force,
                "success": True,
            },
        )

    def _raise_domain_file_error(self, operation: str, program_path: str | None) -> None:
        """Helper to raise consistent domain file errors for version control operations."""
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._raise_domain_file_error")
        has_program: bool = self.program_info is not None and getattr(self.program_info, "program", None) is not None
        has_df: bool = False
        df_path: str | None = None
        if has_program:
            try:
                assert self.program_info is not None, "program_info should not be None here since has_program is True"
                df: GhidraDomainFile | None = self.program_info.program.getDomainFile()
                has_df = df is not None
                df_path = str(df.getPathname()) if df else None
            except Exception:
                pass
        pd: GhidraProjectData | None = self._get_active_project_data()
        raise ActionableError(
            "No project-backed domain file found for the requested programPath",
            context={
                "operation": operation,
                "programPath": program_path,
                "diagnostics": {
                    "hasActiveProgram": has_program,
                    "activeDomainFile": has_df,
                    "activeDomainFilePath": df_path,
                    "hasProjectData": pd is not None,
                },
            },
            next_steps=[
                "If this target is a local binary, call `import-binary` first. If it is a project/repository path, call `open` to establish the project-backed session.",
                "Call `list-project-files` to confirm the program exists in the current project/session.",
            ],
        )

    async def _handle_mkdir(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._handle_mkdir")
        return await self._handle_filesystem_operation_blocked(args)

    async def _handle_touch(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._handle_touch")
        return await self._handle_filesystem_operation_blocked(args)

    async def _handle_list_files(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._handle_list_files")
        file_path: str | None = self._get_str(args, "filepath", "file", "path", "programpath")
        res = self._get_int(args, "maxresults", default=200)
        max_results = 200 if res is None else res
        base_path = Path(file_path).expanduser().resolve() if file_path else Path.cwd()
        if not base_path.exists():
            manage_files_tool = recommend_tool(Tool.MANAGE_FILES.value, Tool.LIST_PROJECT_FILES.value)
            steps = [
                "Run `{}` `mode=list` on the parent directory to discover valid paths.".format(manage_files_tool or Tool.LIST_PROJECT_FILES.value),
                "Retry with an existing directory path.",
            ]
            raise ActionableError(
                f"Path not found: {base_path}",
                context={"operation": "list", "path": str(base_path), "state": "path-not-found"},
                next_steps=filter_recommendations(steps),
            )
        if not base_path.is_dir():
            raise ActionableError(
                f"Path is not a directory: {base_path}",
                context={"operation": "list", "path": str(base_path), "state": "path-type-mismatch"},
                next_steps=[
                    "Use a directory path for filesystem listing.",
                    "Use `mode=list` only with directory paths.",
                ],
            )

        entries: list[dict[str, Any]] = []
        for item in sorted(base_path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))[:max_results]:
            entries.append(
                {
                    "name": item.name,
                    "path": str(item),
                    "isDirectory": item.is_dir(),
                    "size": None if item.is_dir() else item.stat().st_size,
                },
            )
        return create_success_response(
            {
                "operation": "list",
                "path": str(base_path),
                "entries": entries,
                "count": len(entries),
                "maxResults": max_results,
            },
        )

    async def _handle_info(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._handle_info")
        return await self._handle_filesystem_operation_blocked(args)

    async def _handle_read(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._handle_read")
        return await self._handle_filesystem_operation_blocked(args)

    async def _handle_write(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._handle_write")
        return await self._handle_filesystem_operation_blocked(args)

    async def _handle_append(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._handle_append")
        return await self._handle_filesystem_operation_blocked(args)

    async def _handle_rename(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._handle_rename")
        program_path: str | None = self._get_str(args, "programpath", "filepath", "file", "path")
        if not program_path:
            raise ActionableError(
                "path/filePath is required",
                context={"operation": "rename", "state": "missing-path"},
                next_steps=[
                    "Provide a project path such as `/K1/k1_win_gog_swkotor.exe`.",
                    "Use `list-project-files` first to discover valid project paths.",
                ],
            )
        new_name: str | None = self._get_str(args, "newname")
        if not new_name:
            manage_files_tool = recommend_tool(Tool.MANAGE_FILES.value)
            steps = ["Provide `newName` and retry `{}` with `mode=rename`.".format(manage_files_tool or "rename operation")]
            raise ActionableError(
                "newName is required for rename",
                context={"operation": "rename", "state": "missing-parameter", "missingParameter": "newName"},
                next_steps=filter_recommendations(steps),
            )
        if "/" in new_name or "\\" in new_name:
            raise ActionableError(
                "newName must be a file name only (no folder separators)",
                context={"operation": "rename", "newName": new_name, "state": "invalid-name"},
                next_steps=[
                    "For path relocation use `mode=move` with `newPath`.",
                    "Use `newName` with just the filename component.",
                ],
            )

        domain_file: GhidraDomainFile | None = self._resolve_domain_file(program_path)
        if domain_file is None:
            self._raise_domain_file_error("rename", program_path)

        assert domain_file is not None, "domain_file should not be None here since we check and raise above"
        old_path = str(domain_file.getPathname()) if hasattr(domain_file, "getPathname") else str(program_path)
        try:
            if hasattr(domain_file, "setName"):
                domain_file.setName(new_name)
            elif hasattr(domain_file, "rename"):
                domain_file.rename(new_name)
            else:
                raise RuntimeError("Domain file rename API unavailable")
        except Exception as exc:
            raise ActionableError(
                f"Failed to rename project domain file: {exc}",
                context={"operation": "rename", "path": old_path, "newName": new_name},
                next_steps=[
                    "Verify the target program is project-backed and checked out if required.",
                    "Retry rename with the exact path from `list-project-files`.",
                ],
            ) from exc

        new_path = str(domain_file.getPathname()) if hasattr(domain_file, "getPathname") else old_path
        return create_success_response({"operation": "rename", "scope": "project-domain", "path": old_path, "newPath": new_path, "success": True})

    async def _handle_delete(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._handle_delete")
        program_path: str | None = self._get_str(args, "programpath", "filepath", "file", "path")
        if not program_path:
            raise ActionableError(
                "path/filePath is required",
                context={"operation": "delete", "state": "missing-path"},
                next_steps=[
                    "Provide a project path such as `/K1/k1_win_gog_swkotor.exe`.",
                    "Use `list-project-files` first to discover valid project paths.",
                ],
            )

        domain_file: GhidraDomainFile | None = self._resolve_domain_file(program_path)
        if domain_file is None:
            self._raise_domain_file_error("delete", program_path)

        assert domain_file is not None, "domain_file should not be None here since we check and raise above"
        target_path: str = str(domain_file.getPathname()) if hasattr(domain_file, "getPathname") else str(program_path)
        try:
            deleted = bool(domain_file.delete()) if hasattr(domain_file, "delete") else False
        except Exception as exc:
            raise ActionableError(
                f"Failed to delete project domain file: {exc}",
                context={"operation": "delete", "path": target_path},
                next_steps=[
                    "Verify the target program is project-backed and checked out if required.",
                    "Retry delete with the exact path from `list-project-files`.",
                ],
            ) from exc

        return create_success_response({"operation": "delete", "scope": "project-domain", "path": target_path, "success": deleted})

    async def _handle_copy(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._handle_copy")
        return await self._handle_filesystem_operation_blocked(args)

    async def _handle_move(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._handle_move")
        program_path: str | None = self._get_str(args, "programpath", "filepath", "file", "path")
        if not program_path:
            raise ActionableError(
                "path/filePath is required",
                context={"operation": "move", "state": "missing-path"},
                next_steps=[
                    "Provide a project path such as `/K1/k1_win_gog_swkotor.exe`.",
                    "Use `list-project-files` first to discover valid project paths.",
                ],
            )
        destination: str | None = self._get_str(args, "newpath", "destinationpath")
        if not destination:
            raise ActionableError(
                "newPath/destinationPath is required for move",
                context={"operation": "move", "state": "missing-parameter", "missingParameter": "newPath|destinationPath"},
                next_steps=["Provide `newPath` (or `destinationPath`) and retry `mode=move`."],
            )

        domain_file: GhidraDomainFile | None = self._resolve_domain_file(program_path)
        if domain_file is None:
            self._raise_domain_file_error("move", program_path)

        project_data: GhidraProjectData | None = self._get_active_project_data()
        if project_data is None:
            raise ActionableError(
                "No active project context available for move",
                context={"operation": "move", "programPath": program_path, "state": "missing-project-data"},
                next_steps=[
                    "Open a project-backed program first.",
                    "Retry with a valid path from `list-project-files`.",
                ],
            )

        destination_folder_hint: str = self._get_str(args, "destinationfolder")
        normalized_destination: str = self._normalize_repo_path(destination)

        assert domain_file is not None, "domain_file should not be None here since we check and raise above"
        current_name: str = str(domain_file.getName()) if hasattr(domain_file, "getName") else Path(str(program_path)).name
        if destination_folder_hint:
            destination_folder_path = self._normalize_repo_path(destination_folder_hint)
            new_name = current_name
        else:
            destination_folder_path, maybe_name = normalized_destination.rsplit("/", 1)
            destination_folder_path = destination_folder_path or "/"
            new_name = maybe_name or current_name

        destination_folder = self._ensure_project_folder(project_data, destination_folder_path)
        old_path = str(domain_file.getPathname()) if hasattr(domain_file, "getPathname") else str(program_path)

        try:
            if hasattr(domain_file, "moveTo"):
                domain_file.moveTo(destination_folder)
            elif hasattr(domain_file, "move"):
                domain_file.move(destination_folder)
            else:
                raise RuntimeError("Domain file move API unavailable")

            current_after_move: str = str(domain_file.getName()) if hasattr(domain_file, "getName") else current_name
            if new_name and new_name != current_after_move:
                if hasattr(domain_file, "setName"):
                    domain_file.setName(new_name)
                elif hasattr(domain_file, "rename"):
                    domain_file.rename(new_name)
                else:
                    raise RuntimeError("Domain file rename API unavailable after move")
        except Exception as exc:
            raise ActionableError(
                f"Failed to move project domain file: {exc}",
                context={"operation": "move", "path": old_path, "newPath": normalized_destination},
                next_steps=[
                    "Verify the target program is project-backed and checked out if required.",
                    "Retry move with exact source and destination project paths.",
                ],
            ) from exc

        new_path = str(domain_file.getPathname()) if hasattr(domain_file, "getPathname") else normalized_destination
        return create_success_response({"operation": "move", "scope": "project-domain", "path": old_path, "newPath": new_path, "success": True})

    async def _handle_sync_project(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._handle_sync_project")
        return await self._sync_shared_repository(args, default_mode="pull")

    async def _handle_switch_project(self, args: dict[str, Any]) -> list[types.TextContent]:
        """Switch between project modes without restarting the server.

        mode='download': connect to configured shared Ghidra server, pull all
            files to the local project, then clear the shared-session handle so
            subsequent tools operate on the local copy.
        mode='local':    open a local binary / .gpr project (same as open
            with a path arg).
        mode='shared':   (re)connect to the shared Ghidra server (same as
            connect-shared-project).

        Credentials are resolved from: explicit args → request auth context →
        AGENT_DECOMPILE_GHIDRA_SERVER_* environment variables.
        """
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._handle_switch_project")
        mode: str = n(self._get_str(args, "mode", default="download"))
        if mode in {"local", "openlocal", "localproject"}:
            return await self._switch_to_local(args)
        if mode in {"shared", "server", "sharedserver", "reconnect", "connectshared"}:
            return await self._switch_to_shared(args)
        # default: download / pull / sync
        return await self._switch_download(args)

    def _resolve_server_credentials(self, args: dict[str, Any]) -> dict[str, Any]:
        """Build a credentials dict by merging args, auth context, and env vars (in that priority order)."""
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._resolve_server_credentials")
        resolved: dict[str, Any] = dict(args)

        # Layer 2: auth context
        try:
            from agentdecompile_cli.mcp_server.auth import get_current_auth_context  # noqa: PLC0415

            _auth_ctx = get_current_auth_context()
            if _auth_ctx is not None:
                if not resolved.get("serverhost") and _auth_ctx.server_host:
                    resolved["serverhost"] = _auth_ctx.server_host
                if not resolved.get("serverport") and _auth_ctx.server_port:
                    resolved["serverport"] = _auth_ctx.server_port
                if not resolved.get("serverusername") and _auth_ctx.username:
                    resolved["serverusername"] = _auth_ctx.username
                if not resolved.get("serverpassword") and _auth_ctx.password is not None:
                    resolved["serverpassword"] = _auth_ctx.password
                if not resolved.get("path") and _auth_ctx.repository:
                    resolved["path"] = _auth_ctx.repository
        except Exception:
            pass

        # Layer 3: environment variables
        if not resolved.get("serverhost"):
            resolved["serverhost"] = os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_HOST", "") or os.environ.get("AGENT_DECOMPILE_SERVER_HOST", "")
        if not resolved.get("serverport"):
            _port_str = os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_PORT", "") or os.environ.get("AGENT_DECOMPILE_SERVER_PORT", "")
            if _port_str:
                resolved["serverport"] = _port_str
        if not resolved.get("serverusername"):
            resolved["serverusername"] = os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME", "") or os.environ.get("AGENT_DECOMPILE_SERVER_USERNAME", "")
        if not resolved.get("serverpassword"):
            resolved["serverpassword"] = os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD", "") or os.environ.get("AGENT_DECOMPILE_SERVER_PASSWORD", "")
        if not resolved.get("path"):
            _repo = os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY", "") or os.environ.get("AGENT_DECOMPILE_REPOSITORY", "")
            if _repo:
                resolved["path"] = _repo

        return resolved

    async def _switch_to_shared(self, args: dict[str, Any]) -> list[types.TextContent]:
        """(Re)connect to the shared Ghidra server and store session handle."""
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._switch_to_shared")
        resolved: dict[str, Any] = self._resolve_server_credentials(args)
        return await self._handle_connect_shared_project(resolved)

    async def _switch_to_local(self, args: dict[str, Any]) -> list[types.TextContent]:
        """Open a local project/binary and clear any shared-server session handle."""
        # Clear shared handle so the session is fully local
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._switch_to_local")
        session_id: str = get_current_mcp_session_id()
        SESSION_CONTEXTS.set_project_handle(session_id, None)

        local_path: str = self._get_str(args, "localpath", "filepath", "path")
        if not local_path:
            return create_success_response(
                {
                    "action": "switch-project",
                    "mode": "local",
                    "success": False,
                    "error": "No local path provided. Pass 'path' or 'localPath' pointing to a binary or .gpr file.",
                    "nextSteps": [
                        "Retry with 'path=/path/to/binary' or 'path=/path/to/project.gpr'.",
                    ],
                },
            )
        open_args = dict(args)
        open_args["path"] = local_path
        result = await self._handle_open(open_args)
        return result

    async def _switch_download(self, args: dict[str, Any]) -> list[types.TextContent]:
        """Connect to shared server, pull all files to local project, then go-local."""
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._switch_download")
        resolved: dict[str, Any] = self._resolve_server_credentials(args)

        if not resolved.get("serverhost"):
            return create_success_response(
                {
                    "action": "switch-project",
                    "mode": "download",
                    "success": False,
                    "error": ("Cannot determine shared Ghidra server host. Pass 'serverHost' explicitly or set AGENT_DECOMPILE_GHIDRA_SERVER_HOST."),
                    "nextSteps": [
                        "Call switch-project with serverHost='<ghidra-server-host>' and serverUsername/serverPassword.",
                        "Or set AGENT_DECOMPILE_GHIDRA_SERVER_HOST / _USERNAME / _PASSWORD environment variables.",
                    ],
                },
            )

        # Step 1: connect to shared server (populates session handle + repo adapter)
        connect_result: list[types.TextContent] = await self._handle_connect_shared_project(resolved)
        session_id, handle, repository_adapter, repository_name = self._get_shared_session_context()

        connect_success: bool = bool(handle and is_shared_server_handle(handle))
        if not connect_success:
            return create_success_response(
                {
                    "action": "switch-project",
                    "mode": "download",
                    "success": False,
                    "error": "Failed to connect to shared Ghidra server. See connectResult for details.",
                    "connectResult": [t.text if hasattr(t, "text") else str(t) for t in connect_result],
                    "nextSteps": [
                        "Verify serverHost, serverPort, serverUsername, serverPassword.",
                        "Ensure the Ghidra server is reachable.",
                    ],
                },
            )

        # Step 2: pull all files from shared to local
        sync_result: list[types.TextContent] = await self._sync_shared_repository(resolved, default_mode="pull")

        # Step 3: clear the shared-server handle so the session is now local
        SESSION_CONTEXTS.set_project_handle(session_id, None)

        # Build a combined summary response
        sync_data: dict[str, Any] = {}
        for item in sync_result:
            if hasattr(item, "text"):
                try:
                    import json  # noqa: PLC0415

                    sync_data = json.loads(item.text)
                except Exception:
                    pass
                break

        return create_success_response(
            {
                "action": "switch-project",
                "mode": "download",
                "success": sync_data.get("success", True),
                "repository": repository_name,
                "serverHost": resolved.get("serverhost", ""),
                "localMode": True,
                "note": ("Shared project pulled to local. Session is now operating in local mode. Call switch-project(mode='shared') at any time to reconnect to the shared server."),
                "syncSummary": {
                    "requested": sync_data.get("requested", 0),
                    "transferred": sync_data.get("transferred", 0),
                    "skipped": sync_data.get("skipped", 0),
                    "errors": sync_data.get("errors", []),
                },
            },
        )

    def _resolve_domain_file(self, program_path: str | None) -> GhidraDomainFile | None:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._resolve_domain_file")
        if not program_path:
            if self.program_info is not None and getattr(self.program_info, "program", None) is not None:
                try:
                    return self.program_info.program.getDomainFile()
                except Exception:
                    return None
            return None

        try:
            normalized = str(program_path).strip()
            # Check active program's domain file first
            if self.program_info is not None and getattr(self.program_info, "program", None) is not None:
                try:
                    current_df = self.program_info.program.getDomainFile()
                except Exception:
                    current_df = None
                if current_df is not None:
                    current_path = str(current_df.getPathname())
                    if current_path == normalized or current_path.lstrip("/") == normalized.lstrip("/"):
                        return current_df
                    logger.debug("_resolve_domain_file: active DF path='%s' != requested='%s'", current_path, normalized)

            # Try project_data.getFile() from active program
            project_data: GhidraProjectData | None = self._get_active_project_data()
            logger.debug("_resolve_domain_file: project_data=%s", type(project_data).__name__ if project_data else None)
            if project_data is not None:
                df = project_data.getFile(normalized)
                if df is not None:
                    return df
                # Try with leading slash normalized
                if not normalized.startswith("/"):
                    df = project_data.getFile(f"/{normalized}")
                    if df is not None:
                        return df

            # Fallback: try from session context project handle (shared-server mode)
            session_id: str = get_current_mcp_session_id()
            session: SessionContext = SESSION_CONTEXTS.get_or_create(session_id)
            handle: dict[str, Any] | None = session.project_handle if isinstance(session.project_handle, dict) else None
            if handle and project_data is None:
                # No project data found through normal paths; try to get it from
                # the active program's domain file or root project
                logger.debug("_resolve_domain_file: trying session-context fallback for '%s'", normalized)
                if self.program_info is not None and getattr(self.program_info, "program", None) is not None:
                    try:
                        df_check = self.program_info.program.getDomainFile()
                        if df_check is not None:
                            pd = df_check.getProjectData()
                            if pd is not None:
                                result = pd.getFile(normalized)
                                if result is not None:
                                    return result
                    except Exception as exc:
                        logger.debug("session-context fallback failed: %s", exc)

            return None
        except Exception as exc:
            logger.debug("_resolve_domain_file exception: %s", exc)
            return None

    async def _import_file(self, file_path: str, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._import_file")
        session_id: str = get_current_mcp_session_id()
        enable_version_control: bool = self._get_bool(args, "enableversioncontrol", default=False)
        if enable_version_control:
            return create_success_response(
                {
                    "operation": "import",
                    "importedFrom": file_path,
                    "versionControlRequested": True,
                    "versionControlEnabled": False,
                    "success": False,
                    "error": "Automatic promotion of a local import into shared-project version control is not implemented for open local imports. Connect to a shared server first and use a shared-backed workflow.",
                },
            )

        source: Path = Path(file_path).expanduser().resolve()
        if not source.exists():
            raise ValueError(f"Import path not found: {source}")

        recursive: bool = self._get_bool(args, "recursive", default=source.is_dir())
        res = self._get_int(args, "maxdepth", default=16)
        max_depth: int = 16 if res is None else res
        analyze: bool = self._get_bool(args, "analyzeafterimport", default=True)

        discovered: list[Path] = []
        if source.is_file():
            discovered = [source]
        else:
            root_depth = len(source.parts)
            for candidate in source.rglob("*"):
                if not candidate.is_file():
                    continue
                if not recursive and candidate.parent != source:
                    continue
                if len(candidate.parts) - root_depth > max_depth:
                    continue
                discovered.append(candidate)

        imported: list[dict[str, Any]] = []
        imported_count: int = 0
        errors: list[dict[str, Any]] = []
        imported_session_binaries: list[dict[str, Any]] = []

        project_handle: dict | None = None
        ghidra_project: GhidraProject | None = getattr(self._manager, "ghidra_project", None) if self._manager else None
        if ghidra_project is not None:
            project_handle = ghidra_project
            try:
                if not hasattr(project_handle, "importProgram"):
                    project_handle = ghidra_project.getProject()
            except Exception:
                pass

        for entry in discovered:
            try:
                from java.io import File as JavaFile  # pyright: ignore[reportMissingImports]

                if project_handle is None:
                    raise RuntimeError("No active Ghidra project context available for import")

                program: GhidraProgram = project_handle.importProgram(JavaFile(str(entry)))
                if program is None:
                    raise RuntimeError("import_binary returned None")

                from agentdecompile_cli.launcher import ProgramInfo
                from agentdecompile_cli.mcp_utils.decompiler_util import open_decompiler_for_program

                decompiler = None
                try:
                    decompiler = open_decompiler_for_program(program)
                except Exception as dec_exc:
                    logger.warning(
                        "import_binary decompiler_open_failed path_tail=%s exc_type=%s",
                        basename_hint(str(entry)),
                        type(dec_exc).__name__,
                    )

                program_path: str = str(program.getDomainFile().getPathname()) if program.getDomainFile() else str(entry)
                program_info = ProgramInfo(
                    name=program.getName(),
                    program=program,
                    flat_api=None,
                    decompiler=decompiler,
                    metadata={},
                    ghidra_analysis_complete=True,
                    file_path=Path(str(entry)),
                    load_time=time.time(),
                )
                SESSION_CONTEXTS.set_active_program_info(session_id, program_path, program_info)
                if self._manager is not None:
                    self._manager.set_program_info(program_info)
                else:
                    self.set_program_info(program_info)

                imported_count += 1
                imported.append({"path": str(entry), "programName": program.getName() if hasattr(program, "getName") else entry.name})
                imported_session_binaries.append(
                    {
                        "path": program_path,
                        "name": program.getName() if hasattr(program, "getName") else entry.name,
                        "type": "Program",
                        "sourcePath": str(entry),
                    },
                )
            except Exception as exc:
                errors.append({"path": str(entry), "error": str(exc)})

        if imported_session_binaries:
            existing_binaries = SESSION_CONTEXTS.get_project_binaries(session_id)
            merged_by_path: dict[str, dict[str, Any]] = {}
            for item in existing_binaries:
                item_path = str(item.get("path") or "")
                if item_path:
                    merged_by_path[item_path] = dict(item)
            for item in imported_session_binaries:
                merged_by_path[str(item["path"])] = item
            SESSION_CONTEXTS.set_project_binaries(session_id, list(merged_by_path.values()))

        return create_success_response(
            {
                "operation": "import",
                "importedFrom": str(source),
                "filesDiscovered": len(discovered),
                "filesImported": imported_count,
                "importedPrograms": imported,
                "groupsCreated": 0,
                "maxDepthUsed": max_depth,
                "wasRecursive": recursive,
                "analysisRequested": analyze,
                "errors": errors,
            },
        )

    async def _export_current_program(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._export_current_program")
        if self.program_info is None:
            raise ValueError("No program loaded for export")

        out_path = self._get_str(args, "newpath", "destinationpath", "path", "filepath")
        if not out_path:
            raise ValueError("path/newPath is required for export")

        output: Path = Path(out_path).expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)

        program: GhidraProgram = self.program_info.program
        payload: dict[str, Any] = {
            "name": program.getName(),
            "path": str(program.getDomainFile().getPathname()) if program.getDomainFile() else None,
            "language": str(program.getLanguage().getLanguageID()),
            "compiler": str(program.getCompilerSpec().getCompilerSpecID()),
            "imageBase": str(program.getImageBase()),
            "functionCount": self._get_function_manager(program).getFunctionCount(),
        }
        output.write_text(str(payload), encoding="utf-8")

        return create_success_response({"operation": "export", "program": program.getName(), "outputPath": str(output), "success": True})

    def _normalize_repo_path(self, value: str | None, default: str = "/") -> str:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._normalize_repo_path")
        normalized = (value or default).strip()
        if not normalized:
            normalized = default
        if not normalized.startswith("/"):
            normalized = f"/{normalized}"
        while "//" in normalized:
            normalized = normalized.replace("//", "/")
        if len(normalized) > 1:
            normalized = normalized.rstrip("/")
        return normalized

    def _path_in_scope(self, item_path: str, source_folder: str, recursive: bool) -> bool:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._path_in_scope")
        path: str = self._normalize_repo_path(item_path)
        source: str = self._normalize_repo_path(source_folder)
        if source == "/":
            if recursive:
                return True
            parent = path.rsplit("/", 1)[0] or "/"
            return parent == "/"

        if recursive:
            return path == source or path.startswith(f"{source}/")

        parent = path.rsplit("/", 1)[0] or "/"
        return parent == source

    def _map_repo_path_to_local(self, repo_path: str, source_folder: str, destination_folder: str) -> str:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._map_repo_path_to_local")
        source: str = self._normalize_repo_path(source_folder)
        destination: str = self._normalize_repo_path(destination_folder)
        path: str = self._normalize_repo_path(repo_path)

        relative: str = path.lstrip("/")
        if source != "/":
            prefix = f"{source}/"
            if path.startswith(prefix):
                relative = path[len(prefix) :]

        if destination == "/":
            return self._normalize_repo_path(f"/{relative}")
        return self._normalize_repo_path(f"{destination}/{relative}")

    def _get_active_project_data(self) -> GhidraProjectData | None:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._get_active_project_data")
        logger.info("shared-sync getting active project data start")
        ghidra_project: GhidraProject | None = getattr(self._manager, "ghidra_project", None) if self._manager else None
        if ghidra_project is not None:
            try:
                project_data = ghidra_project.getProject().getProjectData()
                logger.info("shared-sync got project data from ghidra_project.getProject().getProjectData()")
                return project_data
            except Exception:
                try:
                    project_data = ghidra_project.getProjectData()
                    logger.info("shared-sync got project data from ghidra_project.getProjectData()")
                    return project_data
                except Exception:
                    logger.info("shared-sync failed to get project data from ghidra_project")

        if self.program_info is not None and getattr(self.program_info, "program", None) is not None:
            try:
                prog: GhidraProgram = self.program_info.program
                domain_file: GhidraProjectData = prog.getDomainFile()
                if domain_file is not None:
                    project_data = domain_file.getProjectData()
                    logger.info("shared-sync got project data from program_info domain_file")
                    return project_data
            except Exception:
                logger.info("shared-sync failed to get project data from program_info")

        logger.info("shared-sync no active project data found")
        return None

    @staticmethod
    def _domain_file_folder_path_and_name(domain_file: GhidraDomainFile) -> tuple[str, str]:
        """Split DomainFile pathname into Ghidra folder path and program name for openProgram(String, String, boolean).

        Ghidra builds the lookup path as ``folderPath + SEPARATOR + programName``. Using ``"/"`` as folder for
        root files yields ``//name``, which can resolve incorrectly; root folder must be ``""``.
        """
        pn = ""
        try:
            pn = str(domain_file.getPathname() or "").replace("\\", "/").strip()
        except Exception:
            pn = ""
        name = ""
        try:
            name = str(domain_file.getName() or "").strip()
        except Exception:
            name = ""
        if not name and pn:
            name = Path(pn).name
        if not pn:
            return "", name
        body = pn.strip("/")
        if "/" not in body:
            return "", name or body
        parent_body, basename = body.rsplit("/", 1)
        name = name or basename
        parent = f"/{parent_body}" if parent_body else ""
        return parent, name

    def _ghidra_project_open_program_compat(self, ghidra_project: GhidraProject, domain_file: GhidraDomainFile) -> GhidraProgram | None:
        """Open a program from a DomainFile; JPype/Ghidra 12 may not expose openProgram(DomainFile)."""
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._ghidra_project_open_program_compat")
        if ghidra_project is None or domain_file is None:
            return None
        try:
            opened = ghidra_project.openProgram(domain_file)
            if opened is not None:
                return opened
        except Exception:
            pass
        try:
            folder_path, program_name = self._domain_file_folder_path_and_name(domain_file)
            if not program_name:
                return None
            return ghidra_project.openProgram(folder_path, program_name, False)
        except Exception as exc:
            logger.debug("GhidraProject.openProgram(folder,name,boolean) failed: %s", exc)
            return None

    def _open_program_from_domain_file(self, domain_file: GhidraDomainFile) -> GhidraProgram | None:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._open_program_from_domain_file")
        ghidra_project: GhidraProject | None = getattr(self._manager, "ghidra_project", None) if self._manager else None
        if ghidra_project is not None:
            opened_program = self._ghidra_project_open_program_compat(ghidra_project, domain_file)
            if opened_program is not None:
                return opened_program

        from ghidra.util.task import TaskMonitor as GhidraTaskMonitor  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

        return self._get_domain_object_compat(domain_file, GhidraTaskMonitor.DUMMY)

    def _get_domain_object_compat(self, holder: GhidraDomainFile, monitor: GhidraTaskMonitor) -> GhidraDomainObject | None:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._get_domain_object_compat")
        consumers: list[Any] = [self]
        try:
            from java.lang import Object as JavaObject  # pyright: ignore[reportMissingImports]

            consumers.append(JavaObject())
        except Exception:
            pass
        consumers.append(None)

        last_error: Exception | None = None
        for consumer in consumers:
            attempts = [
                (consumer, True, False, monitor),
                (consumer, True, monitor),
                (consumer, False, monitor),
                (consumer, monitor),
                (consumer, True, False),
                (consumer, True),
                (consumer,),
            ]
            for call_args in attempts:
                try:
                    return holder.getDomainObject(*call_args)
                except Exception as exc:
                    last_error = exc

        if last_error is not None:
            raise last_error
        raise RuntimeError("Unable to open domain object")

    def _set_active_program_info(self, program: GhidraProgram, program_path: str) -> None:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._set_active_program_info")
        from ghidra.app.decompiler import DecompInterface, DecompileOptions  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

        from agentdecompile_cli.launcher import ProgramInfo

        decompiler = DecompInterface()
        decomp_options = DecompileOptions()
        decomp_options.grabFromProgram(program)
        decompiler.setOptions(decomp_options)
        decompiler.openProgram(program)

        session_id: str = get_current_mcp_session_id()
        prev_key = SESSION_CONTEXTS.get_active_program_key(session_id)
        program_info = ProgramInfo(
            name=program.getName(),
            program=program,
            flat_api=None,
            decompiler=decompiler,
            metadata={},
            ghidra_analysis_complete=True,
            file_path=None,
            load_time=time.time(),
        )

        SESSION_CONTEXTS.set_active_program_info(session_id, program_path, program_info)
        if prev_key != program_path:
            pname = program.getName() if hasattr(program, "getName") else None
            logger.info(
                "active_program_changed session_id=%s prev_tail=%s next_tail=%s name=%s",
                redact_session_id(session_id),
                basename_hint(prev_key),
                basename_hint(program_path),
                pname or basename_hint(program_path),
            )
        if self._manager is not None:
            self._manager.set_program_info(program_info)
        else:
            self.set_program_info(program_info)

    def _ensure_project_folder(self, project_data: GhidraProjectData, folder_path: str):
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._ensure_project_folder")
        normalized: str = self._normalize_repo_path(folder_path)
        if normalized == "/":
            return project_data.getRootFolder()

        folder: GhidraProjectData | None = project_data.getFolder(normalized)
        if folder is not None:
            return folder

        current: GhidraProjectData = project_data.getRootFolder()
        for component in normalized.strip("/").split("/"):
            if not component:
                continue
            child: GhidraProjectData | None = current.getFolder(component)
            if child is None:
                child = current.createFolder(component)
            current = child
        return current

    def _resolve_shared_sync_mode(self, args: dict[str, Any], default_mode: str = "pull") -> str:
        # Check direction-specific keys first, then fall back to generic 'mode'.
        # When routed through manage-files, 'mode' contains the operation alias
        # (e.g. 'pull-shared') which also resolves correctly.
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._resolve_shared_sync_mode")
        requested = self._get_str(args, "syncdirection", "direction", "syncmode", default="")
        if not requested:
            requested = self._get_str(args, "mode", default=default_mode)
        normalized = n(requested)
        logger.info(
            "shared-sync mode resolution requested=%s normalized=%s default=%s",
            requested,
            normalized,
            default_mode,
        )
        if normalized in {"pull", "download", "downloadshared", "pullshared"}:
            logger.info("shared-sync mode resolved to pull")
            return "pull"
        if normalized in {"push", "upload", "uploadshared", "pushshared", "importtoshared"}:
            logger.info("shared-sync mode resolved to push")
            return "push"
        if normalized in {"bidirectional", "both", "sync", "syncshared", "mirror"}:
            logger.info("shared-sync mode resolved to bidirectional")
            return "bidirectional"
        logger.info("shared-sync mode fell back to default=%s", default_mode)
        return default_mode

    def _get_shared_session_context(self) -> tuple[str, dict[str, Any] | None, GhidraProject | None, str | None]:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._get_shared_session_context")
        session_id: str = get_current_mcp_session_id()
        session: SessionContext = SESSION_CONTEXTS.get_or_create(session_id)
        handle = session.project_handle if isinstance(session.project_handle, dict) else None
        repository_adapter: GhidraRepositoryAdapter | None = handle.get("repository_adapter") if handle else None
        repository_name: str | None = handle.get("repository_name") if handle else None
        _sid_hint = (session_id[:12] + "…") if session_id and len(session_id) > 12 else (session_id or "—")
        logger.info(
            "shared-sync session context session_id=%s has_handle=%s handle_mode=%s has_repository_adapter=%s repository=%s",
            _sid_hint,
            bool(handle),
            (handle or {}).get("mode") if isinstance(handle, dict) else None,
            repository_adapter is not None,
            repository_name,
        )
        return session_id, handle, repository_adapter, repository_name

    @staticmethod
    def _end_open_transaction_on_program_pull(program: GhidraProgram) -> None:
        if program is None or not (hasattr(program, "getCurrentTransactionInfo") or hasattr(program, "getCurrentTransaction")):
            return
        try:
            tx = program.getCurrentTransactionInfo() if hasattr(program, "getCurrentTransactionInfo") else program.getCurrentTransaction()
            if tx is not None and hasattr(program, "endTransaction"):
                tx_id = int(tx.getID()) if hasattr(tx, "getID") else int(tx)
                program.endTransaction(tx_id, True)
        except Exception as exc:
            logger.debug("Could not end open transaction before sync pull delete: %s", exc)

    @staticmethod
    def _end_open_transactions_on_domain_file_pull(domain_file: GhidraDomainFile) -> None:
        """End Program transactions for Ghidra consumers of this DomainFile (mirrors import_export)."""
        if domain_file is None or not hasattr(domain_file, "getConsumers"):
            return
        try:
            consumers = domain_file.getConsumers()
            if consumers is None:
                return
            for obj in consumers:
                if obj is None:
                    continue
                if (hasattr(obj, "getCurrentTransactionInfo") or hasattr(obj, "getCurrentTransaction")) and hasattr(obj, "endTransaction"):
                    try:
                        tx = obj.getCurrentTransactionInfo() if hasattr(obj, "getCurrentTransactionInfo") else obj.getCurrentTransaction()
                        if tx is not None:
                            tx_id = int(tx.getID()) if hasattr(tx, "getID") else int(tx)
                            obj.endTransaction(tx_id, True)
                    except Exception as inner_exc:
                        logger.debug("Could not end transaction on domain consumer: %s", inner_exc)
        except Exception as exc:
            logger.debug("Could not iterate DomainFile consumers: %s", exc)

    @staticmethod
    def _domain_file_path_key(domain_file: GhidraDomainFile) -> str:
        try:
            return str(domain_file.getPathname() or "").strip().replace("\\", "/").lower()
        except Exception:
            return ""

    def _domain_files_same_pull(self, a: GhidraDomainFile, b: GhidraDomainFile) -> bool:
        if a is None or b is None:
            return False
        if a is b:
            return True
        pa = self._domain_file_path_key(a)
        pb = self._domain_file_path_key(b)
        if bool(pa) and pa == pb:
            return True
        try:
            na = str(a.getName() or "").strip().lower()
        except Exception:
            na = ""
        try:
            nb = str(b.getName() or "").strip().lower()
        except Exception:
            nb = ""
        if na and na == nb:
            return True
        ba = Path(pa.replace("\\", "/")).name.lower() if pa else ""
        bb = Path(pb.replace("\\", "/")).name.lower() if pb else ""
        return bool(ba) and ba == bb

    def _invoke_import_export_end_transactions_on_domain_file(self, domain_file: GhidraDomainFile) -> None:
        """Drain nested Program transactions on DomainFile consumers (sync push save() needs no active tx)."""
        mgr = self._manager
        if mgr is None or domain_file is None:
            return
        try:
            for pr in getattr(mgr, "providers", None) or []:
                fn = getattr(pr, "_end_open_transactions_on_domain_file_consumers", None)
                if callable(fn):
                    fn(domain_file)
                    return
        except Exception as exc:
            logger.debug("import_export domain-file transaction drain: %s", exc)

    def _drain_all_domain_file_handles_for_sync_push(self, source_file: GhidraDomainFile, session_id: str) -> None:
        """Call ``_end_open_transactions_on_domain_file_consumers`` on every DomainFile identity that aliases ``source_file``.

        ``project_data.getFile()`` and ``Program.getDomainFile()`` can be distinct Java objects for the same binary;
        Ghidra attaches open Programs as consumers only on the instance they were opened from, so draining only
        ``source_file`` leaves active transactions on the other handle and ``save()`` fails to lock.
        """
        mgr = self._manager
        if mgr is None or source_file is None:
            return
        consumer_fn = None
        try:
            for pr in getattr(mgr, "providers", None) or []:
                fn = getattr(pr, "_end_open_transactions_on_domain_file_consumers", None)
                if callable(fn):
                    consumer_fn = fn
                    break
        except Exception as exc:
            logger.debug("sync-project push: resolve consumer drain fn: %s", exc)
            return
        if consumer_fn is None:
            return
        seen: set[int] = set()
        frames: list[GhidraDomainFile] = []

        def add_frame(df: GhidraDomainFile) -> None:
            if df is None:
                return
            i = id(df)
            if i in seen:
                return
            seen.add(i)
            frames.append(df)

        add_frame(source_file)
        try:
            session = SESSION_CONTEXTS.get_or_create(session_id)
            for _path_key, info in list((session.open_programs or {}).items()):
                prog = getattr(info, "program", None) or getattr(info, "current_program", None)
                if prog is None or not hasattr(prog, "getDomainFile"):
                    continue
                try:
                    df = prog.getDomainFile()
                except Exception:
                    df = None
                if df is not None and self._domain_files_same_pull(df, source_file):
                    add_frame(df)
            for pr in getattr(mgr, "providers", None) or []:
                opi = getattr(pr, "program_info", None)
                prog = getattr(opi, "program", None) if opi is not None else None
                if prog is None or not hasattr(prog, "getDomainFile"):
                    continue
                try:
                    df = prog.getDomainFile()
                except Exception:
                    df = None
                if df is not None and self._domain_files_same_pull(df, source_file):
                    add_frame(df)
        except Exception as exc:
            logger.debug("sync-project push: collect domain file handles: %s", exc)

        for df in frames:
            try:
                consumer_fn(df)
            except Exception as exc:
                logger.debug("sync-project push: domain consumer drain id=%s: %s", id(df), exc)

    @staticmethod
    def _end_all_transactions_on_program_for_sync_push(program: GhidraProgram, *, max_rounds: int = 64) -> None:
        """Drain nested Ghidra transactions until none remain (tool tx inside GhidraProject batch tx, etc.)."""
        if program is None or not (hasattr(program, "getCurrentTransactionInfo") or hasattr(program, "getCurrentTransaction")):
            return
        for _ in range(max_rounds):
            try:
                tx = program.getCurrentTransactionInfo() if hasattr(program, "getCurrentTransactionInfo") else program.getCurrentTransaction()
                if tx is None:
                    break
                if hasattr(program, "endTransaction"):
                    tx_id = int(tx.getID()) if hasattr(tx, "getID") else int(tx)
                    program.endTransaction(tx_id, True)
            except Exception:
                break

    def _release_one_program_info_pull(self, program_info: ProgramInfo, *, ghidra_project: GhidraProject | None) -> None:
        """Dispose decompiler and release program handles (order matters for DomainFile.delete)."""
        if program_info is None:
            return
        prog = getattr(program_info, "program", None)
        decompiler = getattr(program_info, "decompiler", None)
        if decompiler is not None:
            try:
                decompiler.closeProgram()
            except Exception:
                pass
            try:
                decompiler.dispose()
            except Exception:
                pass
        if prog is None:
            return
        self._end_open_transaction_on_program_pull(prog)
        doc = getattr(program_info, "domain_object_consumer", None)
        consumers_try: list[Any] = []
        if doc is not None:
            consumers_try.append(doc)
        consumers_try.extend([None, ghidra_project])
        for consumer in consumers_try:
            try:
                prog.release(consumer)
                logger.debug("program.release ok consumer=%s", "project" if consumer is not None else "null")
                break
            except Exception as exc:
                logger.debug("program.release failed consumer=%s: %s", consumer, exc)
        if ghidra_project is not None:
            try:
                if hasattr(prog, "isClosed") and not prog.isClosed():
                    ghidra_project.close(prog)
            except Exception as exc:
                logger.debug("ghidra_project.close after release: %s", exc)

    def _release_tool_provider_program_infos_for_domain_file(self, domain_file: GhidraDomainFile) -> None:
        """``checkin-program`` / shared flows may leave ``ToolProvider.program_info`` holding the Program+Decompiler without session.open_programs."""
        mgr = self._manager
        if mgr is None or domain_file is None:
            return
        ghidra_project: GhidraProject | None = getattr(mgr, "ghidra_project", None)
        seen_prog: set[int] = set()
        for provider in getattr(mgr, "providers", None) or []:
            pi: ProgramInfo | None = getattr(provider, "program_info", None)
            if pi is None:
                continue
            prog: GhidraProgram | None = getattr(pi, "program", None)
            if prog is None:
                continue
            pid: int = id(prog)
            if pid in seen_prog:
                continue
            df: GhidraDomainFile | None = prog.getDomainFile()
            if not self._domain_files_same_pull(df, domain_file):
                continue
            seen_prog.add(pid)
            self._release_one_program_info_pull(pi, ghidra_project=ghidra_project)

    def _release_java_consumers_on_domain_file_pull(self, domain_file: GhidraDomainFile) -> None:
        """Release any remaining Ghidra DomainObject consumers (Programs) still attached to the file."""
        if domain_file is None or not hasattr(domain_file, "getConsumers"):
            return
        ghidra_project: GhidraProject | None = getattr(self._manager, "ghidra_project", None) if self._manager else None
        try:
            consumers = domain_file.getConsumers()
        except Exception:
            consumers = None
        if consumers is None:
            return
        for obj in list(consumers):
            if obj is None or not hasattr(obj, "release"):
                continue
            self._end_open_transaction_on_program_pull(obj)
            for consumer in (None, ghidra_project):
                try:
                    obj.release(consumer)
                    break
                except Exception:
                    continue
            if ghidra_project is not None and hasattr(obj, "isClosed") and not obj.isClosed():
                try:
                    ghidra_project.close(obj)
                except Exception:
                    pass

    def _release_versioned_checkout_before_pull_delete(self, domain_file: GhidraDomainFile) -> None:
        """``GhidraFile.delete`` fails while a versioned file is still checked out locally, even with no open Program."""
        if domain_file is None:
            return
        try:
            versioned = bool(domain_file.isVersioned()) if hasattr(domain_file, "isVersioned") else False
            checked_out = bool(domain_file.isCheckedOut()) if hasattr(domain_file, "isCheckedOut") else False
        except Exception:
            return
        if not versioned or not checked_out:
            return
        from ghidra.framework.data import DefaultCheckinHandler  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
        from ghidra.util.task import TaskMonitor  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

        monitor: TaskMonitor = TaskMonitor.DUMMY
        try:
            if hasattr(domain_file, "canCheckin") and domain_file.canCheckin() and hasattr(domain_file, "checkin"):
                handler = DefaultCheckinHandler("AgentDecompile sync-project pull force (pre-delete)", False, False)
                domain_file.checkin(handler, monitor)
                logger.info("shared-sync pull pre-delete: checked in versioned domain file")
                return
        except Exception as exc:
            logger.debug("shared-sync pull pre-delete checkin failed: %s", exc)
        try:
            if hasattr(domain_file, "isCheckedOut") and domain_file.isCheckedOut() and hasattr(domain_file, "undoCheckout"):
                domain_file.undoCheckout(False, True)
                logger.info("shared-sync pull pre-delete: undoCheckout(force) on versioned domain file")
        except Exception as exc:
            logger.warning("shared-sync pull pre-delete undoCheckout failed: %s", exc)

    def _release_all_open_handles_matching_program_basename(self, exe_name: str) -> None:
        """When DomainFile path keys differ between project_data mirror and ``Program.getDomainFile()``, match on program file name."""
        want = (exe_name or "").strip().lower()
        if not want:
            return
        ghidra_project: GhidraProject | None = getattr(self._manager, "ghidra_project", None) if self._manager else None
        seen: set[int] = set()
        session_id = get_current_mcp_session_id()
        session = SESSION_CONTEXTS.get_or_create(session_id)
        keys_to_pop: list[str] = []
        for key, info in list((session.open_programs or {}).items()):
            prog: GhidraProgram | None = getattr(info, "program", None)
            if prog is None:
                continue
            try:
                nm = str(prog.getName() or "").strip().lower()
            except Exception:
                nm = ""
            if nm != want:
                continue
            pid = id(prog)
            if pid in seen:
                keys_to_pop.append(key)
                continue
            seen.add(pid)
            self._release_one_program_info_pull(info, ghidra_project=ghidra_project)
            keys_to_pop.append(key)
        for key in keys_to_pop:
            session.open_programs.pop(key, None)
        if session.active_program_key and session.active_program_key in keys_to_pop:
            session.active_program_key = next(iter(session.open_programs.keys()), None)

        mgr = self._manager
        if mgr is not None:
            for provider in mgr.providers:
                pi: ProgramInfo | None = getattr(provider, "program_info", None)
                if pi is None:
                    continue
                prog: GhidraProgram | None = getattr(pi, "program", None)
                if prog is None:
                    continue
                try:
                    nm = str(prog.getName() or "").strip().lower()
                except Exception:
                    nm = ""
                if nm != want:
                    continue
                pid = id(prog)
                if pid in seen:
                    continue
                seen.add(pid)
                self._release_one_program_info_pull(pi, ghidra_project=ghidra_project)

    def _release_session_programs_for_domain_file(
        self,
        *,
        session_id: str,
        domain_file: GhidraDomainFile,
    ) -> None:
        """Close and release Ghidra Programs using this DomainFile so ``delete()`` / replace does not raise FileInUseException."""
        if domain_file is None:
            return
        self._end_open_transactions_on_domain_file_pull(domain_file)
        self._release_tool_provider_program_infos_for_domain_file(domain_file)
        try:
            pn = str(domain_file.getPathname() or "").strip().replace("\\", "/")
        except Exception:
            pn = ""
        tail = Path(pn).name if pn else ""
        if tail:
            self._remove_shared_session_item(session_id, tail)
        no_slash: str = pn.lstrip("/")
        if no_slash and no_slash != tail:
            self._remove_shared_session_item(session_id, no_slash)
        try:
            exn = str(domain_file.getName() or "").strip()
        except Exception:
            exn = ""
        if exn:
            self._release_all_open_handles_matching_program_basename(exn)
        self._release_java_consumers_on_domain_file_pull(domain_file)

    def _pull_shared_repository_to_local(
        self,
        args: dict[str, Any],
        repository_adapter: GhidraRepositoryAdapter,
        repository_name: str | None,
        project_data: GhidraProjectData,
    ) -> dict[str, Any]:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._pull_shared_repository_to_local")
        start_time = time.time()
        source_folder = self._normalize_repo_path(
            self._get_str(args, "path", "sourcepath", "folder", default="/"),
        )
        destination_folder = self._normalize_repo_path(
            self._get_str(args, "newpath", "destinationpath", "destinationfolder", default="/"),
        )
        recursive: bool = self._get_bool(args, "recursive", default=True)
        res = self._get_int(args, "maxresults", "limit", default=100000)
        max_results: int = 100000 if res is None or res <= 0 else res
        force: bool = self._get_bool(args, "force", default=False)
        dry_run: bool = self._get_bool(args, "dryrun", default=False)
        logger.info(
            "shared-sync pull start repository=%s source_folder=%s destination_folder=%s recursive=%s max_results=%s force=%s dry_run=%s",
            repository_name,
            source_folder,
            destination_folder,
            recursive,
            max_results,
            force,
            dry_run,
        )

        from ghidra.util.task import TaskMonitor as GhidraTaskMonitor  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

        session_id: str = get_current_mcp_session_id()
        items: list[dict[str, Any]] = SESSION_CONTEXTS.get_project_binaries(session_id, fallback_to_latest=False)
        logger.info("shared-sync pull fetched cached session items count=%s", len(items))
        if not items:
            logger.info("shared-sync pull cache empty, listing repository items from adapter")
            items = self._list_repository_items(repository_adapter)
        logger.info("shared-sync pull source items total=%s", len(items))

        candidates: list[dict[str, Any]] = []
        logger.info("shared-sync pull filtering candidates start source_folder=%s recursive=%s", source_folder, recursive)
        for item in items:
            item_path = str(item.get("path") or "")
            if item_path and self._path_in_scope(item_path, source_folder, recursive):
                candidates.append(item)
        logger.info("shared-sync pull candidates after scope filter=%s", len(candidates))

        if max_results > 0:
            candidates = candidates[:max_results]
            logger.info("shared-sync pull candidates after max_results clamp=%s", len(candidates))

        monitor: GhidraTaskMonitor = GhidraTaskMonitor.DUMMY
        transferred: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        heartbeat_interval = 10

        logger.info("shared-sync pull starting transfer loop total_candidates=%s", len(candidates))
        for index, item in enumerate(candidates, start=1):
            repo_path: str = self._normalize_repo_path(str(item.get("path") or ""))
            if not repo_path or repo_path == "/":
                logger.debug("shared-sync pull skipping empty/root repo_path at index=%s", index)
                continue

            if index == 1 or index % heartbeat_interval == 0:
                logger.info(
                    "shared-sync pull progress index=%s total=%s transferred=%s skipped=%s errors=%s elapsed_sec=%.2f",
                    index,
                    len(candidates),
                    len(transferred),
                    len(skipped),
                    len(errors),
                    time.time() - start_time,
                )

            target_path: str = self._map_repo_path_to_local(repo_path, source_folder, destination_folder)
            existing: GhidraDomainFile | None = project_data.getFile(target_path)
            if existing is not None and not force:
                logger.debug("shared-sync pull skip already exists source=%s target=%s", repo_path, target_path)
                skipped.append({"sourcePath": repo_path, "targetPath": target_path, "reason": "already-exists"})
                continue

            if dry_run:
                logger.info("shared-sync pull dry-run planned source=%s target=%s", repo_path, target_path)
                transferred.append({"sourcePath": repo_path, "targetPath": target_path, "planned": True})
                continue

            parts = repo_path.rsplit("/", 1)
            if len(parts) == 2:
                repo_folder = parts[0] or "/"
                item_name = parts[1]
            else:
                repo_folder = "/"
                item_name = parts[0]
            target_parent_path = target_path.rsplit("/", 1)[0] or "/"

            try:
                if existing is not None and force and hasattr(existing, "delete"):
                    logger.info("shared-sync pull deleting existing target due to force target=%s", target_path)
                    self._release_session_programs_for_domain_file(session_id=session_id, domain_file=existing)
                    try:
                        ex_name = str(existing.getName() or "").strip()
                    except Exception:
                        ex_name = ""
                    if ex_name:
                        self._release_all_open_handles_matching_program_basename(ex_name)
                    self._release_versioned_checkout_before_pull_delete(existing)
                    self._release_java_consumers_on_domain_file_pull(existing)
                    existing.delete()

                parent_folder: GhidraDomainFolder | GhidraProjectData = self._ensure_project_folder(project_data, target_parent_path)
                remote_domain_obj: GhidraDomainObject | None = None
                repo_item: GhidraRepositoryItem | None = None

                # Strategy 1: Open via project_data DomainFile (works when files are
                # already visible through the shared-server project connection).
                try:
                    source_df = project_data.getFile(repo_path)
                    if source_df is not None:
                        logger.info("shared-sync pull strategy=project_data_domain_file source=%s", repo_path)
                        remote_domain_obj = self._get_domain_object_compat(source_df, monitor)
                except Exception:
                    logger.info("shared-sync pull strategy=project_data_domain_file failed source=%s", repo_path, exc_info=True)

                # Strategy 2: Use RepositoryItem if we have a working adapter.
                adapter_folder = repo_folder
                if remote_domain_obj is None:
                    logger.info("shared-sync pull strategy=repository_item source=%s folder=%s item=%s", repo_path, repo_folder, item_name)
                    repo_item = None
                    for fp in repository_adapter_folder_candidates(repo_folder):
                        try:
                            ri = repository_adapter.getItem(fp, item_name)
                            if ri is not None:
                                repo_item = ri
                                adapter_folder = fp
                                break
                        except Exception:
                            continue
                    if repo_item is None:
                        raise ValueError(f"Repository item not found: {repo_path}")
                    # Try DomainFile-style open on the repo item (some Ghidra versions).
                    if hasattr(repo_item, "getDomainObject"):
                        remote_domain_obj = self._get_domain_object_compat(repo_item, monitor)
                    elif hasattr(repo_item, "open"):
                        remote_domain_obj = repo_item.open(monitor)

                # Strategy 3: ProgramDB fallback via adapter's openDatabase.
                if remote_domain_obj is None and hasattr(repository_adapter, "openDatabase"):
                    logger.info("shared-sync pull strategy=programdb_fallback source=%s", repo_path)
                    try:
                        from db import DBHandle  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
                        from ghidra.framework.data import OpenMode as GhidraOpenMode  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
                        from ghidra.program.database import ProgramDB as GhidraProgramDB  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
                        from java.lang import Object as JavaObject  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

                        repo_item = repository_adapter.getItem(adapter_folder, item_name) if repo_item is None else repo_item
                        if repo_item is not None:
                            version = int(repo_item.getVersion()) if hasattr(repo_item, "getVersion") else -1
                            managed_db = repository_adapter.openDatabase(adapter_folder, item_name, version, 0)
                            db_handle = DBHandle(managed_db)
                            try:
                                remote_domain_obj = GhidraProgramDB(db_handle, GhidraOpenMode.UPDATE, monitor, JavaObject())
                            except Exception:
                                remote_domain_obj = GhidraProgramDB(db_handle, GhidraOpenMode.IMMUTABLE, monitor, JavaObject())
                    except Exception:
                        logger.info("shared-sync pull strategy=programdb_fallback failed source=%s", repo_path, exc_info=True)

                if remote_domain_obj is None:
                    raise ValueError(f"Unable to open shared item: {repo_path}")

                try:
                    logger.info("shared-sync pull creating target file source=%s target=%s", repo_path, target_path)
                    parent_folder.createFile(item_name, remote_domain_obj, monitor)
                finally:
                    try:
                        # null consumer: same pattern as project_manager (avoids mismatched JavaObject vs ProgramDB opener)
                        remote_domain_obj.release(None)
                    except Exception:
                        logger.info("shared-sync pull release remote_domain_obj failed source=%s", repo_path, exc_info=True)

                transferred.append({"sourcePath": repo_path, "targetPath": target_path})
                logger.info("shared-sync pull transferred source=%s target=%s", repo_path, target_path)
            except Exception as exc:
                logger.exception("shared-sync pull failed source=%s target=%s error=%s", repo_path, target_path, exc)
                errors.append({"sourcePath": repo_path, "targetPath": target_path, "error": str(exc)})

        logger.info(
            "shared-sync pull complete repository=%s requested=%s transferred=%s skipped=%s errors=%s elapsed_sec=%.2f",
            repository_name,
            len(candidates),
            len(transferred),
            len(skipped),
            len(errors),
            time.time() - start_time,
        )

        # Replacing project files invalidates any in-memory Program still tied to the pre-pull DomainFile.
        # Without this, checkout-program may appear to succeed while edits + checkin-program hit
        # "File has not been modified since checkout" (stale checkout metadata vs. open consumer).
        if not dry_run and transferred:
            for row in transferred:
                if not isinstance(row, dict) or row.get("planned"):
                    continue
                tp = str(row.get("targetPath") or row.get("sourcePath") or "").strip()
                if not tp:
                    continue
                try:
                    self._remove_shared_session_item(session_id, tp)
                except Exception as inv_exc:
                    logger.debug("shared-sync pull session invalidate for %s: %s", tp, inv_exc)

        return {
            "direction": "pull",
            "repository": repository_name,
            "sourceFolder": source_folder,
            "destinationFolder": destination_folder,
            "recursive": recursive,
            "requested": len(candidates),
            "transferred": len(transferred),
            "skipped": len(skipped),
            "errors": errors,
            "items": transferred,
            "skippedItems": skipped,
            "dryRun": dry_run,
        }

    def _push_local_project_to_shared(self, args: dict[str, Any], repository_name: str | None, project_data: GhidraProject) -> dict[str, Any]:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._push_local_project_to_shared")
        start_time = time.time()
        source_folder: str = self._normalize_repo_path(
            self._get_str(args, "path", "sourcepath", "folder", default="/"),
        )
        recursive: bool = self._get_bool(args, "recursive", default=True)
        res = self._get_int(args, "maxresults", "limit", default=100000)
        max_results: int = 0 if res is None else res
        dry_run: bool = self._get_bool(args, "dryrun", default=False)
        logger.info(
            "shared-sync push start repository=%s source_folder=%s recursive=%s max_results=%s dry_run=%s",
            repository_name,
            source_folder,
            recursive,
            max_results,
            dry_run,
        )

        root: GhidraDomainFolder = project_data.getRootFolder()
        local_items: list[dict[str, Any]] = [item for item in self._list_domain_files(root, max_results * 5 if max_results > 0 else 100000) if item.get("type") != "Folder"]
        logger.info("shared-sync push discovered local items=%s", len(local_items))

        candidates: list[dict[str, Any]] = []
        for item in local_items:
            local_path: str = self._normalize_repo_path(str(item.get("path") or ""))
            if local_path and self._path_in_scope(local_path, source_folder, recursive):
                candidates.append(item)
        logger.info("shared-sync push candidates after scope filter=%s", len(candidates))

        if max_results > 0:
            candidates = candidates[:max_results]
            logger.info("shared-sync push candidates after max_results clamp=%s", len(candidates))

        transferred: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        heartbeat_interval = 10

        # Headless: wait for active transactions to end (up to 60s), then drain nested txs so save() can lock.
        _tx_wait_sec = 60
        if not dry_run and candidates:
            try:
                session_id = get_current_mcp_session_id()
                session = SESSION_CONTEXTS.get_or_create(session_id)
                wait_start = time.time()
                mgr = self._manager
                while time.time() - wait_start < _tx_wait_sec:
                    has_tx = False
                    for path_key, info in (session.open_programs or {}).items():
                        prog = getattr(info, "program", None) or getattr(info, "current_program", None)
                        if prog is None:
                            continue
                        tx = (prog.getCurrentTransactionInfo() if hasattr(prog, "getCurrentTransactionInfo") else prog.getCurrentTransaction()) if (hasattr(prog, "getCurrentTransactionInfo") or hasattr(prog, "getCurrentTransaction")) else None
                        if tx is not None:
                            has_tx = True
                            break
                    if not has_tx and mgr is not None:
                        for pr in getattr(mgr, "providers", None) or []:
                            opi = getattr(pr, "program_info", None)
                            prog = getattr(opi, "program", None) if opi is not None else None
                            if prog is None or not (hasattr(prog, "getCurrentTransactionInfo") or hasattr(prog, "getCurrentTransaction")):
                                continue
                            try:
                                _ctx = prog.getCurrentTransactionInfo() if hasattr(prog, "getCurrentTransactionInfo") else prog.getCurrentTransaction()
                                if _ctx is not None:
                                    has_tx = True
                                    break
                            except Exception:
                                continue
                    if not has_tx:
                        break
                    time.sleep(1)
                # After wait: drain GhidraProject/batch + tool nested transactions (single endTransaction is not enough).
                for path_key, info in (session.open_programs or {}).items():
                    prog = getattr(info, "program", None) or getattr(info, "current_program", None)
                    if prog is None:
                        continue
                    self._end_all_transactions_on_program_for_sync_push(prog)
                if mgr is not None:
                    for pr in getattr(mgr, "providers", None) or []:
                        opi = getattr(pr, "program_info", None)
                        prog = getattr(opi, "program", None) if opi is not None else None
                        if prog is not None:
                            self._end_all_transactions_on_program_for_sync_push(prog)
                if mgr is not None:
                    try:
                        for pr in getattr(mgr, "providers", None) or []:
                            drain_all = getattr(pr, "_end_open_transactions_on_all_session_programs", None)
                            if callable(drain_all):
                                drain_all(session_id)
                                break
                    except Exception as drain_all_exc:
                        logger.debug("sync-project push: session-wide tx drain: %s", drain_all_exc)
            except Exception as end_all_exc:
                logger.warning("sync-project push: could not wait/end transactions before save (continuing): %s", end_all_exc)

        logger.info("shared-sync push starting transfer loop total_candidates=%s", len(candidates))
        for index, item in enumerate(candidates, start=1):
            source_path: str = self._normalize_repo_path(str(item.get("path") or ""))
            if not source_path or source_path == "/":
                logger.info("shared-sync push skipping empty/root source path at index=%s", index)
                continue

            if index == 1 or index % heartbeat_interval == 0:
                logger.info(
                    "shared-sync push progress index=%s total=%s transferred=%s skipped=%s errors=%s elapsed_sec=%.2f",
                    index,
                    len(candidates),
                    len(transferred),
                    len(skipped),
                    len(errors),
                    time.time() - start_time,
                )

            if dry_run:
                logger.info("shared-sync push dry-run planned source=%s", source_path)
                transferred.append({"sourcePath": source_path, "planned": True})
                continue

            try:
                source_file: GhidraDomainFile | None = project_data.getFile(source_path)
                if source_file is None and source_path.startswith("/"):
                    source_file = project_data.getFile(source_path.lstrip("/"))
                if source_file is None and not source_path.startswith("/"):
                    source_file = project_data.getFile(f"/{source_path}")
                if source_file is None:
                    raise ValueError(f"Local project item not found: {source_path}")

                if hasattr(source_file, "save"):
                    logger.info("shared-sync push saving source file=%s", source_path)
                    from ghidra.util.task import TaskMonitor  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

                    # DomainFile.save fails with "active transaction" if GhidraProject's openProgram batch tx
                    # is still open. Match checkin-program: run ImportExport._persist_open_program_for_versioned_checkin
                    # first (gp.save(program) commits batch correctly), then drain consumers, then save.
                    try:
                        session_id = get_current_mcp_session_id()
                        session = SESSION_CONTEXTS.get_or_create(session_id)
                        iep = None
                        mgr = self._manager
                        if mgr is not None:
                            for pr in getattr(mgr, "providers", None) or []:
                                if hasattr(pr, "_persist_open_program_for_versioned_checkin"):
                                    iep = pr
                                    break

                        def _flush_open_program_for_push(prog: GhidraProgram) -> None:
                            if prog is None or iep is None:
                                return
                            try:
                                df = prog.getDomainFile() if hasattr(prog, "getDomainFile") else None
                                if df is None or not self._domain_files_same_pull(df, source_file):
                                    return
                                iep._persist_open_program_for_versioned_checkin(prog)
                                self._end_all_transactions_on_program_for_sync_push(prog)
                                logger.debug("shared-sync push flushed open program for %s", source_path)
                            except Exception as exc:
                                logger.debug("shared-sync push flush program for %s: %s", source_path, exc)

                        for _path_key, info in (session.open_programs or {}).items():
                            prog = getattr(info, "program", None) or getattr(info, "current_program", None)
                            if prog is None:
                                continue
                            _flush_open_program_for_push(prog)
                        if self.program_info is not None:
                            _flush_open_program_for_push(getattr(self.program_info, "program", None))
                        # Local project_data.getFile() may return a different DomainFile instance than
                        # Program.getDomainFile() after shared checkout; basename match can still miss if
                        # pathnames differ. Flush every open program so GhidraProject batch txs end before save.
                        if iep is not None:
                            for _path_key, info in (session.open_programs or {}).items():
                                prog_any = getattr(info, "program", None) or getattr(info, "current_program", None)
                                if prog_any is None:
                                    continue
                                try:
                                    iep._persist_open_program_for_versioned_checkin(prog_any)
                                    self._end_all_transactions_on_program_for_sync_push(prog_any)
                                except Exception as exc:
                                    logger.debug("shared-sync push flush-all open program: %s", exc)
                            try:
                                drain_all = getattr(iep, "_end_open_transactions_on_all_session_programs", None)
                                if callable(drain_all):
                                    drain_all(session_id)
                            except Exception as exc:
                                logger.debug("shared-sync push session-wide drain before save: %s", exc)
                        if iep is None:
                            drained = False
                            for _path_key, info in (session.open_programs or {}).items():
                                prog = getattr(info, "program", None) or getattr(info, "current_program", None)
                                if prog is None:
                                    continue
                                df = prog.getDomainFile() if hasattr(prog, "getDomainFile") else None
                                if df is None or not self._domain_files_same_pull(df, source_file):
                                    continue
                                self._end_all_transactions_on_program_for_sync_push(prog)
                                drained = True
                                break
                            if not drained and self.program_info is not None:
                                prog_m = getattr(self.program_info, "program", None)
                                if prog_m is not None:
                                    df_m = prog_m.getDomainFile() if hasattr(prog_m, "getDomainFile") else None
                                    if df_m is not None and self._domain_files_same_pull(df_m, source_file):
                                        self._end_all_transactions_on_program_for_sync_push(prog_m)
                    except Exception as tx_exc:
                        logger.debug("shared-sync push could not flush/drain for %s (continuing): %s", source_path, tx_exc)

                    self._drain_all_domain_file_handles_for_sync_push(source_file, session_id)

                    try:
                        source_file.save(TaskMonitor.DUMMY)
                    except Exception as save_exc:
                        save_msg = str(save_exc).lower()
                        if "domainobj not open" in save_msg or "cannot save" in save_msg:
                            logger.info(
                                "shared-sync push save skipped (domain object already closed/committed) source=%s: %s",
                                source_path,
                                save_exc,
                            )
                        else:
                            raise
                else:
                    logger.info("shared-sync push skip save-not-supported source=%s", source_path)
                    skipped.append({"sourcePath": source_path, "reason": "save-not-supported"})
                    continue

                transferred.append({"sourcePath": source_path})
                logger.info("shared-sync push transferred source=%s", source_path)
            except Exception as exc:
                logger.exception("shared-sync push failed source=%s error=%s", source_path, exc)
                errors.append({"sourcePath": source_path, "error": str(exc)})

        logger.info(
            "shared-sync push complete repository=%s requested=%s transferred=%s skipped=%s errors=%s elapsed_sec=%.2f",
            repository_name,
            len(candidates),
            len(transferred),
            len(skipped),
            len(errors),
            time.time() - start_time,
        )

        return {
            "direction": "push",
            "repository": repository_name,
            "sourceFolder": source_folder,
            "recursive": recursive,
            "requested": len(candidates),
            "transferred": len(transferred),
            "skipped": len(skipped),
            "errors": errors,
            "items": transferred,
            "skippedItems": skipped,
            "dryRun": dry_run,
            "note": (
                "Push syncs local project domain files by saving scoped items. For shared-backed files, this persists "
                "local modifications to the backing shared project workflow. "
                "If a program had an open Ghidra transaction, sync-project push may end it with commit=true so save() "
                "can obtain the domain-file lock — pending edits are committed, not rolled back."
            ),
        }

    async def _sync_shared_repository(self, args: dict[str, Any], default_mode: str = "pull") -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._sync_shared_repository")
        sync_start = time.time()
        logger.info("shared-sync execution start default_mode=%s arg_keys=%s", default_mode, sorted(list(args.keys())))
        mode = self._resolve_shared_sync_mode(args, default_mode=default_mode)
        session_id, handle, repository_adapter, repository_name = self._get_shared_session_context()
        _sid_hint = (session_id[:12] + "…") if session_id and len(session_id) > 12 else (session_id or "—")
        logger.info(
            "shared-sync context resolved session_id=%s mode=%s has_handle=%s has_adapter=%s repository=%s",
            _sid_hint,
            mode,
            bool(handle),
            repository_adapter is not None,
            repository_name,
        )
        is_shared_session = handle and is_shared_server_handle(handle)
        is_local_gpr_session = handle and n(str(handle.get("mode", ""))) in {"localgpr", "local"}  # noqa: F841

        if not is_shared_session:
            # No shared server session — try local project operations
            project_data = self._get_active_project_data()

            if project_data is not None and mode == "push":
                # Local push: save all modified domain files in the local project
                logger.info("sync-project local push mode (no shared session)")
                push_result: dict[str, Any] = self._push_local_project_to_shared(args, "local-project", project_data)
                errors: list[dict[str, Any]] = push_result.get("errors") or []
                success: bool = len(errors) == 0
                payload: dict[str, Any] = {
                    "operation": "sync-project",
                    "mode": mode,
                    **push_result,
                    "direction": "local-save",
                    "success": success,
                    "note": "No shared server session. Performed local project save." if success else "Local save completed with errors; annotations may still be in the current program.",
                }
                if not success and "error" not in payload:
                    first = errors[0] if errors else {}
                    msg = first.get("error", "One or more files could not be saved.")
                    payload["error"] = f"Local save had {len(errors)} error(s). First: {msg}"
                return create_success_response(payload)

            if project_data is not None and mode == "bidirectional":
                # Local bidirectional: just save (can't pull without a source)
                logger.info("sync-project local bidirectional mode (no shared session, saving only)")
                push_result: dict[str, Any] = self._push_local_project_to_shared(args, "local-project", project_data)
                errors: list[dict[str, Any]] = push_result.get("errors") or []
                success: bool = len(errors) == 0
                payload: dict[str, Any] = {
                    "operation": "sync-project",
                    **push_result,
                    "mode": "bidirectional",
                    "direction": "local-save-only",
                    "success": success,
                    "note": "No shared server session. Only local save was performed (pull requires a shared server connection)." if success else "Local save completed with errors.",
                }
                if not success and "error" not in payload:
                    first = errors[0] if errors else {}
                    payload["error"] = f"Local save had {len(errors)} error(s). First: {first.get('error', 'Unknown')}"
                return create_success_response(payload)

            logger.warning("sync-project aborted: no shared-server session and no actionable local project")
            return create_success_response(
                {
                    "operation": "sync-project",
                    "mode": mode,
                    "success": False,
                    "error": "No active shared-server session or local project. Run open first.",
                    "context": {
                        "state": "no-sync-source",
                        "hasLocalProject": project_data is not None,
                        "isSharedSession": False,
                    },
                    "nextSteps": [
                        "Call `open` with `serverHost`, `serverPort`, `serverUsername`, `serverPassword` for shared sync.",
                        "Call `open` with a local `.gpr` project path for local project operations.",
                        "After `open` succeeds, retry `sync-project`.",
                    ],
                },
            )

        if repository_adapter is None:
            logger.warning("shared-sync aborted: shared adapter missing repository=%s", repository_name)
            return create_success_response(
                {
                    "operation": "sync-project",
                    "mode": mode,
                    "success": False,
                    "repository": repository_name,
                    "error": "Shared repository adapter is unavailable in this session.",
                    "context": {
                        "state": "shared-adapter-missing",
                        "repository": repository_name,
                    },
                    "nextSteps": [
                        "Re-run `open` against the shared server to re-establish repository adapter state.",
                        "Then retry the same sync command.",
                    ],
                },
            )

        project_data: GhidraProjectData | None = self._get_active_project_data()
        logger.info("shared-sync project_data resolved has_project_data=%s", project_data is not None)
        if project_data is None:
            logger.warning("shared-sync aborted: local project_data unavailable repository=%s", repository_name)
            return create_success_response(
                {
                    "operation": "sync-project",
                    "mode": mode,
                    "success": False,
                    "repository": repository_name,
                    "error": "No local Ghidra project context available for shared sync.",
                    "context": {
                        "state": "local-project-context-missing",
                        "repository": repository_name,
                    },
                    "nextSteps": [
                        "Call `open` with a local project (`.gpr`) or `import-binary` after shared `open` so a transient local Ghidra project has GhidraProjectData.",
                        "Run `open` + `import-binary` + `sync-project` in one `tool-seq` (same MCP session). Restarting agentdecompile-server clears in-memory session — re-`open` before sync if you restarted.",
                        "If using the CLI proxy, ensure `mcp-session-id` is forwarded so the session that ran `open` is the same one that runs `sync-project`.",
                    ],
                },
            )

        if mode == "pull":
            logger.info("shared-sync executing pull phase repository=%s", repository_name)
            pull_result: dict[str, Any] = self._pull_shared_repository_to_local(args, repository_adapter, repository_name, project_data)
            logger.info(
                "shared-sync pull phase complete success=%s requested=%s transferred=%s skipped=%s errors=%s elapsed_sec=%.2f",
                len(pull_result.get("errors", [])) == 0,
                pull_result.get("requested", 0),
                pull_result.get("transferred", 0),
                pull_result.get("skipped", 0),
                len(pull_result.get("errors", [])),
                time.time() - sync_start,
            )
            pull_errors: list[Any] = pull_result.get("errors") or []
            pull_ok: bool = len(pull_errors) == 0
            pull_payload: dict[str, Any] = {
                "operation": "sync-project",
                "mode": mode,
                "direction": "shared-to-local",
                "success": pull_ok,
                **pull_result,
            }
            if not pull_ok and not pull_payload.get("error"):
                first_err = pull_errors[0] if pull_errors else {}
                pull_payload["error"] = str(
                    first_err.get("error", first_err) if isinstance(first_err, dict) else first_err,
                )
            return create_success_response(pull_payload)

        if mode == "push":
            logger.info("shared-sync executing push phase repository=%s", repository_name)
            push_result = self._push_local_project_to_shared(args, repository_name, project_data)
            logger.info(
                "shared-sync push phase complete success=%s requested=%s transferred=%s skipped=%s errors=%s elapsed_sec=%.2f",
                len(push_result["errors"]) == 0,
                push_result.get("requested", 0),
                push_result.get("transferred", 0),
                push_result.get("skipped", 0),
                len(push_result.get("errors", [])),
                time.time() - sync_start,
            )
            push_errors = push_result.get("errors") or []
            push_payload: dict[str, Any] = {
                "operation": "sync-project",
                "mode": mode,
                "direction": "local-to-shared",
                "success": len(push_errors) == 0,
                **push_result,
            }
            if push_errors and not push_payload.get("error"):
                fe = push_errors[0]
                push_payload["error"] = str(fe.get("error", fe) if isinstance(fe, dict) else fe)
            return create_success_response(push_payload)

        logger.info("shared-sync executing bidirectional pull phase repository=%s", repository_name)
        pull_result = self._pull_shared_repository_to_local(args, repository_adapter, repository_name, project_data)
        logger.info("shared-sync executing bidirectional push phase repository=%s", repository_name)
        push_result = self._push_local_project_to_shared(args, repository_name, project_data)

        logger.info(
            "shared-sync bidirectional complete pull_errors=%s push_errors=%s total_requested=%s total_transferred=%s total_skipped=%s total_errors=%s elapsed_sec=%.2f",
            len(pull_result.get("errors", [])),
            len(push_result.get("errors", [])),
            int(pull_result.get("requested", 0)) + int(push_result.get("requested", 0)),
            int(pull_result.get("transferred", 0)) + int(push_result.get("transferred", 0)),
            int(pull_result.get("skipped", 0)) + int(push_result.get("skipped", 0)),
            len(pull_result.get("errors", [])) + len(push_result.get("errors", [])),
            time.time() - sync_start,
        )

        pull_errs = pull_result.get("errors") or []
        push_errs = push_result.get("errors") or []
        bi_ok = len(pull_errs) == 0 and len(push_errs) == 0
        bi_payload: dict[str, Any] = {
            "operation": "sync-project",
            "mode": "bidirectional",
            "direction": "shared-and-local",
            "success": bi_ok,
            "repository": repository_name,
            "phases": {
                "pull": pull_result,
                "push": push_result,
            },
            "totals": {
                "requested": int(pull_result.get("requested", 0)) + int(push_result.get("requested", 0)),
                "transferred": int(pull_result.get("transferred", 0)) + int(push_result.get("transferred", 0)),
                "skipped": int(pull_result.get("skipped", 0)) + int(push_result.get("skipped", 0)),
                "errors": len(pull_errs) + len(push_errs),
            },
        }
        if not bi_ok and not bi_payload.get("error"):
            if push_errs:
                fe = push_errs[0]
                bi_payload["error"] = f"push: {fe.get('error', fe) if isinstance(fe, dict) else fe}"
            elif pull_errs:
                fe = pull_errs[0]
                bi_payload["error"] = f"pull: {fe.get('error', fe) if isinstance(fe, dict) else fe}"
        return create_success_response(bi_payload)

    async def _download_shared_repository_to_local(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._download_shared_repository_to_local")
        return await self._sync_shared_repository(args, default_mode="pull")

    def _get_domain_file_with_path_variants(self, project_data: GhidraProjectData | None, program_path: str, item_name: str) -> GhidraDomainFile | None:
        """Resolve ``DomainFile`` via ``project_data.getFile`` using the same path variants as checkout/checkin."""
        if project_data is None:
            return None
        p = (program_path or "").strip().replace("\\", "/")
        name = (item_name or "").strip()
        variants: list[str] = []
        if p:
            variants.append(p)
            if not p.startswith("/"):
                variants.append(f"/{p}")
            variants.append(p.lstrip("/"))
        if name:
            variants.append(f"/{name}")
            variants.append(name)
        seen: set[str] = set()
        for v in variants:
            if not v or v in seen:
                continue
            seen.add(v)
            try:
                df = project_data.getFile(v)
                if df is not None:
                    return df
            except Exception:
                continue
        return None

    def _find_domain_file_shared_item_in_tree(self, project_data: GhidraProjectData | None, item_name: str) -> GhidraDomainFile | None:
        """Walk project tree for ``item_name``; prefer the **checked-out** copy, then any versioned file."""
        if project_data is None or not item_name:
            return None
        try:
            root = project_data.getRootFolder()
        except Exception:
            root = None
        if root is None:
            return None
        want: str = item_name.casefold()
        matches: list[GhidraDomainFile] = []
        stack: list[GhidraDomainFolder] = [root]
        df: GhidraDomainFile | None = None
        while stack:
            folder = stack.pop()
            try:
                for df in folder.getFiles() or []:
                    if df is None:
                        continue
                    try:
                        if str(df.getName() or "").casefold() == want:
                            matches.append(df)
                    except Exception:
                        continue
                for sub in folder.getFolders() or []:
                    if sub is not None:
                        stack.append(sub)
            except Exception:
                continue
        for df in matches:
            try:
                if bool(df.isCheckedOut()):
                    return df
            except Exception:
                continue
        for df in matches:
            try:
                if bool(df.isVersioned()):
                    return df
            except Exception:
                continue
        return matches[0] if matches else None

    def _resolve_shared_checkout_domain_file(
        self,
        project_data: GhidraProjectData | None,
        program_path: str,
        item_name: str,
    ) -> GhidraDomainFile | None:
        """Prefer a **versioned** ``GhidraDomainFile`` after ``RepositoryAdapter.checkout`` (getFile can return a stale stub)."""
        df: GhidraDomainFile | None = self._get_domain_file_with_path_variants(project_data, program_path, item_name)
        if df is not None:
            try:
                if bool(df.isCheckedOut()):
                    return df
                if bool(df.isVersioned()):
                    return df
            except Exception:
                pass
        found: GhidraDomainFile | None = self._find_domain_file_shared_item_in_tree(project_data, item_name)
        if found is not None:
            return found
        return df

    def _ensure_shared_domain_file_registered_for_version_control(self, domain_file: GhidraDomainFile, program_path: str) -> None:
        """If Ghidra leaves a post-checkout ``GhidraDomainFile`` unversioned, register it (same API as shared ``import-binary``)."""
        if domain_file is None or not hasattr(domain_file, "isVersioned"):
            return
        try:
            if bool(domain_file.isVersioned()):
                return
        except Exception:
            return
        from ghidra.util.task import TaskMonitor as GhidraTaskMonitor  # pyright: ignore[reportMissingImports, reportMissingModuleSource]

        try:
            domain_file.save(GhidraTaskMonitor.DUMMY)
        except Exception as save_exc:
            logger.debug("pre-addToVersionControl save failed for %s: %s", program_path, save_exc)
        try:
            domain_file.addToVersionControl("Shared repository checkout", False, GhidraTaskMonitor.DUMMY)
            if bool(domain_file.isVersioned()):
                logger.info("Registered version control for checked-out file %s", program_path)
        except Exception as vc_exc:
            logger.warning("addToVersionControl after shared checkout failed for %s: %s", program_path, vc_exc)

    async def _checkout_shared_program(
        self,
        repository_adapter: GhidraRepositoryAdapter,
        program_path: str,
        session_id: str,
        *,
        exclusive: bool = False,
    ) -> str:
        """Checkout a program from a shared Ghidra server repository and set it as active.

        This opens the remote program for read-only browsing via Ghidra's
        ``RepositoryAdapter`` API, creates a ``ProgramInfo`` for it, and
        sets it on the session and tool-provider so that all subsequent tool
        calls operate on the checked-out program.

        Returns the program path that was checked out.
        """
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._checkout_shared_program")
        import time

        from db import DBHandle  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
        from ghidra.framework.data import OpenMode as GhidraOpenMode  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
        from ghidra.program.database import ProgramDB as GhidraProgramDB  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
        from ghidra.util.task import TaskMonitor as GhidraTaskMonitor  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
        from java.lang import Object as JavaObject  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

        monitor = GhidraTaskMonitor.DUMMY

        # Split program_path into folder + name
        parts: list[str] = program_path.rsplit("/", 1)
        if len(parts) == 2:
            folder_path: str = parts[0] or "/"
            item_name: str = parts[1]
        else:
            folder_path = "/"
            item_name = parts[0]

        # Get the repository item (try exact name, then match from getItemList for case-insensitive match).
        # RepositoryAdapter may use '' instead of '/' for the repository root.
        repo_item: GhidraRepositoryItem | None = None
        repo_folder_path = folder_path
        for fp in repository_adapter_folder_candidates(folder_path):
            try:
                ri = repository_adapter.getItem(fp, item_name)
                if ri is not None:
                    repo_item = ri
                    repo_folder_path = fp
                    break
            except Exception:
                continue
        if repo_item is None:
            for fp in repository_adapter_folder_candidates(folder_path):
                if fp is None:
                    continue
                try:
                    repo_items: JArray[GhidraRepositoryItem] | list[GhidraRepositoryItem] = repository_adapter.getItemList(fp) or []
                except Exception:
                    continue
                for ri in repo_items:
                    rname = str(ri.getName()) if hasattr(ri, "getName") else str(ri)
                    if rname == item_name or rname.lower() == item_name.lower():
                        try:
                            repo_item = repository_adapter.getItem(fp, rname)
                        except Exception:
                            repo_item = None
                        if repo_item is not None:
                            item_name = rname
                            repo_folder_path = fp
                        break
                if repo_item is not None:
                    break

        # If not found in repository, check session's open programs and local transient project
        # This handles the case where import created the file locally but it's not yet in the server repo
        if repo_item is None:
            # First check if program is already open in session (case-insensitive path key)
            session_ctx = SESSION_CONTEXTS.get_or_create(session_id)
            matched_session_key: str | None = None
            if program_path in session_ctx.open_programs:
                matched_session_key = program_path
            else:
                pp_l = program_path.strip().lower()
                for k in session_ctx.open_programs:
                    if k.strip().lower() == pp_l or k.strip().lower().lstrip("/") == pp_l.lstrip("/"):
                        matched_session_key = k
                        break
            if matched_session_key is not None:
                program_info = session_ctx.open_programs[matched_session_key]
                assert program_info is not None, "session_ctx.open_programs should not have None values"
                domain_file_local = program_info.domain_file if hasattr(program_info, "domain_file") else None
                if domain_file_local is not None:
                    logger.info("File '%s' already open in session, checking checkout status", program_path)
                    from ghidra.util.task import TaskMonitor  # pyright: ignore[reportMissingImports, reportMissingModuleSource]

                    # If not checked out, checkout it
                    if not domain_file_local.isCheckedOut():
                        try:
                            domain_file_local.checkout(exclusive, TaskMonitor.DUMMY)
                            logger.info("Checked out '%s' from session program", program_path)
                        except Exception as co_exc:
                            logger.warning("Failed to checkout '%s' from session: %s", program_path, co_exc)
                    else:
                        logger.info("File '%s' already checked out in session", program_path)

                    session_ctx.active_program_key = matched_session_key
                    logger.info("Successfully checked out '%s' from session", matched_session_key)
                    return matched_session_key

            # If not in session, check local transient project
            ghidra_project: GhidraProject | None = getattr(self._manager, "ghidra_project", None) if self._manager else None
            if ghidra_project is not None:
                try:
                    project_data = ghidra_project.getProject().getProjectData()
                    if project_data is not None:
                        # Try multiple path variations
                        domain_file_local = None
                        for path_variant in [program_path, f"/{item_name}", item_name, f"/{program_path.lstrip('/')}"]:
                            domain_file_local = project_data.getFile(path_variant)
                            if domain_file_local is not None:
                                logger.info("File '%s' found in local project (path: %s), attempting checkout", program_path, path_variant)
                                break

                        if domain_file_local is not None:
                            from ghidra.util.task import TaskMonitor as GhidraTaskMonitor  # pyright: ignore[reportMissingImports, reportMissingModuleSource]

                            # If not versioned, try to add to version control first
                            if not domain_file_local.isVersioned():
                                try:
                                    domain_file_local.addToVersionControl("Initial import", False, GhidraTaskMonitor.DUMMY)
                                    logger.info("Added '%s' to version control in local project", program_path)
                                except Exception as vc_exc:
                                    logger.warning("Failed to add '%s' to version control: %s", program_path, vc_exc)

                            # Checkout the file (works for both versioned and non-versioned files)
                            if not domain_file_local.isCheckedOut():
                                try:
                                    domain_file_local.checkout(exclusive, GhidraTaskMonitor.DUMMY)
                                    logger.info("Checked out '%s' from local project", program_path)
                                except Exception as co_exc:
                                    logger.warning("Failed to checkout '%s' from local project: %s", program_path, co_exc)

                            # Open the program from the GhidraDomainFile
                            program: GhidraProgram | None = self._ghidra_project_open_program_compat(ghidra_project, domain_file_local)
                            if program is not None:
                                from agentdecompile_cli.launcher import ProgramInfo
                                from agentdecompile_cli.mcp_utils.decompiler_util import open_decompiler_for_program

                                decompiler_local = None
                                try:
                                    decompiler_local = open_decompiler_for_program(program)
                                except Exception as dec_exc:
                                    logger.warning(
                                        "checkout local decompiler_open_failed program_tail=%s exc_type=%s",
                                        basename_hint(program_path),
                                        type(dec_exc).__name__,
                                    )
                                program_info = ProgramInfo(
                                    name=program.getName(),
                                    program=program,
                                    flat_api=None,
                                    decompiler=decompiler_local,
                                    metadata={},
                                    ghidra_analysis_complete=True,
                                    file_path=None,
                                    load_time=time.time(),
                                )
                                setattr(program_info, "domain_file", domain_file_local)
                                SESSION_CONTEXTS.set_active_program_info(session_id, program_path, program_info)
                                if self._manager is not None:
                                    self._manager.set_program_info(program_info)
                                else:
                                    self.set_program_info(program_info)
                                session_ctx.open_programs[program_path] = program_info
                                session_ctx.active_program_key = program_path

                                # Update session binaries to include this file
                                binaries = SESSION_CONTEXTS.get_project_binaries(session_id) or []
                                found = False
                                for b in binaries:
                                    if (b.get("path") or "").strip() == program_path or (b.get("name") or "").strip() == item_name:
                                        found = True
                                        break
                                if not found:
                                    binaries.append({"name": item_name, "path": program_path, "type": "Program"})
                                    SESSION_CONTEXTS.set_project_binaries(session_id, binaries)

                                logger.info("Successfully checked out '%s' from local project", program_path)
                                return program_path
                            else:
                                logger.warning("Found '%s' in local project but failed to open program", program_path)
                except Exception as local_exc:
                    logger.debug("Failed to checkout from local project: %s", local_exc)

        # Only raise exception if we didn't successfully checkout from local project
        if repo_item is None:
            raise ValueError(f"Program '{program_path}' not found in repository folder '{folder_path}'")
        adapter_folder_path = repo_folder_path

        # Prefer opening via GhidraProjectData/GhidraDomainFile so the resulting Program has
        # standard project-backed behavior (including stable decompiler support).
        # Keep a ProgramDB fallback for environments where GhidraDomainFile checkout is
        # unavailable.
        program = None
        domain_object_consumer: GhidraDomainFile | None = None  # ProgramDB / low-level open consumer for Program.release()

        # Open / checkout the file via the project data
        # We need to use the project's GhidraDomainFile which can be retrieved
        # from the project data after connecting.

        # Use the manager's GhidraProject (set from launcher) to get project data.
        project_data: GhidraProjectData | None = None
        ghidra_project: GhidraProject | None = getattr(self._manager, "ghidra_project", None) if self._manager else None
        if ghidra_project is not None:
            try:
                project_data = ghidra_project.getProject().getProjectData()
            except Exception:
                try:
                    # Some GhidraProject versions expose getProjectData directly
                    project_data = ghidra_project.getProjectData()
                except Exception:
                    pass

        if project_data is None and self.program_info and self.program_info.program:
            try:
                project_data = self.program_info.program.getDomainFile().getProjectData()
            except Exception:
                pass

        checkout_link_domain_file: GhidraDomainFile | None = None

        if project_data is not None:
            # Prefer RepositoryAdapter.checkout() so the file is versioned and supports checkin.
            domain_file = self._resolve_shared_checkout_domain_file(project_data, program_path, item_name)
            # Import-binary may leave a local GhidraDomainFile that is not server-checked-out; getFile is
            # non-None so we must still run RepositoryAdapter.checkout (skip only when already checked out).
            # Also re-run adapter checkout when a stale local GhidraDomainFile exists but is not versioned —
            # otherwise checkin-program takes the non-versioned branch and only saves locally (no server).
            needs_adapter_checkout: bool = domain_file is None or (domain_file is not None and hasattr(domain_file, "isCheckedOut") and not domain_file.isCheckedOut()) or (domain_file is not None and hasattr(domain_file, "isVersioned") and not domain_file.isVersioned())
            # Exclusive checkout: always re-invoke RepositoryAdapter.checkout when the adapter supports it.
            # After sync-project pull, the local GhidraDomainFile can still report checked out while the open
            # Program is not wired to the server checkout metadata, so checkin-program fails with
            # "File has not been modified since checkout" even after real listing edits.
            force_adapter_checkout = bool(exclusive)
            if (needs_adapter_checkout or force_adapter_checkout) and hasattr(repository_adapter, "checkout"):
                try:
                    from ghidra.framework.store import CheckoutType as GhidraCheckoutType  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

                    # EXCLUSIVE when requested (tool checkout-program exclusive=true); fall back to NORMAL if enum missing
                    if exclusive:
                        checkout_type = getattr(GhidraCheckoutType, "EXCLUSIVE", None) or getattr(
                            GhidraCheckoutType,
                            "EXCLUSIVE_CHECKOUT",
                            None,
                        )
                        if checkout_type is None:
                            checkout_type = GhidraCheckoutType.NORMAL
                            logger.warning(
                                "exclusive checkout requested but GhidraCheckoutType has no EXCLUSIVE; using NORMAL for %s",
                                program_path,
                            )
                    else:
                        checkout_type = GhidraCheckoutType.NORMAL
                    # 4th param is projectPath: absolute path where checked-out file is stored (Java expects absolute)
                    checkout_project_path: str = program_path
                    try:
                        assert ghidra_project is not None
                        proj = ghidra_project.getProject()
                        if proj is not None and hasattr(proj, "getProjectLocator"):
                            locator = proj.getProjectLocator()
                            if locator is not None and hasattr(locator, "getProjectDir"):
                                proj_dir = locator.getProjectDir()
                                if proj_dir is not None:
                                    abs_dir = str(proj_dir.getAbsolutePath()).replace("\\", "/")
                                    checkout_project_path = f"{abs_dir}/{item_name}" if not abs_dir.endswith("/") else f"{abs_dir}{item_name}"
                    except Exception:
                        pass
                    status = repository_adapter.checkout(adapter_folder_path, item_name, checkout_type, checkout_project_path)
                    if status is not None:
                        domain_file = self._resolve_shared_checkout_domain_file(project_data, program_path, item_name)
                        if domain_file is not None:
                            self._ensure_shared_domain_file_registered_for_version_control(domain_file, program_path)
                            logger.info("Checked out '%s' via RepositoryAdapter.checkout (versioned)", program_path)
                except Exception as exc:
                    logger.debug("RepositoryAdapter.checkout for '%s' failed: %s. Trying createFile fallback.", program_path, exc)
                    if needs_adapter_checkout:
                        domain_file = None

            if domain_file is None:
                try:
                    parent_folder = project_data.getFolder(folder_path)
                    if parent_folder is None:
                        parent_folder = project_data.getRootFolder()
                        # Create intermediate folders
                        for folder_component in folder_path.strip("/").split("/"):
                            if folder_component:
                                child = parent_folder.getFolder(folder_component)
                                if child is None:
                                    child = parent_folder.createFolder(folder_component)
                                parent_folder = child

                    # Multi-strategy to get a domain object from the repo item:
                    remote_domain_obj: GhidraDomainObject | None = None
                    consumer = JavaObject()

                    # Strategy 1: RepositoryItem.getDomainObject (some Ghidra versions)
                    if hasattr(repo_item, "getDomainObject"):
                        try:
                            remote_domain_obj = repo_item.getDomainObject(consumer, True, False, monitor)
                        except Exception:
                            pass

                    # Strategy 2: Open via ProgramDB from repository database
                    if remote_domain_obj is None and hasattr(repository_adapter, "openDatabase"):
                        try:
                            version = int(repo_item.getVersion()) if hasattr(repo_item, "getVersion") else -1
                            managed_db = repository_adapter.openDatabase(adapter_folder_path, item_name, version, 0)
                            db_handle = DBHandle(managed_db)
                            try:
                                remote_domain_obj = GhidraProgramDB(db_handle, GhidraOpenMode.UPDATE, monitor, consumer)
                            except Exception:
                                remote_domain_obj = GhidraProgramDB(db_handle, GhidraOpenMode.IMMUTABLE, monitor, consumer)
                        except Exception as e2:
                            logger.debug("ProgramDB strategy for createFile failed: %s", e2)

                    if remote_domain_obj is None:
                        raise ValueError(f"Failed to fetch remote domain object for '{program_path}'")
                    try:
                        domain_file = parent_folder.createFile(item_name, remote_domain_obj, monitor)  # pyright: ignore[reportAttributeAccessIssue]
                    finally:
                        try:
                            remote_domain_obj.release(consumer)
                        except Exception:
                            pass

                    if domain_file is not None:
                        self._ensure_shared_domain_file_registered_for_version_control(domain_file, program_path)
                        # Prefer GhidraProject.openProgram() which gives writable access
                        # on local project files, over getDomainObject() which may
                        # open read-only.
                        opened = False
                        if ghidra_project is not None:
                            domain_obj = self._ghidra_project_open_program_compat(ghidra_project, domain_file)
                            if domain_obj is not None:
                                program = domain_obj
                                opened = True
                                logger.info("Opened '%s' via GhidraProject.openProgram (writable)", program_path)
                        if not opened:
                            domain_obj = self._get_domain_object_compat(domain_file, monitor)  # pyright: ignore[reportAttributeAccessIssue]
                            if domain_obj is not None:
                                program = domain_obj
                                logger.info("Opened '%s' via GhidraDomainFile.getDomainObject (path=%s)", program_path, domain_file.getPathname())
                except Exception as exc:
                    logger.info("project_data checkout of '%s' failed: %s. Trying lower-level fallbacks.", program_path, exc)
                finally:
                    try:
                        domain_file.release(consumer)
                    except Exception:
                        pass

            # RepositoryAdapter.checkout can leave the local GhidraDomainFile not marked checked-out for modify/checkin;
            # GhidraDomainFile.checkout links the working copy for this JVM.
            if domain_file is not None:
                try:
                    if hasattr(domain_file, "isCheckedOut") and not bool(domain_file.isCheckedOut()):
                        domain_file.checkout(exclusive, monitor)
                except Exception as co_exc:
                    logger.warning(
                        "domain_file.checkout after shared resolve failed exclusive=%s program=%s: %s",
                        exclusive,
                        program_path,
                        co_exc,
                    )

            # If we have a versioned domain_file (e.g. from RepositoryAdapter.checkout) but haven't opened it yet
            if domain_file is not None and program is None and ghidra_project is not None:
                program = self._ghidra_project_open_program_compat(ghidra_project, domain_file)
                if program is not None:
                    logger.info("Opened '%s' via GhidraProject.openProgram (versioned)", program_path)
            if domain_file is not None and program is None:
                try:
                    program = self._get_domain_object_compat(domain_file, monitor)  # pyright: ignore[reportAttributeAccessIssue]
                    if program is not None:
                        logger.info("Opened '%s' via GhidraDomainFile.getDomainObject (versioned)", program_path)
                except Exception:
                    pass

            checkout_link_domain_file = self._resolve_shared_checkout_domain_file(project_data, program_path, item_name)
            if checkout_link_domain_file is not None:
                self._ensure_shared_domain_file_registered_for_version_control(
                    checkout_link_domain_file,
                    program_path,
                )

        if program is None:
            # Fallback: open the item directly via low-level API
            try:
                domain_obj = self._get_domain_object_compat(repo_item, monitor)
            except Exception as exc:
                # Many versions of Ghidra don't support getDomainObject on RepositoryItem
                # Fall through to ProgramDB fallback below.
                logger.info(
                    "RepositoryItem.getDomainObject not available for '%s': %s. Trying ProgramDB fallback.",
                    program_path,
                    exc,
                )
                domain_obj = None
            if domain_obj is not None:
                program = domain_obj
        if program is None:
            try:
                version = int(repo_item.getVersion()) if hasattr(repo_item, "getVersion") else -1
                managed_db = repository_adapter.openDatabase(adapter_folder_path, item_name, version, 0)  # pyright: ignore[reportAttributeAccessIssue]
                db_handle = DBHandle(managed_db)
                pdb_consumer = JavaObject()
                try:
                    program = GhidraProgramDB(db_handle, GhidraOpenMode.UPDATE, monitor, pdb_consumer)
                except Exception:
                    program = GhidraProgramDB(db_handle, GhidraOpenMode.IMMUTABLE, monitor, pdb_consumer)
                domain_object_consumer = pdb_consumer
                logger.info("Opened shared program '%s' via ProgramDB fallback", program_path)
            except Exception as exc:
                logger.warning(
                    "Shared ProgramDB open failed for %s (repo item %s/%s): %s",
                    program_path,
                    adapter_folder_path,
                    item_name,
                    exc,
                )

        if program is None:
            raise ValueError(f"Failed to open '{program_path}' from repository")

        if checkout_link_domain_file is None and project_data is not None:
            checkout_link_domain_file = self._resolve_shared_checkout_domain_file(project_data, program_path, item_name)
            if checkout_link_domain_file is not None:
                self._ensure_shared_domain_file_registered_for_version_control(
                    checkout_link_domain_file,
                    program_path,
                )

        # If PyGhidra opened a Program whose getDomainFile() is not the versioned project GhidraDomainFile,
        # checkin-program and checkout-status see a non-versioned stub. Re-open from the versioned file.
        if checkout_link_domain_file is not None and ghidra_project is not None and program is not None:
            try:
                vdf = checkout_link_domain_file
                if bool(vdf.isVersioned()):
                    cur = program.getDomainFile()
                    cur_path = str(cur.getPathname() or "").replace("\\", "/").strip() if cur is not None else ""
                    want_path = str(vdf.getPathname() or "").replace("\\", "/").strip()
                    cur_ver = bool(cur.isVersioned()) if cur is not None and hasattr(cur, "isVersioned") else False
                    # Prefer Java identity: two DomainFiles can report isVersioned() true and equal path strings
                    # but only one is the checkout GhidraServer tracks for save/checkin.
                    need_reopen = cur is None or cur is not vdf
                    if need_reopen:
                        try:
                            program.release(None)
                        except Exception:
                            pass
                        try:
                            ghidra_project.close(program)
                        except Exception:
                            pass
                        reopened = self._ghidra_project_open_program_compat(ghidra_project, vdf)
                        if reopened is None:
                            raise ValueError("openProgram returned None for versioned GhidraDomainFile")
                        program = reopened
                        domain_object_consumer = None
                        logger.info(
                            "Reopened '%s' from versioned GhidraDomainFile (was versioned=%s path=%r now path=%r)",
                            program_path,
                            cur_ver,
                            cur_path,
                            want_path,
                        )
            except Exception as reopen_exc:
                logger.warning("Versioned GhidraDomainFile reopen failed for %s: %s", program_path, reopen_exc)

        # Build ProgramInfo
        from ghidra.app.decompiler import DecompInterface as GhidraDecompInterface, DecompileOptions as GhidraDecompileOptions  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

        from agentdecompile_cli.launcher import ProgramInfo

        decompiler = GhidraDecompInterface()
        decomp_options = GhidraDecompileOptions()
        decomp_options.grabFromProgram(program)
        decompiler.setOptions(decomp_options)
        decompiler.openProgram(program)

        program_info = ProgramInfo(
            name=program.getName(),
            program=program,
            flat_api=None,
            decompiler=decompiler,
            metadata={},
            ghidra_analysis_complete=True,
            file_path=None,
            load_time=time.time(),
        )

        link_domain_file: GhidraDomainFile | None = None
        try:
            link_domain_file = program.getDomainFile()
        except Exception:
            link_domain_file = None
        if link_domain_file is None:
            link_domain_file = checkout_link_domain_file
        if link_domain_file is not None:
            setattr(program_info, "domain_file", link_domain_file)
        if domain_object_consumer is not None:
            setattr(program_info, "domain_object_consumer", domain_object_consumer)

        # Set as active on session and ALL providers (via manager)
        SESSION_CONTEXTS.set_active_program_info(session_id, program_path, program_info)
        if self._manager is not None:
            self._manager.set_program_info(program_info)
        else:
            self.set_program_info(program_info)

        logger.info("Checked out program '%s' from shared repository", program_path)
        return program_path

    def _list_repository_items(self, repository_adapter: GhidraRepositoryAdapter) -> list[dict[str, Any]]:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._list_repository_items")
        logger.info("shared-sync repository listing start")
        start_time = time.time()
        return list_repository_adapter_items(repository_adapter, log=logger, start_time=start_time)

    def _remove_shared_session_item(self, session_id: str, program_path: str) -> None:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._remove_shared_session_item")
        requested_l = program_path.strip().lower().lstrip("/")
        session_ctx = SESSION_CONTEXTS.get_or_create(session_id)
        stale_keys: list[str] = []
        for key, info in list(session_ctx.open_programs.items()):
            key_l = str(key).strip().lower().lstrip("/")
            info_program: GhidraProgram | None = getattr(info, "program", None)
            info_name_l = ""
            info_path_l = ""
            if info_program is not None:
                try:
                    info_name_l = str(info_program.getName()).strip().lower().lstrip("/")
                except Exception:
                    pass
                try:
                    info_path_l = str(info_program.getDomainFile().getPathname()).strip().lower().lstrip("/")
                except Exception:
                    pass
            if requested_l in {key_l, info_name_l, info_path_l}:
                stale_keys.append(key)

        ghidra_project: GhidraProject | None = getattr(self._manager, "ghidra_project", None) if self._manager else None

        for key in stale_keys:
            info: ProgramInfo | None = session_ctx.open_programs.get(key)
            if info is None:
                continue
            info_program = getattr(info, "program", None)
            decompiler: GhidraDecompInterface | None = getattr(info, "decompiler", None)
            if decompiler is not None:
                try:
                    decompiler.closeProgram()
                except Exception:
                    pass
                try:
                    decompiler.dispose()
                except Exception:
                    pass
            if info_program is not None:
                self._end_open_transaction_on_program_pull(info_program)
                released = False
                doc = getattr(info, "domain_object_consumer", None)
                seen_ids: set[int] = set()
                ordered: list[Any] = []
                for c in (doc, None, ghidra_project):
                    cid = id(c) if c is not None else 0
                    if cid in seen_ids:
                        continue
                    seen_ids.add(cid)
                    ordered.append(c)
                for consumer in ordered:
                    try:
                        info_program.release(consumer)
                        released = True
                        break
                    except Exception:
                        continue
                if not released:
                    logger.debug("program.release failed for both consumers key=%r", basename_hint(key))
                if ghidra_project is not None:
                    try:
                        if hasattr(info_program, "isClosed") and not info_program.isClosed():
                            ghidra_project.close(info_program)
                    except Exception:
                        pass

        for key in stale_keys:
            session_ctx.open_programs.pop(key, None)

        if session_ctx.active_program_key in stale_keys:
            session_ctx.active_program_key = next(iter(session_ctx.open_programs.keys()), None)

        filtered_binaries: list[dict[str, Any]] = []
        for item in SESSION_CONTEXTS.get_project_binaries(session_id):
            item_path = str(item.get("path") or "").strip().lower().lstrip("/")
            item_name = str(item.get("name") or Path(item_path).name).strip().lower().lstrip("/")
            if requested_l in {item_name, item_path}:
                continue
            filtered_binaries.append(item)
        SESSION_CONTEXTS.set_project_binaries(session_id, filtered_binaries)

    def _remove_shared_repository_item(self, program_path: str) -> dict[str, Any] | None:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._remove_shared_repository_item")
        session_id, handle, repository_adapter, repository_name = self._get_shared_session_context()
        if not handle or not is_shared_server_handle(handle) or repository_adapter is None:
            return None

        requested: str = self._normalize_repo_path(program_path)
        requested_l: str = requested.strip().lower().lstrip("/")
        items = SESSION_CONTEXTS.get_project_binaries(session_id) or self._list_repository_items(repository_adapter)

        matched_path: str | None = None
        for item in items:
            item_path = self._normalize_repo_path(str(item.get("path") or ""))
            item_name = str(item.get("name") or Path(item_path).name)
            if requested_l in {item_path.strip().lower().lstrip("/"), item_name.strip().lower().lstrip("/")}:
                matched_path = item_path
                break

        if matched_path is None:
            return None

        folder_path, _, item_name = matched_path.rpartition("/")
        folder_path = folder_path or "/"

        try:
            repo_item = None
            adapter_folder = folder_path
            for fp in repository_adapter_folder_candidates(folder_path):
                try:
                    ri = repository_adapter.getItem(fp, item_name)
                    if ri is not None:
                        repo_item = ri
                        adapter_folder = fp
                        break
                except Exception:
                    continue
            if repo_item is None:
                return {
                    "success": False,
                    "error": f"Program '{program_path}' was not found in shared repository '{repository_name}'",
                }
            version: int = int(repo_item.getVersion()) if hasattr(repo_item, "getVersion") else -1
            self._remove_shared_session_item(session_id, matched_path)
            repository_adapter.deleteItem(adapter_folder, item_name, version)
            refreshed_items: list[dict[str, GhidraRepositoryItem]] = self._list_repository_items(repository_adapter)
            SESSION_CONTEXTS.set_project_binaries(session_id, refreshed_items)
            return {
                "success": True,
                "programPath": matched_path,
                "removed": True,
                "storage": "shared-repository",
                "removalMode": "repository-item",
                "repository": repository_name,
            }
        except Exception as exc:
            return {
                "success": False,
                "error": str(exc),
                "programPath": matched_path,
                "storage": "shared-repository",
                "removalMode": "repository-item",
                "repository": repository_name,
            }

    async def _handle_remove_program_binary(self, args: dict[str, Any]) -> list[types.TextContent]:
        """Remove a program from the current Ghidra project via GhidraDomainFile API.

        This NEVER deletes the source binary file from the host filesystem.
        It removes the program object from the currently open Ghidra project,
        regardless of whether that project is shared (versioned) or local.
        """
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._handle_remove_program_binary")
        program_path: str = self._require_str(args, "programpath", "binaryname", "binary", name="programPath")
        confirm = self._get_bool(args, "confirm", default=False)
        if not confirm:
            return create_success_response(
                {
                    "success": False,
                    "error": "Confirmation required: set confirm=true to remove the program from the repository.",
                },
            )

        shared_result: dict[str, Any] | None = self._remove_shared_repository_item(program_path)
        if shared_result is not None:
            return create_success_response(shared_result)

        if self.program_info is None:
            return create_success_response({"success": False, "error": "No program loaded"})

        program: GhidraProgram = self.program_info.program
        if program is None:
            return create_success_response({"success": False, "error": "No active program"})

        domain_file: GhidraDomainFile | None = program.getDomainFile()
        if domain_file is None:
            return create_success_response({"success": False, "error": "No domain file associated with current program"})

        # Detect storage type for response metadata.
        is_versioned = False
        try:
            is_versioned = bool(domain_file.isVersioned())
        except Exception:
            pass

        # Verify the requested path matches the active program
        if program_path not in (program.getName(), str(domain_file.getPathname()), domain_file.getName()):
            return create_success_response({"success": False, "error": f"Requested program '{program_path}' does not match active program"})

        ghidra_project: GhidraProject | None = getattr(self._manager, "ghidra_project", None) if self._manager else None
        if ghidra_project is not None:
            try:
                ghidra_project.close(program)
            except Exception:
                pass
        try:
            program.release(None)
        except Exception:
            pass

        self.program_info = None

        try:
            deleted = bool(domain_file.delete())
        except Exception as exc:
            return create_success_response({"success": False, "error": str(exc)})

        removal_mode = "domain-file"
        session_id: str = get_current_mcp_session_id()
        requested_l = program_path.strip().lower().lstrip("/")
        active_name_l = str(domain_file.getName()).strip().lower().lstrip("/")
        active_path_l = str(domain_file.getPathname()).strip().lower().lstrip("/")

        if not deleted:
            # Some local/headless flows keep binaries in session catalog only.
            # If GhidraDomainFile deletion reports false, prune session state directly.
            session_binaries = SESSION_CONTEXTS.get_project_binaries(session_id)
            filtered_binaries: list[dict[str, Any]] = []
            removed_from_session = False
            for item in session_binaries:
                item_path = str(item.get("path") or "").strip().lower().lstrip("/")
                item_name = str(item.get("name") or Path(item_path).name).strip().lower().lstrip("/")
                if requested_l in {item_name, item_path, active_name_l, active_path_l}:
                    removed_from_session = True
                    continue
                filtered_binaries.append(item)

            self._remove_shared_session_item(session_id, program_path)
            removed_from_session = removed_from_session or requested_l in {active_name_l, active_path_l}

            if removed_from_session:
                SESSION_CONTEXTS.set_project_binaries(session_id, filtered_binaries)
                deleted = True
                removal_mode = "session-catalog"

        return create_success_response(
            {
                "success": deleted,
                "programPath": program_path,
                "removed": deleted,
                "storage": "shared-repository" if is_versioned else "local-project",
                "removalMode": removal_mode,
            },
        )

    # Legacy alias preserved for backward compatibility
    _handle_delete_project_binary = _handle_remove_program_binary

    async def _handle_get_current_address(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._handle_get_current_address")
        return create_success_response(
            {
                "success": False,
                "error": "get-current-address requires GUI mode (Code Browser context)",
                "headless": True,
            },
        )

    async def _handle_get_current_function(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._handle_get_current_function")
        if self.program_info is None:
            return create_success_response({"success": False, "error": "No program loaded"})

        program: GhidraProgram = self.program_info.program
        fm: GhidraFunctionManager = self._get_function_manager(program)
        first: GhidraFunction | None = None
        for func in fm.getFunctions(True):
            first = func
            break

        if first is None:
            return create_success_response({"success": False, "error": "No functions available"})

        return create_success_response(
            {
                "success": True,
                "headless": True,
                "note": "Headless mode fallback returns first available function",
                "function": {"name": first.getName(), "address": str(first.getEntryPoint())},
            },
        )

    async def _handle_get_current_program(self, args: dict[str, Any]) -> list[types.TextContent]:
        """Return metadata for the currently active program."""
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._handle_get_current_program")

        load_error: str | None = None
        try:
            await self._ensure_program_loaded_for_stateless_request(args)
        except Exception as e:
            load_error = str(e)

        if self.program_info is None:
            # Collect available programs for diagnostics
            available: list[str] = []
            try:
                session_id: str = get_current_mcp_session_id()
                session_binaries = SESSION_CONTEXTS.get_project_binaries(session_id, fallback_to_latest=True)
                available = [str(b.get("path") or b.get("name") or "") for b in session_binaries if b.get("path") or b.get("name")]
            except Exception:
                pass

            if not available:
                # Fall back to walking the ghidra project domain files
                try:
                    ghidra_project: GhidraProject | None = getattr(self._manager, "ghidra_project", None) if self._manager else None
                    if ghidra_project is not None:
                        root_folder: GhidraDomainFolder = ghidra_project.getRootFolder()
                        domain_files: list[dict[str, GhidraDomainFile]] = self._list_domain_files(root_folder, 50)
                        available = [str(f.get("path") or f.get("name") or "") for f in domain_files if f.get("path") or f.get("name")]
                except Exception:
                    pass

            payload: dict[str, Any] = {
                "loaded": False,
                "note": load_error or "No program currently loaded",
                "availablePrograms": available,
                "availableCount": len(available),
            }
            if load_error:
                payload["hint"] = "Pass programPath=<path> to auto-load, or call open with one of the availablePrograms paths above."
            return create_success_response(payload)

        program: GhidraProgram = self.program_info.program
        name: str = str(program.getName()) if hasattr(program, "getName") else "unknown"
        path: str = ""
        try:
            df: GhidraDomainFile | None = program.getDomainFile()
            if df is not None:
                path = str(df.getPathname())
        except Exception:
            pass
        language: str = ""
        compiler: str = ""
        try:
            language = str(program.getLanguageID())
        except Exception:
            pass
        try:
            compiler = str(program.getCompilerSpec().getCompilerSpecID())
        except Exception:
            pass
        function_count: int = 0
        try:
            fm = self._get_function_manager(program)
            function_count = fm.getFunctionCount()
        except Exception:
            pass

        return create_success_response(
            {
                "loaded": True,
                "name": name,
                "programPath": path or name,
                "language": language,
                "compiler": compiler,
                "functionCount": function_count,
            },
        )

    async def _handle_gui_unsupported(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._handle_gui_unsupported")
        return create_success_response(
            {
                "success": False,
                "error": "This operation requires GUI mode (Code Browser)",
                "headless": True,
            },
        )

    def _list_domain_files(self, root_folder: GhidraDomainFolder, max_results: int) -> list[dict[str, GhidraDomainFile]]:
        logger.debug("diag.enter %s", "mcp_server/providers/project.py:ProjectToolProvider._list_domain_files")
        return walk_domain_folder_tree(root_folder, max_results)
