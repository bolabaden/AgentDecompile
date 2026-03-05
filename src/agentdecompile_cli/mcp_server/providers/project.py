"""Project Tool Provider - open, list-project-files.

Handles project and program management operations.
"""

from __future__ import annotations

import logging
import os
import socket
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from mcp import types

from agentdecompile_cli.mcp_server.session_context import (
    SESSION_CONTEXTS,
    get_current_mcp_session_id,
)
from agentdecompile_cli.mcp_server.tool_providers import (
    ActionableError,
    ToolProvider,
    create_success_response,
    filter_recommendations,
    recommend_tool,
    n,
)

if TYPE_CHECKING:
    ...
    from abc import ABC, abstractmethod

    class ProjectData(ABC):
        @abstractmethod
        def getFile(self, filePath: str) -> ProjectData: ...
        @abstractmethod
        def getFolder(self, folderPath: str) -> ProjectData: ...
        @abstractmethod
        def getRootFolder(self) -> ProjectData: ...
        @abstractmethod
        def createFolder(self, folderPath: str) -> ProjectData: ...
        @abstractmethod
        def getPathname(self) -> str: ...

    class RepoItem(ABC):
        @abstractmethod
        def getDomainFile(self): ...

    class RepoAdapter(ABC):
        @abstractmethod
        def getItem(self, folderPath: str, itemName: str): ...
        @abstractmethod
        def getVersion(self): ...
        @abstractmethod
        def openDatabase(self, folderPath: str, itemName: str, version: int, monitor: Any) -> Any: ...


logger = logging.getLogger(__name__)


class ProjectToolProvider(ToolProvider):
    HANDLERS: ClassVar[dict[str, str]] = {
        "openproject": "_handle_open_project",
        "listprojectfiles": "_handle_list",
        "syncsharedproject": "_handle_sync_shared_project",
        "downloadsharedrepository": "_handle_download_shared_repository",
        "managefiles": "_handle_manage",
        "connectsharedproject": "_handle_connect_shared_project",
        "deleteprojectbinary": "_handle_delete_project_binary",
        "getcurrentaddress": "_handle_get_current_address",
        "getcurrentfunction": "_handle_get_current_function",
        "getcurrentprogram": "_handle_get_current_program",
        "openprogramincodebrowser": "_handle_gui_unsupported",
        "openallprogramsincodebrowser": "_handle_gui_unsupported",
        "importfile": "_handle_import_file_alias",
    }

    def list_tools(self) -> list[types.Tool]:
        return [
            types.Tool(
                name="open-project",
                description="Open a local binary/project or connect to a shared Ghidra repository server.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Local file path, .gpr path, or repository name."},
                        "serverHost": {"type": "string", "description": "Ghidra server host (shared project mode)."},
                        "serverPort": {"type": "integer", "description": "Ghidra server port (default: 13100)."},
                        "serverUsername": {"type": "string", "description": "Repository authentication username."},
                        "serverPassword": {"type": "string", "description": "Repository authentication password."},
                        "analyzeAfterImport": {"type": "boolean", "default": False, "description": "Run analysis after import."},
                        "openAllPrograms": {"type": "boolean", "default": False, "description": "Open all programs in project."},
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
                name="list-project-files",
                description="List project files.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "Program path."},
                        "binary": {"type": "string", "description": "Program path."},
                        "folder": {"type": "string", "default": "/", "description": "Project folder."},
                        "path": {"type": "string", "description": "Filesystem path (non-project mode)."},
                        "maxResults": {"type": "integer", "default": 100, "description": "Max results."},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="sync-shared-project",
                description="Sync with shared repository.",
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
                        "maxResults": {"type": "integer", "default": 100000, "description": "Max items."},
                        "force": {"type": "boolean", "default": False, "description": "Overwrite conflicts."},
                        "dryRun": {"type": "boolean", "default": False, "description": "Simulate only."},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="manage-files",
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
                        "maxResults": {"type": "integer", "default": 200, "description": "Max results."},
                        "maxDepth": {"type": "integer", "default": 16, "description": "Max depth."},
                        "analyzeAfterImport": {"type": "boolean", "default": False, "description": "Run analysis after import."},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="delete-project-binary",
                description="Delete a project binary.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "binaryName": {"type": "string", "description": "Binary name."},
                        "binary_name": {"type": "string"},
                        "programPath": {"type": "string"},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="list-open-programs",
                description="List open programs (GUI/headless compatible)",
                inputSchema={"type": "object", "properties": {}, "required": []},
            ),
            types.Tool(
                name="get-current-address",
                description="Get current address (GUI-only, headless-safe)",
                inputSchema={"type": "object", "properties": {}, "required": []},
            ),
            types.Tool(
                name="get-current-function",
                description="Get current function (GUI-only, headless-safe)",
                inputSchema={"type": "object", "properties": {}, "required": []},
            ),
            types.Tool(
                name="open-program-in-code-browser",
                description="Open program in Code Browser (GUI-only)",
                inputSchema={"type": "object", "properties": {"programPath": {"type": "string"}}, "required": []},
            ),
            types.Tool(
                name="get-current-program",
                description="Retrieve metadata for the currently active program, including name, path, language, compiler, and analysis status.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "Program path to verify (uses current if omitted)."},
                    },
                    "required": [],
                },
            ),
        ]

    async def _handle_open_project(self, args: dict[str, Any]) -> list[types.TextContent]:
        """Legacy open-project dispatcher: routes to connect-shared-project or manage-files"""
        server_host = self._get_str(args, "serverhost")
        if server_host:
            return await self._handle_connect_shared_project(args)
        return await self._handle_open(args)

    async def _handle_connect_shared_project(self, args: dict[str, Any]) -> list[types.TextContent]:
        """Connect to shared Ghidra repository server and list available binaries."""
        session_id: str = get_current_mcp_session_id()

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

        server_host: str = self._require_str(args, "serverhost", name="serverHost")
        server_port: int = self._get_int(args, "serverport", "port", default=13100)
        server_username: str = self._get_str(args, "serverusername", "username")
        server_password: str = self._get_str(args, "serverpassword", "password")
        path: str = self._get_str(args, "path", "programpath", "repositoryname", "binaryname", "binary", default="")

        auth_provided = bool(server_username and server_password)
        server_reachable = False

        try:
            with socket.create_connection((server_host, server_port), timeout=5):
                server_reachable = True
        except OSError as exc:
            raise ActionableError(
                f"Ghidra server not reachable at {server_host}:{server_port}: {exc}",
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
            try:
                from java.lang import System as JavaSystem  # pyright: ignore[reportMissingImports]

                original_user_name = JavaSystem.getProperty("user.name")
                JavaSystem.setProperty("user.name", server_username)
            except Exception:
                original_user_name = None

            try:
                from ghidra.util import SystemUtilities  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

                field: Any = SystemUtilities.class_.getDeclaredField("userName")
                field.setAccessible(True)
                field.set(None, server_username)
            except Exception:
                pass

        if server_username and server_password:
            ClientUtil.setClientAuthenticator(PasswordClientAuthenticator(server_username, server_password))

        try:
            ClientUtil.clearRepositoryAdapter(server_host, server_port)
        except Exception:
            pass

        server_adapter = ClientUtil.getRepositoryServer(server_host, server_port, True)
        if server_adapter is None:
            raise ActionableError(
                f"Failed to connect to repository server: {server_host}:{server_port}",
                context={"mode": "shared-server", "serverHost": server_host, "serverPort": server_port},
                next_steps=[
                    "Verify repository server endpoint and network reachability.",
                    "Retry with valid server credentials.",
                ],
            )

        if not server_adapter.isConnected():
            try:
                server_adapter.connect()
            except Exception as exc:
                exc_text = str(exc)
                if auth_provided:
                    raise ActionableError(
                        f"Authentication failed for {server_username}@{server_host}:{server_port}: {exc_text}",
                        context={"mode": "shared-server", "serverHost": server_host, "serverPort": server_port, "serverUsername": server_username},
                        next_steps=[
                            "Verify `serverUsername` and `serverPassword` for the Ghidra repository server.",
                            "Retry after confirming the user has access.",
                        ],
                    ) from exc
                raise ActionableError(
                    f"Repository connection failed for {server_host}:{server_port}: {exc_text}",
                    context={"mode": "shared-server", "serverHost": server_host, "serverPort": server_port},
                    next_steps=[
                        "Verify server availability and repository service status.",
                        "Retry after server-side issues are resolved.",
                    ],
                ) from exc

            if not server_adapter.isConnected():
                last_error: Any = getattr(server_adapter, "getLastConnectError", lambda: None)()
                message = str(last_error) if last_error else "unknown authentication/connection failure"
                if auth_provided:
                    raise ActionableError(
                        f"Authentication failed for {server_username}@{server_host}:{server_port}: {message}",
                        context={"mode": "shared-server", "serverHost": server_host, "serverPort": server_port, "serverUsername": server_username},
                        next_steps=[
                            "Verify server credentials and account permissions.",
                            "Retry once credentials are corrected.",
                        ],
                    )
                raise ActionableError(
                    f"Repository connection failed for {server_host}:{server_port}: {message}",
                    context={"mode": "shared-server", "serverHost": server_host, "serverPort": server_port},
                    next_steps=[
                        "Check repository server health/logs and network routing.",
                        "Retry after connectivity is restored.",
                    ],
                )

        try:
            repository_names_raw = server_adapter.getRepositoryNames() or []
        except Exception as exc:
            exc_text = str(exc)
            if auth_provided:
                raise ActionableError(
                    f"Authentication failed for {server_username}@{server_host}:{server_port}: {exc_text}",
                    context={"mode": "shared-server", "serverHost": server_host, "serverPort": server_port, "serverUsername": server_username},
                    next_steps=[
                        "Verify credentials and repository visibility permissions.",
                        "Retry with a repository name in `path.`",
                    ],
                ) from exc
            raise ActionableError(
                f"Repository server connection failed for {server_host}:{server_port}: {exc_text}",
                context={"mode": "shared-server", "serverHost": server_host, "serverPort": server_port},
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
        if not repository_names:
            raise ActionableError(
                f"No repositories found on {server_host}:{server_port}",
                context={"mode": "shared-server", "serverHost": server_host, "serverPort": server_port},
                next_steps=[
                    "Confirm the account has at least one visible repository on the server.",
                    "Retry with a repository name in `path` once access is granted.",
                ],
            )

        repository_name: str | None = None
        checkout_program_path: str | None = None

        if path and path.strip():
            if path in repository_names:
                repository_name = path
            else:
                checkout_program_path = path
                repository_name = repository_names[0]
        else:
            repository_name = repository_names[0]

        repository_adapter: Any = server_adapter.getRepository(repository_name)
        if repository_adapter is None:
            raise ActionableError(
                f"Failed to get repository handle for '{repository_name}'",
                context={"mode": "shared-server", "repository": repository_name},
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
                        f"Authentication failed while opening repository '{repository_name}': {exc_text}",
                        context={"mode": "shared-server", "repository": repository_name, "serverHost": server_host, "serverPort": server_port},
                        next_steps=[
                            "Verify credentials and repository-level permissions.",
                            "Retry after confirming access to this repository.",
                        ],
                    ) from exc
                raise ActionableError(
                    f"Failed to connect repository '{repository_name}': {exc_text}",
                    context={"mode": "shared-server", "repository": repository_name, "serverHost": server_host, "serverPort": server_port},
                    next_steps=[
                        "Verify repository service health and access controls.",
                        "Retry with a known-good repository.",
                    ],
                ) from exc

            if not repository_adapter.isConnected():
                if auth_provided:
                    raise ActionableError(
                        f"Authentication failed while opening repository '{repository_name}'",
                        context={"mode": "shared-server", "repository": repository_name, "serverHost": server_host, "serverPort": server_port},
                        next_steps=[
                            "Verify credentials and repository membership.",
                            "Retry after credentials are corrected.",
                        ],
                    )
                raise ActionableError(
                    f"Failed to connect repository '{repository_name}'",
                    context={"mode": "shared-server", "repository": repository_name, "serverHost": server_host, "serverPort": server_port},
                    next_steps=[
                        "Check repository server status and endpoint routing.",
                        "Retry after connectivity is restored.",
                    ],
                )

        binaries: list[dict[str, Any]] = self._list_repository_items(repository_adapter)

        SESSION_CONTEXTS.set_project_handle(
            session_id,
            {
                "mode": "shared-server",
                "server_host": server_host,
                "server_port": server_port,
                "server_adapter": server_adapter,
                "repository_name": repository_name,
                "repository_adapter": repository_adapter,
            },
        )
        SESSION_CONTEXTS.set_project_binaries(session_id, binaries)

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
                if (b.get("name") or "") == norm_target.split("/")[-1]:
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

        return create_success_response(
            {
                "action": "connect-shared-project",
                "mode": "shared-server",
                "serverHost": server_host,
                "serverPort": server_port,
                "serverReachable": server_reachable,
                "serverConnected": bool(server_adapter.isConnected()),
                "authProvided": auth_provided,
                "serverUsername": server_username if server_username else None,
                "repository": repository_name,
                "availableRepositories": repository_names,
                "programCount": len(binaries),
                "programs": binaries,
                "checkedOutProgram": checked_out_program,
                "checkoutError": checkout_error,
                "message": (
                    f"Connected to shared repository '{repository_name}' and discovered {len(binaries)} items."
                    + (f" Checked out: {checked_out_program}" if checked_out_program else "")
                ),
            },
        )

    async def _handle_open(self, args: dict[str, Any]) -> list[types.TextContent]:
        """Open a program or project from local filesystem or current project."""
        path: str = self._get_str(args, "programpath", "filepath", "file", "path", "program", "binary")

        if not path or not path.strip():
            raise ActionableError(
                "programPath or filePath required",
                context={"action": "open", "mode": "local-or-project"},
                next_steps=[
                    "Call with `path` pointing to a local binary, project file (`.gpr`), or directory.",
                    "For shared server usage, use `connect-shared-project` tool instead.",
                ],
            )

        resolved: Path = Path(path).expanduser().resolve()
        if not resolved.exists():
            normalized_project_path = self._normalize_repo_path(path)
            project_data = self._get_active_project_data()
            if project_data is not None:
                try:
                    domain_file = project_data.getFile(normalized_project_path)
                except Exception:
                    domain_file = None

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
                f"Path does not exist: {resolved}",
                context={"action": "open", "path": str(resolved), "state": "path-not-found"},
                next_steps=filter_recommendations([
                    "Call `{}` with `mode=list` on the parent directory to verify available files.".format(recommend_tool("manage-files", "list-project-files") or "list-project-files"),
                    "Retry with an absolute path that exists in the backend filesystem.",
                ]),
            )

        if resolved.is_file() and resolved.suffix.lower() not in (".gpr",):
            return await self._import_file(str(resolved), args)

        files_discovered: int = 0
        if resolved.is_dir():
            extensions: list[str] = self._get_list(args, "extensions") or []
            patterns: list[str] = [e.lower() for e in extensions] if extensions else []
            for file_path in resolved.rglob("*"):
                if not file_path.is_file():
                    continue
                if patterns and file_path.suffix.lower() not in patterns:
                    continue
                files_discovered += 1

        return create_success_response(
            {
                "action": "open",
                "path": str(resolved),
                "exists": True,
                "isDirectory": resolved.is_dir(),
                "isProject": resolved.suffix.lower() == ".gpr" or resolved.is_dir(),
                "filesDiscovered": files_discovered,
                "note": "Path resolved. Use manage-files mode=import for explicit binary imports.",
            },
        )

    async def _handle_list(self, args: dict[str, Any]) -> list[types.TextContent]:
        await self._ensure_program_loaded_for_stateless_request(args)

        folder: str = self._get_str(args, "folder", "path", default="/")
        max_results: int = self._get_int(args, "maxresults", "limit", default=100)
        session_id: str = get_current_mcp_session_id()

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
            session_binaries: list[dict[str, Any]] = SESSION_CONTEXTS.get_project_binaries(session_id, fallback_to_latest=True)
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
            return create_success_response({"folder": folder, "files": [], "count": 0, "note": "No project loaded"})

        try:
            project_data: Any = self._get_active_project_data()
            if project_data is None:
                raise ValueError("No project data available")

            target_folder: Any = None
            normalized_folder: str = self._normalize_repo_path(folder)
            if normalized_folder == "/":
                target_folder = project_data.getRootFolder()
            else:
                target_folder = project_data.getFolder(normalized_folder)
                if target_folder is None:
                    return create_success_response({"folder": normalized_folder, "files": [], "count": 0})

            files = self._list_domain_files(target_folder, max_results)
            return create_success_response({"folder": folder, "files": files, "count": len(files)})
        except Exception as e:
            session_binaries: list[dict[str, Any]] = SESSION_CONTEXTS.get_project_binaries(session_id, fallback_to_latest=True)
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

    async def _ensure_program_loaded_for_stateless_request(self, args: dict[str, Any]) -> None:
        program = getattr(self.program_info, "program", None) if self.program_info is not None else None
        if program is not None:
            return

        requested_program: str | None = self._get_str(args, "programpath", "binary", "binaryname")
        if not requested_program:
            return

        open_args: dict[str, Any] = {
            "path": requested_program,
        }

        server_host = self._get_str(args, "serverhost", "ghidraserverhost") or os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_HOST", os.getenv("AGENT_DECOMPILE_SERVER_HOST", os.getenv("AGENTDECOMPILE_SERVER_HOST", ""))).strip()
        if server_host:
            open_args["serverhost"] = server_host
            open_args["serverport"] = self._get_int(args, "serverport", "ghidraserverport", default=int(os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_PORT", os.getenv("AGENT_DECOMPILE_SERVER_PORT", os.getenv("AGENTDECOMPILE_SERVER_PORT", "13100"))) or "13100"))
            open_args["serverusername"] = self._get_str(args, "serverusername", "ghidraserverusername") or os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME", os.getenv("AGENT_DECOMPILE_SERVER_USERNAME", os.getenv("AGENTDECOMPILE_SERVER_USERNAME", ""))).strip()
            open_args["serverpassword"] = self._get_str(args, "serverpassword", "ghidraserverpassword") or os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD", os.getenv("AGENT_DECOMPILE_SERVER_PASSWORD", os.getenv("AGENTDECOMPILE_SERVER_PASSWORD", ""))).strip()
            repository_name: str | None = (
                self._get_str(args, "repositoryname", "ghidraserverrepository")
                or os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY", os.getenv("AGENTDECOMPILE_GHIDRA_SERVER_REPOSITORY", "")).strip()
                or os.getenv("AGENT_DECOMPILE_REPOSITORY", os.getenv("AGENTDECOMPILE_REPOSITORY", "")).strip()
            )
            if repository_name:
                open_args["repositoryname"] = repository_name

        try:
            await self._handle_open(open_args)
        except Exception as e:
            logger.debug(f"Auto-open failed for stateless request ({requested_program}): {e}")

    async def _ensure_program_loaded_for_args(self, args: dict[str, Any]) -> None:
        await self._ensure_program_loaded_for_stateless_request(args)

    async def _handle_manage(self, args: dict[str, Any]) -> list[types.TextContent]:
        operation: str = self._require_str(args, "mode", "action", "operation", name="mode")

        return await self._dispatch_handler(
            args,
            operation,
            {
                "open": "_handle_open",
                "openproject": "_handle_open",
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
        operation = self._get_str(args, "mode", "action", "operation", default="unknown")
        manage_files_tool = recommend_tool("manage-files")
        if manage_files_tool:
            steps = [
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
        file_path: str | None = self._get_str(args, "filepath", "file", "path", "programpath")
        if not file_path:
            manage_files_tool = recommend_tool("manage-files")
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
        return await self._export_current_program(args)

    async def _handle_change_processor(self, args: dict[str, Any]) -> list[types.TextContent]:
        await self._ensure_program_loaded_for_args(args)
        self._require_program()
        assert self.program_info is not None

        language = self._get_str(args, "languageid", "language", "lang")
        processor = self._get_str(args, "processor")
        compiler = self._get_str(args, "compilerspecid", "compiler", "compilerspec")
        endian = self._get_str(args, "endian")

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

        program = self.program_info.program
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
        operation = self._get_str(args, "mode", "action", "operation", default="syncshared")
        op = n(operation)
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
        program_path: str | None = self._get_str(args, "programpath", "filepath", "file", "path")
        domain_file = self._resolve_domain_file(program_path)
        if domain_file is None:
            self._raise_domain_file_error("checkout", program_path)
        exclusive = self._get_bool(args, "exclusive", default=False)
        if hasattr(domain_file, "checkout"):
            from ghidra.util.task import TaskMonitor  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

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
        program_path: str | None = self._get_str(args, "programpath", "filepath", "file", "path")
        domain_file = self._resolve_domain_file(program_path)
        if domain_file is None:
            self._raise_domain_file_error("uncheckout", program_path)
        keep = self._get_bool(args, "keep", default=False)
        force = self._get_bool(args, "force", default=False)
        if hasattr(domain_file, "undoCheckout"):
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
        program_path: str | None = self._get_str(args, "programpath", "filepath", "file", "path")
        domain_file = self._resolve_domain_file(program_path)
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
        has_program = self.program_info is not None and getattr(self.program_info, "program", None) is not None
        has_df = False
        df_path = None
        if has_program:
            try:
                assert self.program_info is not None
                df = self.program_info.program.getDomainFile()
                has_df = df is not None
                df_path = str(df.getPathname()) if df else None
            except Exception:
                pass
        pd = self._get_active_project_data()
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
                "Call `open` for the target program path so a project-backed domain file is active.",
                "Call `list-project-files` to confirm the program exists in the current project/session.",
            ],
        )

    async def _handle_mkdir(self, args: dict[str, Any]) -> list[types.TextContent]:
        return await self._handle_filesystem_operation_blocked(args)

    async def _handle_touch(self, args: dict[str, Any]) -> list[types.TextContent]:
        return await self._handle_filesystem_operation_blocked(args)

    async def _handle_list_files(self, args: dict[str, Any]) -> list[types.TextContent]:
        file_path: str | None = self._get_str(args, "filepath", "file", "path", "programpath")
        max_results: int = self._get_int(args, "maxresults", default=200)
        base_path = Path(file_path).expanduser().resolve() if file_path else Path.cwd()
        if not base_path.exists():
            manage_files_tool = recommend_tool("manage-files", "list-project-files")
            steps = [
                "Run `{}` `mode=list` on the parent directory to discover valid paths.".format(manage_files_tool or "list-project-files"),
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
        return await self._handle_filesystem_operation_blocked(args)

    async def _handle_read(self, args: dict[str, Any]) -> list[types.TextContent]:
        return await self._handle_filesystem_operation_blocked(args)

    async def _handle_write(self, args: dict[str, Any]) -> list[types.TextContent]:
        return await self._handle_filesystem_operation_blocked(args)

    async def _handle_append(self, args: dict[str, Any]) -> list[types.TextContent]:
        return await self._handle_filesystem_operation_blocked(args)

    async def _handle_rename(self, args: dict[str, Any]) -> list[types.TextContent]:
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
            manage_files_tool = recommend_tool("manage-files")
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

        domain_file = self._resolve_domain_file(program_path)
        if domain_file is None:
            self._raise_domain_file_error("rename", program_path)

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

        domain_file = self._resolve_domain_file(program_path)
        if domain_file is None:
            self._raise_domain_file_error("delete", program_path)

        target_path = str(domain_file.getPathname()) if hasattr(domain_file, "getPathname") else str(program_path)
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
        return await self._handle_filesystem_operation_blocked(args)

    async def _handle_move(self, args: dict[str, Any]) -> list[types.TextContent]:
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

        domain_file = self._resolve_domain_file(program_path)
        if domain_file is None:
            self._raise_domain_file_error("move", program_path)

        project_data = self._get_active_project_data()
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
        normalized_destination = self._normalize_repo_path(destination)
        current_name = str(domain_file.getName()) if hasattr(domain_file, "getName") else Path(str(program_path)).name
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

            current_after_move = str(domain_file.getName()) if hasattr(domain_file, "getName") else current_name
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

    async def _handle_sync_shared_project(self, args: dict[str, Any]) -> list[types.TextContent]:
        return await self._sync_shared_repository(args, default_mode="pull")

    async def _handle_download_shared_repository(self, args: dict[str, Any]) -> list[types.TextContent]:
        return await self._handle_sync_shared_project(args)

    def _resolve_domain_file(self, program_path: str | None) -> Any:
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
            project_data = self._get_active_project_data()
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
            session_id = get_current_mcp_session_id()
            session = SESSION_CONTEXTS.get_or_create(session_id)
            handle = session.project_handle if isinstance(session.project_handle, dict) else None
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
        session_id: str = get_current_mcp_session_id()
        source: Path = Path(file_path).expanduser().resolve()
        if not source.exists():
            raise ValueError(f"Import path not found: {source}")

        recursive: bool = self._get_bool(args, "recursive", default=source.is_dir())
        max_depth: int = self._get_int(args, "maxdepth", default=16)
        analyze: bool = self._get_bool(args, "analyzeafterimport", default=False)

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

        project_handle: Any = None
        ghidra_project: Any = getattr(self._manager, "ghidra_project", None) if self._manager else None
        if ghidra_project is not None:
            project_handle = ghidra_project
            try:
                if not hasattr(project_handle, "importProgram"):
                    project_handle = ghidra_project.getProject()
            except Exception:
                pass

        for entry in discovered:
            try:
                from java.io import File  # pyright: ignore[reportMissingImports]

                if project_handle is None:
                    raise RuntimeError("No active Ghidra project context available for import")

                program: Any = project_handle.importProgram(File(str(entry)))
                if program is None:
                    raise RuntimeError("import_binary returned None")

                from agentdecompile_cli.launcher import ProgramInfo

                decompiler: Any = None
                try:
                    from agentdecompile_cli.decompiled_function_analyzer import DecompiledFunctionAnalyzer  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

                    decompiler = DecompiledFunctionAnalyzer(program)
                except Exception:
                    decompiler = None

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
            except Exception as exc:
                errors.append({"path": str(entry), "error": str(exc)})

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
        if self.program_info is None:
            raise ValueError("No program loaded for export")

        out_path = self._get_str(args, "newpath", "destinationpath", "path", "filepath")
        if not out_path:
            raise ValueError("path/newPath is required for export")

        output: Path = Path(out_path).expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)

        program: Any = self.program_info.program
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

    def _get_active_project_data(self):
        logger.info("shared-sync getting active project data start")
        ghidra_project: Any = getattr(self._manager, "ghidra_project", None) if self._manager else None
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
                    pass

        if self.program_info is not None and getattr(self.program_info, "program", None) is not None:
            try:
                domain_file = self.program_info.program.getDomainFile()
                if domain_file is not None:
                    project_data = domain_file.getProjectData()
                    logger.info("shared-sync got project data from program_info domain_file")
                    return project_data
            except Exception:
                logger.info("shared-sync failed to get project data from program_info")
                pass

        logger.info("shared-sync no active project data found")
        return None

    def _open_program_from_domain_file(self, domain_file: Any) -> Any:
        ghidra_project: Any = getattr(self._manager, "ghidra_project", None) if self._manager else None
        if ghidra_project is not None:
            try:
                opened_program = ghidra_project.openProgram(domain_file)
                if opened_program is not None:
                    return opened_program
            except Exception:
                pass

        from ghidra.util.task import TaskMonitor  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

        return self._get_domain_object_compat(domain_file, TaskMonitor.DUMMY)

    def _get_domain_object_compat(self, holder: Any, monitor: Any) -> Any:
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

    def _set_active_program_info(self, program: Any, program_path: str) -> None:
        from ghidra.app.decompiler import DecompileOptions, DecompInterface  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

        from agentdecompile_cli.launcher import ProgramInfo

        decompiler = DecompInterface()
        decomp_options = DecompileOptions()
        decomp_options.grabFromProgram(program)
        decompiler.setOptions(decomp_options)
        decompiler.openProgram(program)

        session_id: str = get_current_mcp_session_id()
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
        if self._manager is not None:
            self._manager.set_program_info(program_info)
        else:
            self.set_program_info(program_info)

    def _ensure_project_folder(self, project_data: ProjectData, folder_path: str):
        normalized: str = self._normalize_repo_path(folder_path)
        if normalized == "/":
            return project_data.getRootFolder()

        folder: Any = project_data.getFolder(normalized)
        if folder is not None:
            return folder

        current: Any = project_data.getRootFolder()
        for component in normalized.strip("/").split("/"):
            if not component:
                continue
            child: Any = current.getFolder(component)
            if child is None:
                child = current.createFolder(component)
            current = child
        return current

    def _resolve_shared_sync_mode(self, args: dict[str, Any], default_mode: str = "pull") -> str:
        # Check direction-specific keys first, then fall back to generic 'mode'.
        # When routed through manage-files, 'mode' contains the operation alias
        # (e.g. 'pull-shared') which also resolves correctly.
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

    def _get_shared_session_context(self) -> tuple[str, dict[str, Any] | None, Any, str | None]:
        session_id: str = get_current_mcp_session_id()
        session: Any = SESSION_CONTEXTS.get_or_create(session_id)
        handle = session.project_handle if isinstance(session.project_handle, dict) else None
        repository_adapter: Any = handle.get("repository_adapter") if handle else None
        repository_name: str | None = handle.get("repository_name") if handle else None
        logger.info(
            "shared-sync session context session_id=%s has_handle=%s handle_mode=%s has_repository_adapter=%s repository=%s",
            session_id,
            bool(handle),
            (handle or {}).get("mode") if isinstance(handle, dict) else None,
            repository_adapter is not None,
            repository_name,
        )
        return session_id, handle, repository_adapter, repository_name

    def _pull_shared_repository_to_local(
        self,
        args: dict[str, Any],
        repository_adapter: Any,
        repository_name: str | None,
        project_data: Any,
    ) -> dict[str, Any]:
        start_time = time.time()
        source_folder = self._normalize_repo_path(
            self._get_str(args, "path", "sourcepath", "folder", default="/"),
        )
        destination_folder = self._normalize_repo_path(
            self._get_str(args, "newpath", "destinationpath", "destinationfolder", default="/"),
        )
        recursive: bool = self._get_bool(args, "recursive", default=True)
        max_results: int = self._get_int(args, "maxresults", "limit", default=100000)
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

        from ghidra.util.task import TaskMonitor  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

        session_id: str = get_current_mcp_session_id()
        items: list[dict[str, Any]] = SESSION_CONTEXTS.get_project_binaries(session_id, fallback_to_latest=True)
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

        monitor: Any = TaskMonitor.DUMMY
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
            existing: Any = project_data.getFile(target_path)
            if existing is not None and not force:
                logger.debug("shared-sync pull skip already exists source=%s target=%s", repo_path, target_path)
                skipped.append({"sourcePath": repo_path, "targetPath": target_path, "reason": "already-exists"})
                continue

            if dry_run:
                logger.info("shared-sync pull dry-run planned source=%s target=%s", repo_path, target_path)
                transferred.append({"sourcePath": repo_path, "targetPath": target_path, "planned": True})
                continue

            parts = repo_path.rsplit("/", 1)
            repo_folder = parts[0] if len(parts) == 2 else "/"
            item_name = parts[1] if len(parts) == 2 else parts[0]
            target_parent_path = target_path.rsplit("/", 1)[0] or "/"

            try:
                if existing is not None and force and hasattr(existing, "delete"):
                    logger.info("shared-sync pull deleting existing target due to force target=%s", target_path)
                    existing.delete()

                parent_folder: Any = self._ensure_project_folder(project_data, target_parent_path)
                remote_domain_obj: Any = None
                repo_item: Any = None

                # Strategy 1: Open via project_data DomainFile (works when files are
                # already visible through the shared-server project connection).
                try:
                    source_df = project_data.getFile(repo_path)
                    if source_df is not None:
                        logger.info("shared-sync pull strategy=project_data_domain_file source=%s", repo_path)
                        remote_domain_obj = self._get_domain_object_compat(source_df, monitor)
                except Exception:
                    logger.info("shared-sync pull strategy=project_data_domain_file failed source=%s", repo_path, exc_info=True)
                    pass

                # Strategy 2: Use RepositoryItem if we have a working adapter.
                if remote_domain_obj is None:
                    logger.info("shared-sync pull strategy=repository_item source=%s folder=%s item=%s", repo_path, repo_folder, item_name)
                    repo_item = repository_adapter.getItem(repo_folder, item_name)
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
                        from ghidra.framework.data import OpenMode  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
                        from ghidra.program.database import ProgramDB  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
                        from java.lang import Object as JavaObject  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

                        repo_item = repository_adapter.getItem(repo_folder, item_name) if repo_item is None else repo_item
                        if repo_item is not None:
                            version = int(repo_item.getVersion()) if hasattr(repo_item, "getVersion") else -1
                            managed_db = repository_adapter.openDatabase(repo_folder, item_name, version, 0)
                            db_handle = DBHandle(managed_db)
                            try:
                                remote_domain_obj = ProgramDB(db_handle, OpenMode.UPDATE, monitor, JavaObject())
                            except Exception:
                                remote_domain_obj = ProgramDB(db_handle, OpenMode.IMMUTABLE, monitor, JavaObject())
                    except Exception:
                        logger.info("shared-sync pull strategy=programdb_fallback failed source=%s", repo_path, exc_info=True)
                        pass

                if remote_domain_obj is None:
                    raise ValueError(f"Unable to open shared item: {repo_path}")

                try:
                    logger.info("shared-sync pull creating target file source=%s target=%s", repo_path, target_path)
                    parent_folder.createFile(item_name, remote_domain_obj, monitor)
                finally:
                    try:
                        remote_domain_obj.release(self)
                    except Exception:
                        logger.info("shared-sync pull release remote_domain_obj failed source=%s", repo_path, exc_info=True)
                        pass

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

    def _push_local_project_to_shared(self, args: dict[str, Any], repository_name: str | None, project_data: Any) -> dict[str, Any]:
        start_time = time.time()
        source_folder: str = self._normalize_repo_path(
            self._get_str(args, "path", "sourcepath", "folder", default="/"),
        )
        recursive: bool = self._get_bool(args, "recursive", default=True)
        max_results: int = self._get_int(args, "maxresults", "limit", default=100000)
        dry_run: bool = self._get_bool(args, "dryrun", default=False)
        logger.info(
            "shared-sync push start repository=%s source_folder=%s recursive=%s max_results=%s dry_run=%s",
            repository_name,
            source_folder,
            recursive,
            max_results,
            dry_run,
        )

        root: Any = project_data.getRootFolder()
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
                source_file: Any = project_data.getFile(source_path)
                if source_file is None:
                    raise ValueError(f"Local project item not found: {source_path}")

                if hasattr(source_file, "save"):
                    logger.info("shared-sync push saving source file=%s", source_path)
                    from ghidra.util.task import TaskMonitor  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

                    source_file.save(TaskMonitor.DUMMY)
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
            "note": "Push syncs local project domain files by saving scoped items. For shared-backed files, this persists local modifications to the backing shared project workflow.",
        }

    async def _sync_shared_repository(self, args: dict[str, Any], default_mode: str = "pull") -> list[types.TextContent]:
        sync_start = time.time()
        logger.info("shared-sync execution start default_mode=%s arg_keys=%s", default_mode, sorted(list(args.keys())))
        mode = self._resolve_shared_sync_mode(args, default_mode=default_mode)
        session_id, handle, repository_adapter, repository_name = self._get_shared_session_context()
        logger.info(
            "shared-sync context resolved session_id=%s mode=%s has_handle=%s has_adapter=%s repository=%s",
            session_id,
            mode,
            bool(handle),
            repository_adapter is not None,
            repository_name,
        )
        if not handle or n(str(handle.get("mode", ""))) != "sharedserver":
            logger.warning("shared-sync aborted: no shared-server session handle present")
            return create_success_response(
                {
                    "operation": "sync-shared",
                    "mode": mode,
                    "success": False,
                    "error": "No active shared-server session. Run open with --server-host first.",
                    "context": {
                        "state": "shared-session-unavailable",
                        "requires": "open(shared-server)",
                    },
                    "nextSteps": [
                        "Call `open` with `serverHost`, `serverPort`, `serverUsername`, `serverPassword`, and repository `path`.",
                        "After `open` succeeds, retry `sync-shared-project`.",
                    ],
                },
            )

        if repository_adapter is None:
            logger.warning("shared-sync aborted: shared adapter missing repository=%s", repository_name)
            return create_success_response(
                {
                    "operation": "sync-shared",
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

        project_data: Any = self._get_active_project_data()
        logger.info("shared-sync project_data resolved has_project_data=%s", project_data is not None)
        if project_data is None:
            logger.warning("shared-sync aborted: local project_data unavailable repository=%s", repository_name)
            return create_success_response(
                {
                    "operation": "sync-shared",
                    "mode": mode,
                    "success": False,
                    "repository": repository_name,
                    "error": "No local Ghidra project context available for shared sync.",
                    "context": {
                        "state": "local-project-context-missing",
                        "repository": repository_name,
                    },
                    "nextSteps": [
                        "Call `open` with a local project (`.gpr`) or import a program to initialize local project context.",
                        "Retry `sync-shared-project` after local project context is available.",
                    ],
                },
            )

        if mode == "pull":
            logger.info("shared-sync executing pull phase repository=%s", repository_name)
            pull_result = self._pull_shared_repository_to_local(args, repository_adapter, repository_name, project_data)
            logger.info(
                "shared-sync pull phase complete success=%s requested=%s transferred=%s skipped=%s errors=%s elapsed_sec=%.2f",
                len(pull_result["errors"]) == 0,
                pull_result.get("requested", 0),
                pull_result.get("transferred", 0),
                pull_result.get("skipped", 0),
                len(pull_result.get("errors", [])),
                time.time() - sync_start,
            )
            return create_success_response(
                {
                    "operation": "sync-shared",
                    "mode": mode,
                    "direction": "shared-to-local",
                    "success": len(pull_result["errors"]) == 0,
                    **pull_result,
                },
            )

        if mode == "push":
            logger.info("shared-sync executing push phase repository=%s", repository_name)
            push_result: dict[str, Any] = self._push_local_project_to_shared(args, repository_name, project_data)
            logger.info(
                "shared-sync push phase complete success=%s requested=%s transferred=%s skipped=%s errors=%s elapsed_sec=%.2f",
                len(push_result["errors"]) == 0,
                push_result.get("requested", 0),
                push_result.get("transferred", 0),
                push_result.get("skipped", 0),
                len(push_result.get("errors", [])),
                time.time() - sync_start,
            )
            return create_success_response(
                {
                    "operation": "sync-shared",
                    "mode": mode,
                    "direction": "local-to-shared",
                    "success": len(push_result["errors"]) == 0,
                    **push_result,
                },
            )

        logger.info("shared-sync executing bidirectional pull phase repository=%s", repository_name)
        pull_result: dict[str, Any] = self._pull_shared_repository_to_local(args, repository_adapter, repository_name, project_data)
        logger.info("shared-sync executing bidirectional push phase repository=%s", repository_name)
        push_result: dict[str, Any] = self._push_local_project_to_shared(args, repository_name, project_data)

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

        return create_success_response(
            {
                "operation": "sync-shared",
                "mode": "bidirectional",
                "direction": "shared-and-local",
                "success": len(pull_result["errors"]) == 0 and len(push_result["errors"]) == 0,
                "repository": repository_name,
                "phases": {
                    "pull": pull_result,
                    "push": push_result,
                },
                "totals": {
                    "requested": int(pull_result.get("requested", 0)) + int(push_result.get("requested", 0)),
                    "transferred": int(pull_result.get("transferred", 0)) + int(push_result.get("transferred", 0)),
                    "skipped": int(pull_result.get("skipped", 0)) + int(push_result.get("skipped", 0)),
                    "errors": len(pull_result.get("errors", [])) + len(push_result.get("errors", [])),
                },
            },
        )

    async def _download_shared_repository_to_local(self, args: dict[str, Any]) -> list[types.TextContent]:
        return await self._sync_shared_repository(args, default_mode="pull")

    async def _checkout_shared_program(
        self,
        repository_adapter: RepoAdapter,
        program_path: str,
        session_id: str,
    ) -> str:
        """Checkout a program from a shared Ghidra server repository and set it as active.

        This opens the remote program for read-only browsing via Ghidra's
        ``RepositoryAdapter`` API, creates a ``ProgramInfo`` for it, and
        sets it on the session and tool-provider so that all subsequent tool
        calls operate on the checked-out program.

        Returns the program path that was checked out.
        """
        import time

        from db import DBHandle  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
        from ghidra.framework.data import OpenMode  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
        from ghidra.program.database import ProgramDB  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
        from ghidra.util.task import TaskMonitor  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
        from java.lang import Object as JavaObject  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

        monitor = TaskMonitor.DUMMY

        # Split program_path into folder + name
        parts: list[str] = program_path.rsplit("/", 1)
        if len(parts) == 2:
            folder_path: str = parts[0] or "/"
            item_name: str = parts[1]
        else:
            folder_path = "/"
            item_name = parts[0]

        # Get the repository item
        repo_item: Any = repository_adapter.getItem(folder_path, item_name)
        if repo_item is None:
            raise ValueError(f"Program '{program_path}' not found in repository folder '{folder_path}'")

        # Prefer opening via ProjectData/DomainFile so the resulting Program has
        # standard project-backed behavior (including stable decompiler support).
        # Keep a ProgramDB fallback for environments where DomainFile checkout is
        # unavailable.
        program: Any = None

        # Open / checkout the file via the project data
        # We need to use the project's DomainFile which can be retrieved
        # from the project data after connecting.

        # Use the manager's GhidraProject (set from launcher) to get project data.
        project_data: ProjectData | None = None
        ghidra_project: Any = getattr(self._manager, "ghidra_project", None) if self._manager else None
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

        if project_data is not None:
            # Check if the file is already in the local project
            try:
                domain_file = project_data.getFile(program_path)
                if domain_file is None:
                    # Need to create the file in the local project from the shared repo.
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
                    remote_domain_obj: Any = None
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
                            managed_db = repository_adapter.openDatabase(folder_path, item_name, version, 0)
                            db_handle = DBHandle(managed_db)
                            try:
                                remote_domain_obj = ProgramDB(db_handle, OpenMode.UPDATE, monitor, consumer)
                            except Exception:
                                remote_domain_obj = ProgramDB(db_handle, OpenMode.IMMUTABLE, monitor, consumer)
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
                    # Prefer GhidraProject.openProgram() which gives writable access
                    # on local project files, over getDomainObject() which may
                    # open read-only.
                    opened = False
                    if ghidra_project is not None:
                        try:
                            domain_obj = ghidra_project.openProgram(domain_file)
                            if domain_obj is not None:
                                program = domain_obj
                                opened = True
                                logger.info("Opened '%s' via GhidraProject.openProgram (writable)", program_path)
                        except Exception:
                            pass
                    if not opened:
                        domain_obj = self._get_domain_object_compat(domain_file, monitor)  # pyright: ignore[reportAttributeAccessIssue]
                        if domain_obj is not None:
                            program = domain_obj
                            logger.info("Opened '%s' via DomainFile.getDomainObject (path=%s)", program_path, domain_file.getPathname())
            except Exception as exc:
                logger.info("project_data checkout of '%s' failed: %s. Trying lower-level fallbacks.", program_path, exc)

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
                managed_db = repository_adapter.openDatabase(folder_path, item_name, version, 0)  # pyright: ignore[reportAttributeAccessIssue]
                db_handle = DBHandle(managed_db)
                try:
                    program = ProgramDB(db_handle, OpenMode.UPDATE, monitor, JavaObject())
                except Exception:
                    program = ProgramDB(db_handle, OpenMode.IMMUTABLE, monitor, JavaObject())
                logger.info("Opened shared program '%s' via ProgramDB fallback", program_path)
            except Exception as exc:
                logger.warning(
                    "Shared ProgramDB open failed for %s (repo item %s/%s): %s",
                    program_path,
                    folder_path,
                    item_name,
                    exc,
                )

        if program is None:
            raise ValueError(f"Failed to open '{program_path}' from repository")

        # Build ProgramInfo
        from ghidra.app.decompiler import DecompileOptions, DecompInterface  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

        from agentdecompile_cli.launcher import ProgramInfo

        decompiler = DecompInterface()
        decomp_options = DecompileOptions()
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

        # Set as active on session and ALL providers (via manager)
        SESSION_CONTEXTS.set_active_program_info(session_id, program_path, program_info)
        if self._manager is not None:
            self._manager.set_program_info(program_info)
        else:
            self.set_program_info(program_info)

        logger.info("Checked out program '%s' from shared repository", program_path)
        return program_path

    def _list_repository_items(self, repository_adapter: Any) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        start_time = time.time()
        logger.info("shared-sync repository listing start")

        def _walk(folder_path: str) -> None:
            logger.info("shared-sync repository listing walking folder=%s", folder_path)
            subfolders: list[Any] = repository_adapter.getSubfolderList(folder_path) or []
            logger.info("shared-sync repository listing folder=%s subfolders=%s", folder_path, len(subfolders))
            for subfolder in subfolders:
                subfolder_name = str(subfolder)
                next_path = f"{folder_path.rstrip('/')}/{subfolder_name}" if folder_path != "/" else f"/{subfolder_name}"
                _walk(next_path)

            logger.info("shared-sync repository listing getting items for folder=%s", folder_path)
            repo_items: list[Any] = repository_adapter.getItemList(folder_path) or []
            logger.info("shared-sync repository listing folder=%s items=%s", folder_path, len(repo_items))
            for repo_item in repo_items:
                name = str(repo_item.getName()) if hasattr(repo_item, "getName") else str(repo_item)
                path = f"{folder_path.rstrip('/')}/{name}" if folder_path != "/" else f"/{name}"
                item_type = str(repo_item.getContentType()) if hasattr(repo_item, "getContentType") else "Program"
                items.append(
                    {
                        "name": name,
                        "path": path,
                        "type": item_type,
                    },
                )
                if len(items) == 1 or len(items) % 50 == 0:
                    logger.info("shared-sync repository listing progress discovered_items=%s elapsed_sec=%.2f", len(items), time.time() - start_time)

        _walk("/")
        logger.info("shared-sync repository listing complete total_items=%s elapsed_sec=%.2f", len(items), time.time() - start_time)
        return items

    async def _handle_delete_project_binary(self, args: dict[str, Any]) -> list[types.TextContent]:
        if self.program_info is None:
            return create_success_response({"success": False, "error": "No program loaded"})

        binary_name: str = self._require_str(args, "binaryname", "programpath", "binary", name="binaryName")
        program: Any = self.program_info.program
        domain_file: Any = program.getDomainFile()
        if domain_file is None:
            return create_success_response({"success": False, "error": "No domain file associated with current program"})

        if binary_name not in (program.getName(), str(domain_file.getPathname()), domain_file.getName()):
            return create_success_response({"success": False, "error": f"Refusing to delete non-active binary in this context: {binary_name}"})

        try:
            program.release(None)
        except Exception:
            pass

        try:
            deleted = bool(domain_file.delete())
        except Exception as exc:
            return create_success_response({"success": False, "error": str(exc)})

        return create_success_response({"success": deleted, "binaryName": binary_name, "deleted": deleted})

    async def _handle_get_current_address(self, args: dict[str, Any]) -> list[types.TextContent]:
        return create_success_response(
            {
                "success": False,
                "error": "get-current-address requires GUI mode (Code Browser context)",
                "headless": True,
            },
        )

    async def _handle_get_current_function(self, args: dict[str, Any]) -> list[types.TextContent]:
        if self.program_info is None:
            return create_success_response({"success": False, "error": "No program loaded"})

        program: Any = self.program_info.program
        fm: Any = self._get_function_manager(program)
        first: Any = None
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
        await self._ensure_program_loaded_for_stateless_request(args)

        if self.program_info is None:
            return create_success_response({"loaded": False, "note": "No program currently loaded"})

        program: Any = self.program_info.program
        name: str = str(program.getName()) if hasattr(program, "getName") else "unknown"
        path: str = ""
        try:
            df = program.getDomainFile()
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
        return create_success_response(
            {
                "success": False,
                "error": "This operation requires GUI mode (Code Browser)",
                "headless": True,
            },
        )

    async def _handle_import_file_alias(self, args: dict[str, Any]) -> list[types.TextContent]:
        return await self._import_file(self._require_str(args, "path", "filepath", "file", name="path"), args)

    def _list_domain_files(self, root_folder: Any, max_results: int) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []

        def walk(folder: Any) -> None:
            nonlocal items
            if len(items) >= max_results:
                return

            for child in folder.getFolders():
                if len(items) >= max_results:
                    return
                items.append({"name": child.getName(), "path": str(child.getPathname()), "type": "Folder"})
                walk(child)

            for domain_file in folder.getFiles():
                if len(items) >= max_results:
                    return
                content_type = str(domain_file.getContentType()) if hasattr(domain_file, "getContentType") else "unknown"
                items.append({"name": domain_file.getName(), "path": str(domain_file.getPathname()), "type": content_type})

        walk(root_folder)
        return items
