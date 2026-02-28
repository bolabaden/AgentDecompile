"""Project Tool Provider - open, get-current-program, list-project-files.

Handles project and program management operations.
"""

from __future__ import annotations

import logging
import shutil
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
    ToolProvider,
    create_success_response,
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

    class RepoItem(ABC):
        @abstractmethod
        def getDomainFile(self): ...

    class RepoAdapter(ABC):
        @abstractmethod
        def getItem(self, folderPath: str, itemName: str): ...
        @abstractmethod
        def getVersion(self): ...


logger = logging.getLogger(__name__)


class ProjectToolProvider(ToolProvider):
    HANDLERS: ClassVar[dict[str, str]] = {
        "open": "_handle_open",
        "getcurrentprogram": "_handle_current",
        "listprojectfiles": "_handle_list",
        "syncsharedproject": "_handle_sync_shared_project",
        "downloadsharedrepository": "_handle_download_shared_repository",
        "managefiles": "_handle_manage",
        "listprojectbinaries": "_handle_list_project_binaries",
        "listprojectbinarymetadata": "_handle_list_project_binary_metadata",
        "deleteprojectbinary": "_handle_delete_project_binary",
        "listopenprograms": "_handle_list_open_programs",
        "getcurrentaddress": "_handle_get_current_address",
        "getcurrentfunction": "_handle_get_current_function",
        "openprogramincodebrowser": "_handle_gui_unsupported",
        "openallprogramsincodebrowser": "_handle_gui_unsupported",
        "importfile": "_handle_import_file_alias",
    }

    def list_tools(self) -> list[types.Tool]:
        return [
            types.Tool(
                name="open",
                description="Open a program or project",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "Path to program or project file"},
                        "filePath": {"type": "string"},
                        "path": {"type": "string"},
                        "extensions": {"type": "array", "items": {"type": "string"}},
                        "openAllPrograms": {"type": "boolean", "default": True},
                        "destinationFolder": {"type": "string", "default": "/"},
                        "analyzeAfterImport": {"type": "boolean", "default": True},
                        "enableVersionControl": {"type": "boolean", "default": True},
                        "serverUsername": {"type": "string"},
                        "serverPassword": {"type": "string"},
                        "serverHost": {"type": "string"},
                        "serverPort": {"type": "integer"},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="get-current-program",
                description="Get info about the currently loaded program",
                inputSchema={"type": "object", "properties": {}, "required": []},
            ),
            types.Tool(
                name="list-project-files",
                description="List files in the current project",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "folder": {"type": "string", "default": "/"},
                        "path": {"type": "string"},
                        "maxResults": {"type": "integer", "default": 100},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="sync-shared-project",
                description="Synchronize active shared repository content with the local Ghidra project",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "mode": {
                            "type": "string",
                            "enum": ["pull", "push", "bidirectional"],
                            "default": "pull",
                        },
                        "path": {"type": "string", "default": "/"},
                        "sourcePath": {"type": "string"},
                        "newPath": {"type": "string", "default": "/"},
                        "destinationPath": {"type": "string"},
                        "destinationFolder": {"type": "string"},
                        "recursive": {"type": "boolean", "default": True},
                        "maxResults": {"type": "integer", "default": 100000},
                        "force": {"type": "boolean", "default": False},
                        "dryRun": {"type": "boolean", "default": False},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="manage-files",
                description="Manage project and filesystem files (import/export/list/info/create/edit/move/version-control)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": [
                                "rename",
                                "delete",
                                "copy",
                                "move",
                                "info",
                                "list",
                                "mkdir",
                                "touch",
                                "read",
                                "write",
                                "append",
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
                        "operation": {
                            "type": "string",
                            "enum": [
                                "rename",
                                "delete",
                                "copy",
                                "move",
                                "info",
                                "list",
                                "mkdir",
                                "touch",
                                "read",
                                "write",
                                "append",
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
                        "filePath": {"type": "string"},
                        "path": {"type": "string"},
                        "sourcePath": {"type": "string"},
                        "programPath": {"type": "string"},
                        "mode": {
                            "type": "string",
                            "enum": ["pull", "push", "bidirectional"],
                        },
                        "newPath": {"type": "string"},
                        "destinationPath": {"type": "string"},
                        "destinationFolder": {"type": "string"},
                        "newName": {"type": "string"},
                        "content": {"type": "string"},
                        "encoding": {"type": "string", "default": "utf-8"},
                        "createParents": {"type": "boolean", "default": True},
                        "keep": {"type": "boolean", "default": False},
                        "force": {"type": "boolean", "default": False},
                        "exclusive": {"type": "boolean", "default": False},
                        "recursive": {"type": "boolean", "default": False},
                        "dryRun": {"type": "boolean", "default": False},
                        "maxResults": {"type": "integer", "default": 200},
                        "maxDepth": {"type": "integer", "default": 16},
                        "analyzeAfterImport": {"type": "boolean", "default": False},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="list-project-binaries",
                description="List program binaries in current project",
                inputSchema={"type": "object", "properties": {}, "required": []},
            ),
            types.Tool(
                name="list-project-binary-metadata",
                description="Get metadata for a project binary",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "binaryName": {"type": "string"},
                        "binary_name": {"type": "string"},
                        "programPath": {"type": "string"},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="delete-project-binary",
                description="Delete a binary from the project",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "binaryName": {"type": "string"},
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
                name="open-all-programs-in-code-browser",
                description="Open all project programs in Code Browser (GUI-only)",
                inputSchema={"type": "object", "properties": {}, "required": []},
            ),
        ]

    async def _handle_open(self, args: dict[str, Any]) -> list[types.TextContent]:
        session_id = get_current_mcp_session_id()
        server_host = self._get_str(args, "serverhost", "host")
        server_port = self._get_int(args, "serverport", "port", default=0)
        server_username = self._get_str(args, "serverusername", "username")
        server_password = self._get_str(args, "serverpassword", "password")
        path = self._get_str(args, "programpath", "filepath", "file", "path", "program", "binary")

        if server_host:
            if server_port <= 0:
                server_port = 13100

            auth_provided = bool(server_username and server_password)
            server_reachable = False

            try:
                with socket.create_connection((server_host, server_port), timeout=5):
                    server_reachable = True
            except OSError as exc:
                return create_success_response(
                    {
                        "action": "open",
                        "mode": "shared-server",
                        "serverHost": server_host,
                        "serverPort": server_port,
                        "serverReachable": False,
                        "authProvided": auth_provided,
                        "repository": path if path and "/" not in path else None,
                        "message": f"Ghidra server not reachable at {server_host}:{server_port}: {exc}",
                    },
                )

            try:
                from ghidra.framework.client import ClientUtil, PasswordClientAuthenticator  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
            except Exception:
                return create_success_response(
                    {
                        "action": "open",
                        "mode": "shared-server",
                        "serverHost": server_host,
                        "serverPort": server_port,
                        "serverReachable": server_reachable,
                        "authProvided": auth_provided,
                        "repository": path if path and "/" not in path else None,
                        "availableRepositories": [path] if path and "/" not in path else [],
                        "programCount": 0,
                        "programs": [],
                        "checkedOutProgram": None,
                        "message": "Connected to shared server endpoint, but local Ghidra runtime is unavailable for repository browsing.",
                    },
                )

            if server_username and server_password:
                ClientUtil.setClientAuthenticator(PasswordClientAuthenticator(server_username, server_password))
                for setter_name in (
                    "setUserName",
                    "setUsername",
                    "setUser",
                    "setClientUserName",
                    "setClientUsername",
                    "setClientUser",
                ):
                    try:
                        setter = getattr(ClientUtil, setter_name, None)
                        if callable(setter):
                            setter(server_username)
                            break
                    except Exception:
                        continue

            original_user_name: str | None = None
            if server_username:
                try:
                    from java.lang import System as JavaSystem  # pyright: ignore[reportMissingImports]

                    original_user_name = JavaSystem.getProperty("user.name")
                    JavaSystem.setProperty("user.name", server_username)
                except Exception:
                    original_user_name = None

            server_adapter = None
            if server_username and server_password:
                # Prefer authenticated overloads where available so the
                # repository handshake doesn't default to the process user.
                for overload_args in (
                    (server_host, server_port, False, server_username, server_password),
                    (server_host, server_port, server_username, server_password),
                ):
                    try:
                        server_adapter = ClientUtil.getRepositoryServer(*overload_args)
                        if server_adapter is not None:
                            break
                    except TypeError:
                        continue
                    except Exception:
                        continue

            if server_adapter is None:
                server_adapter = ClientUtil.getRepositoryServer(server_host, server_port, False)
            if server_adapter is None:
                raise ValueError(f"Failed to connect to repository server: {server_host}:{server_port}")

            if not server_adapter.isConnected():
                try:
                    if server_username and server_password:
                        try:
                            connected = bool(server_adapter.connect(server_username, server_password))
                        except TypeError:
                            connected = bool(server_adapter.connect())
                    else:
                        connected = bool(server_adapter.connect())
                    if not connected:
                        last_error = server_adapter.getLastConnectError()
                        logger.warning(
                            "Repository server connect() returned false for %s:%s: %s",
                            server_host,
                            server_port,
                            last_error,
                        )
                except Exception as exc:
                    logger.warning(
                        "Repository server connect() raised for %s:%s: %s. Continuing with repository probe.",
                        server_host,
                        server_port,
                        exc,
                    )

            try:
                repository_names_raw = server_adapter.getRepositoryNames() or []
            except Exception as exc:
                raise ValueError(f"Repository server connection failed for {server_host}:{server_port}: {exc}") from exc
            finally:
                if server_username and original_user_name is not None:
                    try:
                        from java.lang import System as JavaSystem  # pyright: ignore[reportMissingImports]

                        JavaSystem.setProperty("user.name", original_user_name)
                    except Exception:
                        pass
            repository_names: list[str] = [str(name) for name in repository_names_raw]
            if not repository_names:
                raise ValueError(f"No repositories found on {server_host}:{server_port}")

            # Determine repository name and optional program path within it.
            # If ``path`` is a bare repo name (e.g. "Odyssey") use it directly.
            # If ``path`` looks like a program path inside a repo (e.g.
            # "/K1/k1_win_gog_swkotor.exe") we need to figure out which repo
            # contains it and optionally checkout that program.
            repository_name: str | None = None
            checkout_program_path: str | None = None

            if path and path.strip():
                # Check if ``path`` is an exact repo name first
                if path in repository_names:
                    repository_name = path
                else:
                    # Not a repo name - treat as a program-path inside a repo.
                    # Try each known repo to see which contains a matching item.
                    checkout_program_path = path
                    # Default to the first (or only) repository
                    repository_name = repository_names[0]
            else:
                repository_name = repository_names[0]

            repository_adapter: Any = server_adapter.getRepository(repository_name)
            if repository_adapter is None:
                raise ValueError(f"Failed to get repository handle for '{repository_name}'")

            if not repository_adapter.isConnected():
                repository_adapter.connect()

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

            # If a specific program path was requested, attempt to check it out.
            checked_out_program: str | None = None
            checkout_error: str | None = None
            if checkout_program_path:
                # Try to find the matching binary in the discovered items.
                norm_target: str = checkout_program_path.strip().rstrip("/")
                matched: str | None = None
                for b in binaries:
                    bp = (b.get("path") or "").strip()
                    if bp == norm_target or bp.lstrip("/") == norm_target.lstrip("/"):
                        matched = bp
                        break
                    # Also match by name only (e.g. "k1_win_gog_swkotor.exe")
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
                    "action": "open",
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

        if not path or not path.strip():
            raise ValueError("programPath or filePath required (or provide --server-host for shared-server mode)")

        resolved: Path = Path(path).expanduser().resolve()
        if not resolved.exists():
            raise ValueError(f"Path does not exist: {resolved}")

        if resolved.is_file() and resolved.suffix.lower() not in (".gpr",):
            return await self._import_file(str(resolved), args)

        files_discovered: int = 0
        if resolved.is_dir():
            extensions = self._get_list(args, "extensions")
            patterns = [e.lower() for e in extensions] if extensions else []
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
                "note": "Path resolved. Use manage-files operation=import for explicit binary imports.",
            },
        )

    async def _handle_current(self, args: dict[str, Any]) -> list[types.TextContent]:
        if self.program_info is None:
            return create_success_response({"loaded": False, "note": "No program currently loaded"})

        program: Any = getattr(self.program_info, "program", None)
        if program is None or not hasattr(program, "getName"):
            return create_success_response({"loaded": False, "note": "No program currently loaded"})
        info: dict[str, Any] = {"loaded": True}

        try:
            info["name"] = program.getName()
            info["path"] = str(program.getDomainFile().getPathname()) if program.getDomainFile() else None
            info["language"] = str(program.getLanguage().getLanguageID())
            info["compiler"] = str(program.getCompilerSpec().getCompilerSpecID())
            info["addressFactory"] = str(program.getAddressFactory().getDefaultAddressSpace().getName())

            # Stats
            fm = program.getFunctionManager()
            info["functionCount"] = fm.getFunctionCount()
            info["imageBase"] = str(program.getImageBase())

            mem = program.getMemory()
            info["memoryBlocks"] = len(list(mem.getBlocks()))

            st = program.getSymbolTable()
            info["symbolCount"] = st.getNumSymbols()

        except Exception as e:
            info["error"] = str(e)

        return create_success_response(info)

    async def _handle_list(self, args: dict[str, Any]) -> list[types.TextContent]:
        folder: str  = self._get_str(args, "folder", "path", default="/")
        max_results: int = self._get_int(args, "maxresults", "limit", default=100)
        session_id: str = get_current_mcp_session_id()

        fs_path = self._get_str(args, "path")
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
            return create_success_response({"files": [], "note": "No project loaded"})

        try:
            program: Any = self.program_info.program
            if program is None or not hasattr(program, "getDomainFile"):
                raise ValueError("No active program available")
            root: Any = program.getDomainFile().getProjectData().getRootFolder()
            files = self._list_domain_files(root, max_results)
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

    async def _handle_manage(self, args: dict[str, Any]) -> list[types.TextContent]:
        operation: str = self._require_str(args, "operation", "action", "mode", name="operation")
        file_path: str | None = self._get_str(args, "filepath", "file", "path", "programpath")
        program_path: str | None = self._get_str(args, "programpath", "filepath", "file", "path")
        destination: str | None = self._get_str(args, "newpath", "destinationpath")
        new_name: str | None = self._get_str(args, "newname")
        content: str = self._get_str(args, "content", default="")
        encoding: str = self._get_str(args, "encoding", default="utf-8")
        create_parents: bool = self._get_bool(args, "createparents", default=True)
        max_results: int = self._get_int(args, "maxresults", default=200)

        op: str = n(operation)
        if op == "import":
            if not file_path:
                raise ValueError("path/filePath is required for import")
            return await self._import_file(file_path, args)

        if op == "export":
            return await self._export_current_program(args)

        pull_aliases = {
            "downloadshared",
            "downloadsharedrepository",
            "downloadsharedproject",
            "pullshared",
            "pullsharedrepository",
            "pullsharedproject",
        }
        push_aliases = {
            "pushshared",
            "pushsharedrepository",
            "pushsharedproject",
            "uploadshared",
            "uploadsharedrepository",
            "importtoshared",
        }
        sync_aliases = {
            "syncshared",
            "syncsharedrepository",
            "syncsharedproject",
            "syncwithshared",
            "mirrorshared",
        }
        if op in pull_aliases:
            return await self._sync_shared_repository(args, default_mode="pull")
        if op in push_aliases:
            return await self._sync_shared_repository(args, default_mode="push")
        if op in sync_aliases:
            return await self._sync_shared_repository(args, default_mode="bidirectional")

        if op in {"checkout", "uncheckout", "unhijack"}:
            domain_file = self._resolve_domain_file(program_path)
            if domain_file is None:
                return create_success_response(
                    {
                        "operation": op,
                        "programPath": program_path,
                        "success": False,
                        "error": "No project-backed domain file found for the requested programPath",
                    },
                )

            try:
                if op == "checkout":
                    exclusive = self._get_bool(args, "exclusive", default=False)
                    if hasattr(domain_file, "checkout"):
                        domain_file.checkout(exclusive, False, None)
                    return create_success_response(
                        {
                            "operation": "checkout",
                            "programPath": program_path,
                            "exclusive": exclusive,
                            "success": True,
                        },
                    )

                if op == "uncheckout":
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
            except Exception as exc:
                return create_success_response(
                    {
                        "operation": op,
                        "programPath": program_path,
                        "success": False,
                        "error": str(exc),
                    },
                )

        if op == "mkdir":
            if not file_path:
                raise ValueError("path/filePath is required for mkdir")
            target_dir = Path(file_path).expanduser().resolve()
            target_dir.mkdir(parents=create_parents, exist_ok=True)
            return create_success_response({"operation": "mkdir", "path": str(target_dir), "success": True})

        if op == "touch":
            if not file_path:
                raise ValueError("path/filePath is required for touch")
            target_file = Path(file_path).expanduser().resolve()
            if create_parents:
                target_file.parent.mkdir(parents=True, exist_ok=True)
            target_file.touch(exist_ok=True)
            return create_success_response({"operation": "touch", "path": str(target_file), "success": True})

        if op == "list":
            base_path = Path(file_path).expanduser().resolve() if file_path else Path.cwd()
            if not base_path.exists():
                raise ValueError(f"Path not found: {base_path}")
            if not base_path.is_dir():
                raise ValueError(f"Path is not a directory: {base_path}")

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

        if not file_path:
            raise ValueError("path/filePath is required")

        target = Path(file_path).expanduser().resolve()
        if op == "info":
            return create_success_response(
                {
                    "operation": "info",
                    "path": str(target),
                    "exists": target.exists(),
                    "isDirectory": target.is_dir() if target.exists() else False,
                    "size": None if (not target.exists() or target.is_dir()) else target.stat().st_size,
                },
            )

        if op == "read":
            if not target.exists() or target.is_dir():
                raise ValueError(f"Path is not a readable file: {target}")
            file_text = target.read_text(encoding=encoding)
            return create_success_response(
                {
                    "operation": "read",
                    "path": str(target),
                    "encoding": encoding,
                    "content": file_text,
                    "size": len(file_text),
                },
            )

        if op == "write":
            if create_parents:
                target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding=encoding)
            return create_success_response(
                {
                    "operation": "write",
                    "path": str(target),
                    "encoding": encoding,
                    "written": len(content),
                    "success": True,
                },
            )

        if op == "append":
            if create_parents:
                target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("a", encoding=encoding) as handle:
                handle.write(content)
            return create_success_response(
                {
                    "operation": "append",
                    "path": str(target),
                    "encoding": encoding,
                    "appended": len(content),
                    "success": True,
                },
            )

        if not target.exists():
            raise ValueError(f"Path not found: {target}")

        if op == "rename":
            if not new_name:
                raise ValueError("newName is required for rename")
            new_path = target.with_name(new_name)
            target.rename(new_path)
            return create_success_response({"operation": "rename", "path": str(target), "newPath": str(new_path), "success": True})

        if op == "delete":
            recursive = self._get_bool(args, "recursive", default=False)
            if target.is_dir():
                if recursive:
                    shutil.rmtree(target)
                else:
                    target.rmdir()
            else:
                target.unlink()
            return create_success_response({"operation": "delete", "path": str(target), "success": True})

        if op == "copy":
            if not destination:
                raise ValueError("newPath/destinationPath is required for copy")
            dst = Path(destination).expanduser().resolve()
            if target.is_dir():
                shutil.copytree(target, dst, dirs_exist_ok=True)
            else:
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(target, dst)
            return create_success_response({"operation": "copy", "path": str(target), "newPath": str(dst), "success": True})

        if op == "move":
            if not destination:
                raise ValueError("newPath/destinationPath is required for move")
            dst = Path(destination).expanduser().resolve()
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(target), str(dst))
            return create_success_response({"operation": "move", "path": str(target), "newPath": str(dst), "success": True})

        raise ValueError(f"Unsupported manage-files operation: {operation}")

    async def _handle_sync_shared_project(self, args: dict[str, Any]) -> list[types.TextContent]:
        return await self._sync_shared_repository(args, default_mode="pull")

    async def _handle_download_shared_repository(self, args: dict[str, Any]) -> list[types.TextContent]:
        return await self._handle_sync_shared_project(args)

    def _resolve_domain_file(self, program_path: str | None):
        if not program_path:
            if self.program_info is not None and getattr(self.program_info, "program", None) is not None:
                try:
                    return self.program_info.program.getDomainFile()
                except Exception:
                    return None
            return None

        try:
            normalized = str(program_path).strip()
            if self.program_info is not None and getattr(self.program_info, "program", None) is not None:
                current_df = self.program_info.program.getDomainFile()
                if current_df is not None and str(current_df.getPathname()) == normalized:
                    return current_df

            if self.program_info is None or getattr(self.program_info, "program", None) is None:
                return None

            project_data = self.program_info.program.getDomainFile().getProjectData()
            return project_data.getFile(normalized)
        except Exception:
            return None

    async def _import_file(self, file_path: str, args: dict[str, Any]) -> list[types.TextContent]:
        session_id = get_current_mcp_session_id()
        source = Path(file_path).expanduser().resolve()
        if not source.exists():
            raise ValueError(f"Import path not found: {source}")

        recursive = self._get_bool(args, "recursive", default=source.is_dir())
        max_depth = self._get_int(args, "maxdepth", default=16)
        analyze = self._get_bool(args, "analyzeafterimport", default=False)

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
        imported_count = 0
        errors: list[dict[str, Any]] = []

        project_handle = None
        ghidra_project = getattr(self._manager, "ghidra_project", None) if self._manager else None
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

                program = project_handle.importProgram(File(str(entry)))
                if program is None:
                    raise RuntimeError("import_binary returned None")

                from agentdecompile_cli.launcher import ProgramInfo

                decompiler = None
                try:
                    from agentdecompile_cli.decompiled_function_analyzer import DecompiledFunctionAnalyzer

                    decompiler = DecompiledFunctionAnalyzer(program)
                except Exception:
                    decompiler = None

                program_path = str(program.getDomainFile().getPathname()) if program.getDomainFile() else str(entry)
                program_info = ProgramInfo(
                    name=program.getName(),
                    program=program,
                    flat_api=None,
                    decompiler=decompiler,
                    metadata={},
                    ghidra_analysis_complete=True,
                    file_path=str(entry),
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

        output = Path(out_path).expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)

        program = self.program_info.program
        payload = {
            "name": program.getName(),
            "path": str(program.getDomainFile().getPathname()) if program.getDomainFile() else None,
            "language": str(program.getLanguage().getLanguageID()),
            "compiler": str(program.getCompilerSpec().getCompilerSpecID()),
            "imageBase": str(program.getImageBase()),
            "functionCount": program.getFunctionManager().getFunctionCount(),
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
        path = self._normalize_repo_path(item_path)
        source = self._normalize_repo_path(source_folder)
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
        source = self._normalize_repo_path(source_folder)
        destination = self._normalize_repo_path(destination_folder)
        path = self._normalize_repo_path(repo_path)

        relative = path.lstrip("/")
        if source != "/":
            prefix = f"{source}/"
            if path.startswith(prefix):
                relative = path[len(prefix) :]

        if destination == "/":
            return self._normalize_repo_path(f"/{relative}")
        return self._normalize_repo_path(f"{destination}/{relative}")

    def _get_active_project_data(self):
        ghidra_project = getattr(self._manager, "ghidra_project", None) if self._manager else None
        if ghidra_project is not None:
            try:
                return ghidra_project.getProject().getProjectData()
            except Exception:
                try:
                    return ghidra_project.getProjectData()
                except Exception:
                    pass

        if self.program_info is not None and getattr(self.program_info, "program", None) is not None:
            try:
                domain_file = self.program_info.program.getDomainFile()
                if domain_file is not None:
                    return domain_file.getProjectData()
            except Exception:
                pass

        return None

    def _ensure_project_folder(self, project_data: ProjectData, folder_path: str):
        normalized = self._normalize_repo_path(folder_path)
        if normalized == "/":
            return project_data.getRootFolder()

        folder = project_data.getFolder(normalized)
        if folder is not None:
            return folder

        current = project_data.getRootFolder()
        for component in normalized.strip("/").split("/"):
            if not component:
                continue
            child = current.getFolder(component)
            if child is None:
                child = current.createFolder(component)
            current = child
        return current

    def _resolve_shared_sync_mode(self, args: dict[str, Any], default_mode: str = "pull") -> str:
        requested = self._get_str(args, "mode", "direction", "syncmode", "operation", "action", default=default_mode)
        normalized = n(requested)
        if normalized in {"pull", "download", "downloadshared", "pullshared"}:
            return "pull"
        if normalized in {"push", "upload", "uploadshared", "pushshared", "importtoshared"}:
            return "push"
        if normalized in {"bidirectional", "both", "sync", "syncshared", "mirror"}:
            return "bidirectional"
        return default_mode

    def _get_shared_session_context(self) -> tuple[str, dict[str, Any] | None, Any, str | None]:
        session_id = get_current_mcp_session_id()
        session = SESSION_CONTEXTS.get_or_create(session_id)
        handle = session.project_handle if isinstance(session.project_handle, dict) else None
        repository_adapter = handle.get("repository_adapter") if handle else None
        repository_name = handle.get("repository_name") if handle else None
        return session_id, handle, repository_adapter, repository_name

    def _pull_shared_repository_to_local(self, args: dict[str, Any], repository_adapter: Any, repository_name: str | None, project_data: Any) -> dict[str, Any]:
        source_folder = self._normalize_repo_path(
            self._get_str(args, "path", "sourcepath", "folder", default="/"),
        )
        destination_folder = self._normalize_repo_path(
            self._get_str(args, "newpath", "destinationpath", "destinationfolder", default="/"),
        )
        recursive = self._get_bool(args, "recursive", default=True)
        max_results = self._get_int(args, "maxresults", "limit", default=100000)
        force = self._get_bool(args, "force", default=False)
        dry_run = self._get_bool(args, "dryrun", default=False)

        from ghidra.util.task import TaskMonitor  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

        session_id = get_current_mcp_session_id()
        items = SESSION_CONTEXTS.get_project_binaries(session_id, fallback_to_latest=True)
        if not items:
            items = self._list_repository_items(repository_adapter)

        candidates: list[dict[str, Any]] = []
        for item in items:
            item_path = str(item.get("path") or "")
            if item_path and self._path_in_scope(item_path, source_folder, recursive):
                candidates.append(item)

        if max_results > 0:
            candidates = candidates[:max_results]

        monitor = TaskMonitor.DUMMY
        transferred: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []

        for item in candidates:
            repo_path = self._normalize_repo_path(str(item.get("path") or ""))
            if not repo_path or repo_path == "/":
                continue

            target_path = self._map_repo_path_to_local(repo_path, source_folder, destination_folder)
            existing = project_data.getFile(target_path)
            if existing is not None and not force:
                skipped.append({"sourcePath": repo_path, "targetPath": target_path, "reason": "already-exists"})
                continue

            if dry_run:
                transferred.append({"sourcePath": repo_path, "targetPath": target_path, "planned": True})
                continue

            parts = repo_path.rsplit("/", 1)
            repo_folder = parts[0] if len(parts) == 2 else "/"
            item_name = parts[1] if len(parts) == 2 else parts[0]
            target_parent_path = target_path.rsplit("/", 1)[0] or "/"

            try:
                repo_item = repository_adapter.getItem(repo_folder, item_name)
                if repo_item is None:
                    raise ValueError(f"Repository item not found: {repo_path}")

                if existing is not None and force and hasattr(existing, "delete"):
                    existing.delete()

                parent_folder = self._ensure_project_folder(project_data, target_parent_path)
                remote_domain_obj = repo_item.getDomainObject(self, True, False, monitor)
                if remote_domain_obj is None:
                    raise ValueError(f"Unable to open shared item: {repo_path}")

                try:
                    parent_folder.createFile(item_name, remote_domain_obj, monitor)
                finally:
                    try:
                        remote_domain_obj.release(self)
                    except Exception:
                        pass

                transferred.append({"sourcePath": repo_path, "targetPath": target_path})
            except Exception as exc:
                errors.append({"sourcePath": repo_path, "targetPath": target_path, "error": str(exc)})

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
        source_folder = self._normalize_repo_path(
            self._get_str(args, "path", "sourcepath", "folder", default="/"),
        )
        recursive = self._get_bool(args, "recursive", default=True)
        max_results = self._get_int(args, "maxresults", "limit", default=100000)
        dry_run = self._get_bool(args, "dryrun", default=False)

        root = project_data.getRootFolder()
        local_items = [item for item in self._list_domain_files(root, max_results * 5 if max_results > 0 else 100000) if item.get("type") != "Folder"]

        candidates: list[dict[str, Any]] = []
        for item in local_items:
            local_path = self._normalize_repo_path(str(item.get("path") or ""))
            if local_path and self._path_in_scope(local_path, source_folder, recursive):
                candidates.append(item)

        if max_results > 0:
            candidates = candidates[:max_results]

        transferred: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []

        for item in candidates:
            source_path = self._normalize_repo_path(str(item.get("path") or ""))
            if not source_path or source_path == "/":
                continue

            if dry_run:
                transferred.append({"sourcePath": source_path, "planned": True})
                continue

            try:
                source_file = project_data.getFile(source_path)
                if source_file is None:
                    raise ValueError(f"Local project item not found: {source_path}")

                if hasattr(source_file, "save"):
                    source_file.save()
                else:
                    skipped.append({"sourcePath": source_path, "reason": "save-not-supported"})
                    continue

                transferred.append({"sourcePath": source_path})
            except Exception as exc:
                errors.append({"sourcePath": source_path, "error": str(exc)})

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
        mode = self._resolve_shared_sync_mode(args, default_mode=default_mode)
        _, handle, repository_adapter, repository_name = self._get_shared_session_context()
        if not handle or n(str(handle.get("mode", ""))) != "sharedserver":
            return create_success_response(
                {
                    "operation": "sync-shared",
                    "mode": mode,
                    "success": False,
                    "error": "No active shared-server session. Run open with --server-host first.",
                },
            )

        if repository_adapter is None:
            return create_success_response(
                {
                    "operation": "sync-shared",
                    "mode": mode,
                    "success": False,
                    "repository": repository_name,
                    "error": "Shared repository adapter is unavailable in this session.",
                },
            )

        project_data = self._get_active_project_data()
        if project_data is None:
            return create_success_response(
                {
                    "operation": "sync-shared",
                    "mode": mode,
                    "success": False,
                    "repository": repository_name,
                    "error": "No local Ghidra project context available for shared sync.",
                },
            )

        if mode == "pull":
            pull_result = self._pull_shared_repository_to_local(args, repository_adapter, repository_name, project_data)
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
            push_result = self._push_local_project_to_shared(args, repository_name, project_data)
            return create_success_response(
                {
                    "operation": "sync-shared",
                    "mode": mode,
                    "direction": "local-to-shared",
                    "success": len(push_result["errors"]) == 0,
                    **push_result,
                },
            )

        pull_result = self._pull_shared_repository_to_local(args, repository_adapter, repository_name, project_data)
        push_result = self._push_local_project_to_shared(args, repository_name, project_data)

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

    async def _handle_list_project_binaries(self, args: dict[str, Any]) -> list[types.TextContent]:
        session_id = get_current_mcp_session_id()
        session_binaries = SESSION_CONTEXTS.get_project_binaries(session_id, fallback_to_latest=True)
        if session_binaries:
            return create_success_response({"binaries": session_binaries, "count": len(session_binaries)})

        if self.program_info is None:
            return create_success_response({"binaries": [], "count": 0, "note": "No project loaded"})
        try:
            program = getattr(self.program_info, "program", None)
            if program is None or not hasattr(program, "getDomainFile"):
                raise ValueError("No project loaded")
            root = program.getDomainFile().getProjectData().getRootFolder()
            binaries = [f for f in self._list_domain_files(root, 100000) if f.get("type") == "Program"]
            return create_success_response({"binaries": binaries, "count": len(binaries)})
        except Exception as exc:
            return create_success_response({"binaries": [], "count": 0, "error": str(exc)})

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
        parts = program_path.rsplit("/", 1)
        if len(parts) == 2:
            folder_path = parts[0] or "/"
            item_name = parts[1]
        else:
            folder_path = "/"
            item_name = parts[0]

        # Get the repository item
        repo_item = repository_adapter.getItem(folder_path, item_name)
        if repo_item is None:
            raise ValueError(f"Program '{program_path}' not found in repository folder '{folder_path}'")

        # Preferred path for shared-server mode: open repository database directly
        # in immutable mode and wrap it as ProgramDB. This avoids DomainFile
        # assumptions that do not hold for remote RepositoryItem instances.
        program = None
        try:
            version = int(repo_item.getVersion()) if hasattr(repo_item, "getVersion") else -1
            managed_db = repository_adapter.openDatabase(folder_path, item_name, version, 0)
            db_handle = DBHandle(managed_db)
            program = ProgramDB(db_handle, OpenMode.IMMUTABLE, monitor, JavaObject())
        except Exception as exc:
            logger.warning(
                "Shared ProgramDB open failed for %s (repo item %s/%s): %s",
                program_path,
                folder_path,
                item_name,
                exc,
            )

        # Open / checkout the file via the project data
        # We need to use the project's DomainFile which can be retrieved
        # from the project data after connecting.

        # Use the manager's GhidraProject (set from launcher) to get project data.
        project_data: ProjectData | None = None
        ghidra_project = getattr(self._manager, "ghidra_project", None) if self._manager else None
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

        if program is None and project_data is None:
            # Fallback: open the item directly via low-level API
            try:
                domain_obj = repo_item.getDomainObject(self, True, False, monitor)
            except Exception:
                # Many versions of Ghidra don't support getDomainObject on RepositoryItem
                raise ValueError(
                    f"Cannot checkout '{program_path}': direct RepositoryItem.getDomainObject not supported. Import the binary locally first using 'import-binary'.",
                )
            if domain_obj is None:
                raise ValueError(f"Failed to open '{program_path}' from repository")
            program = domain_obj
        elif program is None:
            assert project_data is not None, "project_data should be available if program is None"
            # Check if the file is already in the local project
            domain_file = project_data.getFile(program_path)
            if domain_file is None:
                # Need to checkout the file from the server into the local project
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
                remote_domain_obj = repo_item.getDomainObject(self, True, False, monitor)
                if remote_domain_obj is None:
                    raise ValueError(f"Failed to fetch remote domain object for '{program_path}'")
                try:
                    domain_file = parent_folder.createFile(item_name, remote_domain_obj, monitor)
                finally:
                    try:
                        remote_domain_obj.release(self)
                    except Exception:
                        pass
            if domain_file is None:
                raise ValueError(f"Failed to checkout '{program_path}' into local project")

            domain_obj = domain_file.getDomainObject(self, True, False, monitor)
            if domain_obj is None:
                raise ValueError(f"Failed to open '{program_path}'")
            program = domain_obj

        # Build ProgramInfo
        from ghidra.app.decompiler import DecompInterface  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

        from agentdecompile_cli.launcher import ProgramInfo

        decompiler = DecompInterface()
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

        def _walk(folder_path: str) -> None:
            subfolders = repository_adapter.getSubfolderList(folder_path) or []
            for subfolder in subfolders:
                subfolder_name = str(subfolder)
                next_path = f"{folder_path.rstrip('/')}/{subfolder_name}" if folder_path != "/" else f"/{subfolder_name}"
                _walk(next_path)

            repo_items = repository_adapter.getItemList(folder_path) or []
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

        _walk("/")
        return items

    async def _handle_list_project_binary_metadata(self, args: dict[str, Any]) -> list[types.TextContent]:
        if self.program_info is None:
            return create_success_response({"success": False, "error": "No program loaded"})

        binary_name = self._get_str(args, "binaryname", "binaryname", "programpath", "binary")
        program = self.program_info.program

        if binary_name and binary_name not in (program.getName(), str(program.getDomainFile().getPathname())):
            return create_success_response({"success": False, "error": f"Binary metadata currently available for active program only: {binary_name}"})

        metadata = {
            "binaryName": program.getName(),
            "projectPath": str(program.getDomainFile().getPathname()) if program.getDomainFile() else None,
            "languageId": str(program.getLanguage().getLanguageID()),
            "compilerSpecId": str(program.getCompilerSpec().getCompilerSpecID()),
            "imageBase": str(program.getImageBase()),
            "executableFormat": program.getExecutableFormat(),
            "functionCount": program.getFunctionManager().getFunctionCount(),
            "symbolCount": program.getSymbolTable().getNumSymbols(),
            "isAnalyzed": bool(getattr(self.program_info, "ghidra_analysis_complete", False)),
        }
        return create_success_response({"success": True, "metadata": metadata})

    async def _handle_delete_project_binary(self, args: dict[str, Any]) -> list[types.TextContent]:
        if self.program_info is None:
            return create_success_response({"success": False, "error": "No program loaded"})

        binary_name: str = self._require_str(args, "binaryname", "programpath", "binary", name="binaryName")
        program: Any = self.program_info.program
        domain_file = program.getDomainFile()
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

    async def _handle_list_open_programs(self, args: dict[str, Any]) -> list[types.TextContent]:
        if self.program_info is None:
            return create_success_response({"programs": [], "count": 0})
        program = self.program_info.program
        return create_success_response(
            {
                "programs": [
                    {
                        "name": program.getName(),
                        "path": str(program.getDomainFile().getPathname()) if program.getDomainFile() else None,
                    },
                ],
                "count": 1,
            },
        )

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

        program = self.program_info.program
        fm = program.getFunctionManager()
        first = None
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
