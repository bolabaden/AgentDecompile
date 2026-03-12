"""Debug Info Resource Provider - Python MCP implementation."""

from __future__ import annotations

import json
import logging
import os
import sys
import time

from pathlib import Path
from typing import Any

from mcp import types
from pydantic import AnyUrl

from agentdecompile_cli.mcp_server.auth import get_current_auth_context
from agentdecompile_cli.mcp_server.session_context import SESSION_CONTEXTS, get_current_mcp_session_id
from agentdecompile_cli.registry import RESOURCE_URI_DEBUG_INFO, ToolName

from agentdecompile_cli.mcp_server.profiling import get_profile_analyzer_path, get_profile_storage_dir, list_recent_profiles
from agentdecompile_cli.mcp_server.resource_providers import ResourceProvider
from .programs import ProgramListResource
from .static_analysis import StaticAnalysisResultsResource

logger = logging.getLogger(__name__)

_LEGACY_PROGRAMS_URI = "ghidra://programs"
_LEGACY_STATIC_ANALYSIS_URI = "ghidra://static-analysis-results"
_LEGACY_DEBUG_INFO_URI = "ghidra://agentdecompile-debug-info"
_SUPPORTED_URIS = frozenset(
    {
        RESOURCE_URI_DEBUG_INFO,
        _LEGACY_PROGRAMS_URI,
        _LEGACY_STATIC_ANALYSIS_URI,
        _LEGACY_DEBUG_INFO_URI,
    }
)


class DebugInfoResource(ResourceProvider):
    """MCP resource provider for comprehensive debug information."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._start_time: float = time.time()
        self._resource_read_count: int = 0
        self._programs_resource = ProgramListResource()
        self._static_analysis_resource = StaticAnalysisResultsResource()

    def set_program_info(self, program_info) -> None:
        super().set_program_info(program_info)
        self._programs_resource.set_program_info(program_info)
        self._static_analysis_resource.set_program_info(program_info)

    def set_tool_provider_manager(self, tool_provider_manager: Any) -> None:
        super().set_tool_provider_manager(tool_provider_manager)
        self._programs_resource.set_tool_provider_manager(tool_provider_manager)
        self._static_analysis_resource.set_tool_provider_manager(tool_provider_manager)

    def set_runtime_context(self, runtime_context: dict[str, Any]) -> None:
        super().set_runtime_context(runtime_context)
        self._programs_resource.set_runtime_context(runtime_context)
        self._static_analysis_resource.set_runtime_context(runtime_context)

    def list_resources(self) -> list[types.Resource]:
        """Return list of debug info resources."""
        return [
            types.Resource(
                uri=AnyUrl(url=RESOURCE_URI_DEBUG_INFO),
                name="AgentDecompile Debug Info",
                description="Unified AgentDecompile resource with forced open-project diagnostics, project inventory, program state, and profiling details",
                mimeType="application/json",
            ),
        ]

    async def read_resource(self, uri: str) -> str:
        """Read the debug info resource with comprehensive state information."""
        uri_text = str(uri)
        if uri_text not in _SUPPORTED_URIS:
            raise NotImplementedError(f"Unknown resource: {uri}")

        logger.info("DebugInfoResource: reading resource for URI %s", uri_text)
        self._resource_read_count += 1
        open_project_attempt = await self._force_open_project(uri_text)

        if uri_text == _LEGACY_PROGRAMS_URI:
            logger.info("DebugInfoResource: serving legacy programs alias after open-project attempt")
            return await self._programs_resource.read_resource(uri_text)

        if uri_text == _LEGACY_STATIC_ANALYSIS_URI:
            logger.info("DebugInfoResource: serving legacy static-analysis alias after open-project attempt")
            return await self._static_analysis_resource.read_resource(uri_text)

        try:
            list_project_files = await self._safe_tool_call(
                ToolName.LIST_PROJECT_FILES.value,
                {"folder": "/", "maxResults": 250, "format": "json"},
            )
            current_program = await self._safe_tool_call(
                ToolName.GET_CURRENT_PROGRAM.value,
                {"format": "json"},
            )
            legacy_programs = await self._safe_load_json_resource(self._programs_resource, _LEGACY_PROGRAMS_URI)
            legacy_static_analysis = await self._safe_load_json_resource(self._static_analysis_resource, _LEGACY_STATIC_ANALYSIS_URI)

            debug_info = {
                "metadata": self._get_metadata(),
                "request": self._get_request_state(uri_text),
                "openProject": open_project_attempt,
                "server": self._get_server_state(),
                "runtime": self._get_runtime_state(),
                "session": self._get_session_state(),
                "project": self._get_project_state(list_project_files),
                "programCatalog": legacy_programs,
                "program": self._get_program_state(current_program),
                "analysis": self._get_analysis_state(legacy_static_analysis),
                "profiling": self._get_profiling_state(),
                "resources": self._get_resource_metrics(),
            }

            result = json.dumps(debug_info, indent=2)
            logger.info("DebugInfoResource: successfully generated debug info, %d bytes", len(result))
            return result
        except Exception as e:
            logger.error("DebugInfoResource: Error generating debug info: %s", e, exc_info=True)
            # Return minimal debug info on error
            fallback_info = {
                "metadata": self._get_metadata(),
                "request": self._get_request_state(uri_text),
                "openProject": open_project_attempt,
                "server": {"status": "error", "error": str(e)},
                "runtime": self._get_runtime_state(),
                "session": self._get_session_state(),
                "project": {"status": "error"},
                "program": {"status": "error"},
                "analysis": {"status": "error"},
                "profiling": {"status": "error"},
                "resources": {"read_count": self._resource_read_count},
            }
            return json.dumps(fallback_info, indent=2)

    async def _safe_load_json_resource(self, provider: ResourceProvider, uri: str) -> dict[str, Any]:
        try:
            raw = await provider.read_resource(uri)
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {"value": parsed}
        except Exception as exc:
            logger.warning("DebugInfoResource: failed to load resource %s: %s", uri, exc)
            return {"status": "error", "uri": uri, "error": str(exc)}

    async def _safe_tool_call(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if self.tool_provider_manager is None:
            return {
                "tool": tool_name,
                "attempted": False,
                "success": False,
                "error": "tool_provider_manager unavailable",
            }

        start_time = time.time()
        payload = dict(arguments or {})
        payload.setdefault("format", "json")
        logger.info("DebugInfoResource: calling %s with args=%s", tool_name, self._sanitize_sensitive(payload))
        try:
            response = await self.tool_provider_manager.call_tool(tool_name, payload)
            parsed = self._parse_tool_response(response)
            success = self._tool_response_succeeded(parsed)
            elapsed = round(time.time() - start_time, 3)
            logger.info(
                "DebugInfoResource: tool %s completed success=%s in %.3fs",
                tool_name,
                success,
                elapsed,
            )
            return {
                "tool": tool_name,
                "attempted": True,
                "success": success,
                "durationSeconds": elapsed,
                "arguments": self._sanitize_sensitive(payload),
                "response": parsed,
            }
        except Exception as exc:
            elapsed = round(time.time() - start_time, 3)
            logger.error("DebugInfoResource: tool %s failed after %.3fs: %s", tool_name, elapsed, exc, exc_info=True)
            return {
                "tool": tool_name,
                "attempted": True,
                "success": False,
                "durationSeconds": elapsed,
                "arguments": self._sanitize_sensitive(payload),
                "error": str(exc),
            }

    async def _force_open_project(self, requested_uri: str) -> dict[str, Any]:
        open_args, source = self._build_open_project_arguments()
        logger.info(
            "DebugInfoResource: forcing open-project for resource=%s source=%s args=%s",
            requested_uri,
            source,
            self._sanitize_sensitive(open_args),
        )
        result = await self._safe_tool_call(ToolName.OPEN_PROJECT.value, open_args)
        result["requestedResourceUri"] = requested_uri
        result["argumentSource"] = source
        return result

    def _build_open_project_arguments(self) -> tuple[dict[str, Any], str]:
        session_id = get_current_mcp_session_id()
        session_snapshot = SESSION_CONTEXTS.get_session_snapshot(session_id, project_binary_limit=10, tool_history_limit=5)
        project_handle = session_snapshot.get("projectHandle")

        if isinstance(project_handle, dict):
            mode = str(project_handle.get("mode") or "")
            active_program_key = session_snapshot.get("activeProgramKey")
            if mode == "shared-server":
                repository_name = str(project_handle.get("repository_name") or "").strip()
                shared_path = str(active_program_key or repository_name).strip()
                return (
                    {
                        "shared": True,
                        "serverHost": project_handle.get("server_host"),
                        "serverPort": project_handle.get("server_port"),
                        "serverUsername": project_handle.get("server_username"),
                        "serverPassword": project_handle.get("server_password"),
                        "repositoryName": repository_name or None,
                        "path": shared_path or repository_name,
                    },
                    "session-project-handle:shared-server",
                )
            if mode == "local-gpr":
                project_path = str(project_handle.get("path") or "").strip()
                return ({"path": project_path}, "session-project-handle:local-gpr")

        auth_ctx = get_current_auth_context()
        if auth_ctx is not None and auth_ctx.server_host:
            shared_path = (session_snapshot.get("activeProgramKey") or auth_ctx.repository or "").strip()
            return (
                {
                    "shared": True,
                    "serverHost": auth_ctx.server_host,
                    "serverPort": auth_ctx.server_port,
                    "serverUsername": auth_ctx.username or None,
                    "serverPassword": auth_ctx.password,
                    "repositoryName": auth_ctx.repository or None,
                    "path": shared_path or auth_ctx.repository,
                },
                "auth-context:shared-server",
            )

        env_host = self._get_env_value(
            "AGENT_DECOMPILE_GHIDRA_SERVER_HOST",
            "AGENTDECOMPILE_HTTP_GHIDRA_SERVER_HOST",
            "AGENTDECOMPILE_GHIDRA_SERVER_HOST",
            "AGENT_DECOMPILE_SERVER_HOST",
            "AGENTDECOMPILE_SERVER_HOST",
        )
        if env_host:
            env_repo = self._get_env_value(
                "AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY",
                "AGENTDECOMPILE_HTTP_GHIDRA_SERVER_REPOSITORY",
                "AGENTDECOMPILE_GHIDRA_SERVER_REPOSITORY",
                "AGENT_DECOMPILE_REPOSITORY",
                "AGENTDECOMPILE_REPOSITORY",
            )
            shared_path = str(session_snapshot.get("activeProgramKey") or env_repo or "").strip()
            return (
                {
                    "shared": True,
                    "serverHost": env_host,
                    "serverPort": self._get_env_value(
                        "AGENT_DECOMPILE_GHIDRA_SERVER_PORT",
                        "AGENTDECOMPILE_HTTP_GHIDRA_SERVER_PORT",
                        "AGENT_DECOMPILE_SERVER_PORT",
                        "AGENTDECOMPILE_SERVER_PORT",
                    )
                    or "13100",
                    "serverUsername": self._get_env_value(
                        "AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME",
                        "AGENT_DECOMPILE_SERVER_USERNAME",
                        "AGENTDECOMPILE_SERVER_USERNAME",
                    ),
                    "serverPassword": self._get_env_value(
                        "AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD",
                        "AGENT_DECOMPILE_SERVER_PASSWORD",
                        "AGENTDECOMPILE_SERVER_PASSWORD",
                    ),
                    "repositoryName": env_repo or None,
                    "path": shared_path or env_repo,
                },
                "environment:shared-server",
            )

        runtime_gpr = str(self.runtime_context.get("projectPathGpr") or "").strip()
        if runtime_gpr:
            return ({"path": runtime_gpr}, "runtime-context:gpr")

        runtime_dir = str(self.runtime_context.get("projectDirectory") or "").strip()
        runtime_name = str(self.runtime_context.get("projectName") or "").strip()
        if runtime_dir and runtime_name:
            synthesized_gpr = str(Path(runtime_dir) / f"{runtime_name}.gpr")
            return ({"path": synthesized_gpr}, "runtime-context:directory")

        if self.program_info is not None and self.program_info.file_path is not None:
            return ({"path": str(self.program_info.file_path)}, "program-info:file-path")

        return ({}, "unresolved")

    @staticmethod
    def _get_env_value(*names: str) -> str:
        for name in names:
            value = os.getenv(name, "").strip()
            if value:
                return value
        return ""

    @staticmethod
    def _parse_tool_response(response: Any) -> Any:
        if not isinstance(response, list):
            return response

        text_parts: list[str] = []
        for item in response:
            text = getattr(item, "text", None)
            if isinstance(text, str):
                text_parts.append(text)

        if not text_parts:
            return []

        merged = "\n".join(text_parts)
        try:
            return json.loads(merged)
        except Exception:
            return {"rawText": merged}

    @staticmethod
    def _tool_response_succeeded(parsed: Any) -> bool:
        if isinstance(parsed, dict):
            if parsed.get("success") is False:
                return False
            if parsed.get("error"):
                return False
        return True

    @classmethod
    def _sanitize_sensitive(cls, value: Any) -> Any:
        if isinstance(value, dict):
            sanitized: dict[str, Any] = {}
            for key, item in value.items():
                lowered = str(key).lower()
                if "password" in lowered:
                    sanitized[key] = "***"
                elif lowered.endswith("adapter"):
                    sanitized[key] = type(item).__name__ if item is not None else None
                else:
                    sanitized[key] = cls._sanitize_sensitive(item)
            return sanitized
        if isinstance(value, list):
            return [cls._sanitize_sensitive(item) for item in value]
        if isinstance(value, tuple):
            return [cls._sanitize_sensitive(item) for item in value]
        if isinstance(value, Path):
            return str(value)
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        return str(value)

    def _get_metadata(self) -> dict:
        """Get metadata about the debug info itself."""
        return {
            "version": "3.0.0",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "agent_decompile_version": "1.1.0",
            "python_version": sys.version,
            "python_executable": sys.executable,
            "platform": sys.platform,
            "encoding": sys.getdefaultencoding(),
        }

    def _get_request_state(self, requested_uri: str) -> dict[str, Any]:
        session_id = get_current_mcp_session_id()
        return {
            "requestedUri": requested_uri,
            "canonicalUri": RESOURCE_URI_DEBUG_INFO,
            "legacyCompatibilityUris": [
                _LEGACY_PROGRAMS_URI,
                _LEGACY_STATIC_ANALYSIS_URI,
                _LEGACY_DEBUG_INFO_URI,
            ],
            "sessionId": session_id,
            "resourceReadCount": self._resource_read_count,
        }

    def _get_server_state(self) -> dict:
        """Get server runtime state information."""
        uptime_seconds = time.time() - self._start_time
        uptime_hours = uptime_seconds / 3600
        uptime_minutes = (uptime_seconds % 3600) / 60

        return {
            "status": "running",
            "uptime": {
                "seconds": round(uptime_seconds, 2),
                "formatted": f"{int(uptime_hours)}h {int(uptime_minutes)}m",
            },
            "resource_reads": self._resource_read_count,
            "runtimeContextAvailable": bool(self.runtime_context),
        }

    def _get_runtime_state(self) -> dict[str, Any]:
        auth_ctx = get_current_auth_context()
        auth_state = None
        if auth_ctx is not None:
            auth_state = self._sanitize_sensitive(
                {
                    "serverHost": auth_ctx.server_host,
                    "serverPort": auth_ctx.server_port,
                    "username": auth_ctx.username,
                    "password": auth_ctx.password,
                    "repository": auth_ctx.repository,
                }
            )

        env_state = self._sanitize_sensitive(
            {
                "projectPath": self._get_env_value("AGENT_DECOMPILE_PROJECT_PATH", "AGENTDECOMPILE_PROJECT_PATH"),
                "sharedServerHost": self._get_env_value(
                    "AGENT_DECOMPILE_GHIDRA_SERVER_HOST",
                    "AGENTDECOMPILE_HTTP_GHIDRA_SERVER_HOST",
                    "AGENTDECOMPILE_GHIDRA_SERVER_HOST",
                    "AGENT_DECOMPILE_SERVER_HOST",
                    "AGENTDECOMPILE_SERVER_HOST",
                ),
                "sharedServerPort": self._get_env_value(
                    "AGENT_DECOMPILE_GHIDRA_SERVER_PORT",
                    "AGENTDECOMPILE_HTTP_GHIDRA_SERVER_PORT",
                    "AGENT_DECOMPILE_SERVER_PORT",
                    "AGENTDECOMPILE_SERVER_PORT",
                ),
                "sharedServerRepository": self._get_env_value(
                    "AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY",
                    "AGENTDECOMPILE_HTTP_GHIDRA_SERVER_REPOSITORY",
                    "AGENTDECOMPILE_GHIDRA_SERVER_REPOSITORY",
                    "AGENT_DECOMPILE_REPOSITORY",
                    "AGENTDECOMPILE_REPOSITORY",
                ),
                "sharedServerUsername": self._get_env_value(
                    "AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME",
                    "AGENT_DECOMPILE_SERVER_USERNAME",
                    "AGENTDECOMPILE_SERVER_USERNAME",
                ),
                "sharedServerPassword": self._get_env_value(
                    "AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD",
                    "AGENT_DECOMPILE_SERVER_PASSWORD",
                    "AGENTDECOMPILE_SERVER_PASSWORD",
                ),
            }
        )

        return {
            "startup": self._sanitize_sensitive(self.runtime_context),
            "authContext": auth_state,
            "environment": env_state,
        }

    def _get_session_state(self) -> dict[str, Any]:
        session_id = get_current_mcp_session_id()
        snapshot = SESSION_CONTEXTS.get_session_snapshot(session_id, project_binary_limit=250, tool_history_limit=50)
        return self._sanitize_sensitive(snapshot)

    def _get_project_state(self, list_project_files: dict[str, Any]) -> dict[str, Any]:
        session_id = get_current_mcp_session_id()
        binaries = SESSION_CONTEXTS.get_project_binaries(session_id, fallback_to_latest=True)
        runtime_dir = str(self.runtime_context.get("projectDirectory") or "").strip()
        return {
            "status": "available",
            "sessionBinaryCount": len(binaries),
            "sessionBinariesPreview": self._sanitize_sensitive(binaries[:100]),
            "projectListing": list_project_files,
            "localFilesystemPreview": self._list_local_project_filesystem(runtime_dir),
        }

    @staticmethod
    def _list_local_project_filesystem(project_dir: str) -> dict[str, Any]:
        if not project_dir:
            return {"status": "unavailable", "reason": "runtime project directory not set"}

        root = Path(project_dir)
        if not root.exists():
            return {"status": "missing", "path": str(root)}

        entries: list[dict[str, Any]] = []
        for item in sorted(root.iterdir(), key=lambda path: (not path.is_dir(), path.name.lower()))[:200]:
            try:
                entries.append(
                    {
                        "name": item.name,
                        "path": str(item),
                        "isDirectory": item.is_dir(),
                        "size": None if item.is_dir() else item.stat().st_size,
                    }
                )
            except Exception as exc:
                entries.append(
                    {
                        "name": item.name,
                        "path": str(item),
                        "error": str(exc),
                    }
                )

        return {
            "status": "available",
            "path": str(root),
            "entries": entries,
            "count": len(entries),
        }

    def _get_program_state(self, current_program_probe: dict[str, Any] | None = None) -> dict | None:
        """Get information about the currently loaded program."""
        if not self.program_info or not self.program_info.current_program:
            return {
                "status": "no_program_loaded",
                "current_program": None,
                "programs_available": 0,
                "currentProgramProbe": current_program_probe,
            }

        try:
            prog = self.program_info.current_program
            prog_name = prog.getName() if prog else None
            metadata = self.program_info.metadata or {}

            return {
                "status": "loaded",
                "current_program": prog_name,
                "file_path": str(self.program_info.file_path) if self.program_info.file_path else None,
                "load_time": self.program_info.load_time,
                "architecture": metadata.get("architecture", "unknown"),
                "format": metadata.get("format", "unknown"),
                "language": metadata.get("language", "unknown"),
                "compiler_spec": metadata.get("compiler_spec", "unknown"),
                "image_base": metadata.get("image_base", None),
                "analysis_complete": self.program_info.analysis_complete,
                "currentProgramProbe": current_program_probe,
            }
        except Exception as e:
            logger.warning("Error gathering program state: %s", e)
            return {
                "status": "error",
                "error": str(e),
                "currentProgramProbe": current_program_probe,
            }

    def _get_analysis_state(self, static_analysis_report: dict[str, Any] | None = None) -> dict:
        """Get information about current program analysis."""
        if not self.program_info or not self.program_info.current_program:
            return {
                "status": "no_program",
                "functions_count": 0,
                "strings_count": 0,
                "symbols_count": 0,
                "data_types_count": 0,
                "staticAnalysisReport": static_analysis_report,
            }

        try:
            prog = self.program_info.current_program
            listing = prog.getListing() if prog else None

            # Gather analysis metrics
            functions_count = 0
            if listing:
                functions_count = listing.getNumFunctions()

            # Get strings
            strings_count = 0
            if self.program_info.strings_collection:
                try:
                    strings_count = len(list(self.program_info.strings_collection))
                except Exception:
                    strings_count = -1

            # Get symbols count
            symbols_count = 0
            if prog:
                try:
                    symbol_table = prog.getSymbolTable()
                    symbols_count = symbol_table.getGlobalSymbolCount()
                except Exception:
                    symbols_count = -1

            # Get data types count
            data_types_count = 0
            if prog:
                try:
                    dtm = prog.getDataTypeManager()
                    # Count user-defined types (not built-ins)
                    data_types_count = len([dt for dt in dtm.getAllDataTypes() if not dt.isBuiltIn()])
                except Exception:
                    data_types_count = -1

            return {
                "status": "available",
                "functions_count": functions_count,
                "strings_count": strings_count,
                "symbols_count": symbols_count,
                "data_types_count": data_types_count,
                "staticAnalysisReport": static_analysis_report,
            }
        except Exception as e:
            logger.warning("Error gathering analysis state: %s", e)
            return {
                "status": "error",
                "error": str(e),
                "staticAnalysisReport": static_analysis_report,
            }

    def _get_resource_metrics(self) -> dict:
        """Get metrics about MCP resources and caching."""
        return {
            "resources_served": [
                RESOURCE_URI_DEBUG_INFO,
            ],
            "legacy_compatibility_aliases": [
                _LEGACY_PROGRAMS_URI,
                _LEGACY_STATIC_ANALYSIS_URI,
                _LEGACY_DEBUG_INFO_URI,
            ],
            "cache_status": "enabled",
            "debug_info_reads": self._resource_read_count,
        }

    def _get_profiling_state(self) -> dict:
        analyzer_path = get_profile_analyzer_path()
        recent_runs = list_recent_profiles()
        return {
            "status": "available",
            "storage_dir": str(get_profile_storage_dir()),
            "analyzer_path": str(analyzer_path) if analyzer_path is not None else None,
            "recent_runs": recent_runs,
            "run_count": len(recent_runs),
        }
