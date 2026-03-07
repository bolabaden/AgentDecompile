"""Debug Info Resource Provider - Python MCP implementation."""

from __future__ import annotations

import json
import logging
import sys
import time

from mcp import types

from ..profiling import get_profile_analyzer_path, get_profile_storage_dir, list_recent_profiles
from ..resource_providers import ResourceProvider

logger = logging.getLogger(__name__)


class DebugInfoResource(ResourceProvider):
    """MCP resource provider for comprehensive debug information."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._start_time: float = time.time()
        self._resource_read_count: int = 0

    def list_resources(self) -> list[types.Resource]:
        """Return list of debug info resources."""
        return [
            types.Resource(
                uri="ghidra://agentdecompile-debug-info",
                name="AgentDecompile Debug Info",
                description="Comprehensive debug information for AgentDecompile including server state, program analysis, and resource metrics",
                mimeType="application/json",
            ),
        ]

    async def read_resource(self, uri: str) -> str:
        """Read the debug info resource with comprehensive state information."""
        if uri != "ghidra://agentdecompile-debug-info":
            raise NotImplementedError(f"Unknown resource: {uri}")

        logger.info(f"DebugInfoResource: reading resource for URI {uri}")
        self._resource_read_count += 1

        try:
            # Build comprehensive debug info
            debug_info = {
                "metadata": self._get_metadata(),
                "server": self._get_server_state(),
                "program": self._get_program_state(),
                "analysis": self._get_analysis_state(),
                "profiling": self._get_profiling_state(),
                "resources": self._get_resource_metrics(),
            }

            result = json.dumps(debug_info, indent=2)
            logger.info(f"DebugInfoResource: successfully generated debug info, {len(result)} bytes")
            return result
        except Exception as e:
            logger.error(f"DebugInfoResource: Error generating debug info: {e}", exc_info=True)
            # Return minimal debug info on error
            fallback_info = {
                "metadata": self._get_metadata(),
                "server": {"status": "error", "error": str(e)},
                "program": {"status": "error"},
                "analysis": {"status": "error"},
                "profiling": {"status": "error"},
                "resources": {"read_count": self._resource_read_count},
            }
            return json.dumps(fallback_info, indent=2)

    def _get_metadata(self) -> dict:
        """Get metadata about the debug info itself."""
        return {
            "version": "2.0.0",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "agent_decompile_version": "1.1.0",
            "python_version": sys.version,
            "python_executable": sys.executable,
            "platform": sys.platform,
            "encoding": sys.getdefaultencoding(),
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
        }

    def _get_program_state(self) -> dict | None:
        """Get information about the currently loaded program."""
        if not self.program_info or not self.program_info.current_program:
            return {
                "status": "no_program_loaded",
                "current_program": None,
                "programs_available": 0,
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
            }
        except Exception as e:
            logger.warning(f"Error gathering program state: {e}")
            return {
                "status": "error",
                "error": str(e),
            }

    def _get_analysis_state(self) -> dict:
        """Get information about current program analysis."""
        if not self.program_info or not self.program_info.current_program:
            return {
                "status": "no_program",
                "functions_count": 0,
                "strings_count": 0,
                "symbols_count": 0,
                "data_types_count": 0,
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
                except:
                    strings_count = -1

            # Get symbols count
            symbols_count = 0
            if prog:
                try:
                    symbol_table = prog.getSymbolTable()
                    symbols_count = symbol_table.getGlobalSymbolCount()
                except:
                    symbols_count = -1

            # Get data types count
            data_types_count = 0
            if prog:
                try:
                    dtm = prog.getDataTypeManager()
                    # Count user-defined types (not built-ins)
                    data_types_count = len([dt for dt in dtm.getAllDataTypes() if not dt.isBuiltIn()])
                except:
                    data_types_count = -1

            return {
                "status": "available",
                "functions_count": functions_count,
                "strings_count": strings_count,
                "symbols_count": symbols_count,
                "data_types_count": data_types_count,
            }
        except Exception as e:
            logger.warning(f"Error gathering analysis state: {e}")
            return {
                "status": "error",
                "error": str(e),
            }

    def _get_resource_metrics(self) -> dict:
        """Get metrics about MCP resources and caching."""
        return {
            "resources_served": [
                "ghidra://programs",
                "ghidra://static-analysis-results",
                "ghidra://agentdecompile-debug-info",
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
