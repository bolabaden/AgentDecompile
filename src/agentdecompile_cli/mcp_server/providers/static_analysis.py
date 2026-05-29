"""Static analysis tools — Tier 0 file triage without Ghidra."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from mcp import types

from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
    create_error_response,
    create_success_response,
)
from agentdecompile_cli.mcp_utils.static_triage import build_file_triage_payload
from agentdecompile_cli.registry import Tool

logger = logging.getLogger(__name__)


class StaticAnalysisToolProvider(ToolProvider):
    """Provider for run-file-triage (no open Ghidra program required)."""

    HANDLERS = {
        "runfiletriage": "_handle_run_file_triage",
    }

    def list_tools(self) -> list[types.Tool]:
        logger.debug("diag.enter %s", "mcp_server/providers/static_analysis.py:StaticAnalysisToolProvider.list_tools")
        return [
            types.Tool(
                name=Tool.RUN_FILE_TRIAGE.value,
                description=(
                    "Tier 0 static triage: file(1), SHA-256, strings sample, and optional yara/capa/binwalk "
                    "probes when those tools are on PATH. Does not require Ghidra or an open program."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "binaryPath": {
                            "type": "string",
                            "description": "Absolute or relative path to the binary or artifact file.",
                        },
                        "stringLimit": {
                            "type": "integer",
                            "description": "Maximum number of strings to return (default 100).",
                        },
                        "stringFilter": {
                            "type": "string",
                            "description": "Optional case-insensitive substring filter applied to strings output.",
                        },
                        "tryYara": {
                            "type": "boolean",
                            "description": "When true, probe yara --version if yara is on PATH (default true).",
                        },
                        "tryCapa": {
                            "type": "boolean",
                            "description": "When true, probe capa --version if capa is on PATH (default true).",
                        },
                        "tryBinwalk": {
                            "type": "boolean",
                            "description": "When true, run binwalk -E entropy scan if binwalk is on PATH (default true).",
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Per-command timeout in milliseconds (default 30000).",
                        },
                    },
                    "required": ["binaryPath"],
                },
            ),
        ]

    async def _handle_run_file_triage(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/static_analysis.py:StaticAnalysisToolProvider._handle_run_file_triage")
        try:
            binary_path = self._require_str(
                args,
                "binaryPath",
                "binary_path",
                "path",
                name="binaryPath",
            )
            string_limit = self._get_int(args, "stringLimit", "string_limit", "limit", default=100) or 100
            string_filter = self._get_str(args, "stringFilter", "string_filter", "filter")
            try_yara = self._get_bool(args, "tryYara", "try_yara", default=True)
            try_capa = self._get_bool(args, "tryCapa", "try_capa", default=True)
            try_binwalk = self._get_bool(args, "tryBinwalk", "try_binwalk", default=True)
            timeout_ms = self._get_int(args, "timeout", default=30_000) or 30_000

            payload = build_file_triage_payload(
                Path(binary_path),
                string_limit=max(0, int(string_limit)),
                string_filter=string_filter or None,
                try_yara=try_yara,
                try_capa=try_capa,
                try_binwalk=try_binwalk,
                timeout_ms=max(1000, int(timeout_ms)),
            )
            return create_success_response(payload)
        except FileNotFoundError as exc:
            return create_error_response(exc)
        except ValueError as exc:
            return create_error_response(exc)
        except OSError as exc:
            return create_error_response(exc)
