"""Batch analysis tools — Tier 1 ghidrecomp without an open MCP session program."""

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
from agentdecompile_cli.mcp_utils.batch_decompile import build_batch_decompile_payload
from agentdecompile_cli.registry import Tool

logger = logging.getLogger(__name__)


class BatchAnalysisToolProvider(ToolProvider):
    """Provider for run-batch-decompile (Tier 1 ghidrecomp batch export)."""

    HANDLERS = {
        "runbatchdecompile": "_handle_run_batch_decompile",
    }

    def list_tools(self) -> list[types.Tool]:
        logger.debug("diag.enter %s", "mcp_server/providers/batch_analysis.py:BatchAnalysisToolProvider.list_tools")
        return [
            types.Tool(
                name=Tool.RUN_BATCH_DECOMPILE.value,
                description=(
                    "Tier 1 batch decompile via ghidrecomp: headless analyze + per-function C export "
                    "to outputPath. Does not require an open MCP session program."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "binaryPath": {
                            "type": "string",
                            "description": "Path to the binary to analyze and decompile.",
                        },
                        "outputPath": {
                            "type": "string",
                            "description": "Root directory for ghidrecomp results (default ghidrecomps).",
                        },
                        "projectPath": {
                            "type": "string",
                            "description": "Ghidra project base path for batch analysis (default ghidra_projects).",
                        },
                        "functionFilter": {
                            "type": "string",
                            "description": "Optional regex filter applied to function names.",
                        },
                        "skipCache": {
                            "type": "boolean",
                            "description": "When true, regenerate decompilations even if cached (default false).",
                        },
                        "forceAnalysis": {
                            "type": "boolean",
                            "description": "Force re-analysis even if the program was analyzed before (default false).",
                        },
                        "callgraphs": {
                            "type": "boolean",
                            "description": "When true, also emit callgraph markdown artifacts (default false).",
                        },
                    },
                    "required": ["binaryPath"],
                },
            ),
        ]

    async def _handle_run_batch_decompile(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug(
            "diag.enter %s",
            "mcp_server/providers/batch_analysis.py:BatchAnalysisToolProvider._handle_run_batch_decompile",
        )
        try:
            binary_path = self._require_str(
                args,
                "binaryPath",
                "binary_path",
                "path",
                name="binaryPath",
            )
            output_path = self._get_str(args, "outputPath", "output_path") or "ghidrecomps"
            project_path = self._get_str(args, "projectPath", "project_path") or "ghidra_projects"
            function_filter = self._get_str(args, "functionFilter", "function_filter", "filter")
            skip_cache = self._get_bool(args, "skipCache", "skip_cache", default=False)
            force_analysis = self._get_bool(args, "forceAnalysis", "force_analysis", "fa", default=False)
            callgraphs = self._get_bool(args, "callgraphs", default=False)

            payload = build_batch_decompile_payload(
                Path(binary_path),
                output_path=output_path,
                project_path=project_path,
                function_filter=function_filter or None,
                skip_cache=skip_cache,
                force_analysis=force_analysis,
                callgraphs=callgraphs,
            )
            return create_success_response(payload)
        except FileNotFoundError as exc:
            return create_error_response(exc)
        except ValueError as exc:
            return create_error_response(exc)
        except OSError as exc:
            return create_error_response(exc)
