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
from agentdecompile_cli.mcp_utils.batch_bsim import build_batch_bsim_payload
from agentdecompile_cli.mcp_utils.batch_decompile import build_batch_decompile_payload
from agentdecompile_cli.mcp_utils.batch_gzf import build_batch_gzf_payload
from agentdecompile_cli.mcp_utils.batch_sast import build_batch_sast_payload
from agentdecompile_cli.registry import Tool

logger = logging.getLogger(__name__)


class BatchAnalysisToolProvider(ToolProvider):
    """Provider for Tier 1 ghidrecomp batch tools (no open MCP session program)."""

    HANDLERS = {
        "runbatchdecompile": "_handle_run_batch_decompile",
        "runbatchexportgzf": "_handle_run_batch_export_gzf",
        "runbatchbsimsignatures": "_handle_run_batch_bsim_signatures",
        "runbatchsastscan": "_handle_run_batch_sast_scan",
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
            types.Tool(
                name=Tool.RUN_BATCH_EXPORT_GZF.value,
                description=(
                    "Tier 1 batch gzf export via ghidrecomp: headless analyze + packed .gzf snapshot "
                    "under gzfPath. Does not require an open MCP session program."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "binaryPath": {
                            "type": "string",
                            "description": "Path to the binary to analyze and export as .gzf.",
                        },
                        "outputPath": {
                            "type": "string",
                            "description": "Root directory for ghidrecomp results (default ghidrecomps).",
                        },
                        "gzfPath": {
                            "type": "string",
                            "description": (
                                "Directory for .gzf archives (default gzfs under outputPath, "
                                "or absolute/custom path matching ghidrecomp --gzf-path)."
                            ),
                        },
                        "projectPath": {
                            "type": "string",
                            "description": "Ghidra project base path for batch analysis (default ghidra_projects).",
                        },
                        "forceAnalysis": {
                            "type": "boolean",
                            "description": "Force re-analysis even if the program was analyzed before (default false).",
                        },
                        "skipSymbols": {
                            "type": "boolean",
                            "description": "When true, skip PDB/symbol application (default true).",
                        },
                    },
                    "required": ["binaryPath"],
                },
            ),
            types.Tool(
                name=Tool.RUN_BATCH_BSIM_SIGNATURES.value,
                description=(
                    "Tier 1 batch BSim signatures via ghidrecomp: headless analyze + BSim XML "
                    "signature export under bsimSigPath. Skips gracefully when BSim is not installed. "
                    "Does not require an open MCP session program."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "binaryPath": {
                            "type": "string",
                            "description": "Path to the binary to analyze and sign.",
                        },
                        "outputPath": {
                            "type": "string",
                            "description": "Root directory for ghidrecomp results (default ghidrecomps).",
                        },
                        "bsimSigPath": {
                            "type": "string",
                            "description": "Directory for BSim XML signatures (default bsim-xmls under outputPath).",
                        },
                        "bsimTemplate": {
                            "type": "string",
                            "description": "BSim database template name (default medium_nosize).",
                        },
                        "bsimCategories": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional BSim categories as type:value strings (e.g. family:malware).",
                        },
                        "projectPath": {
                            "type": "string",
                            "description": "Ghidra project base path for batch analysis (default ghidra_projects).",
                        },
                        "functionFilter": {
                            "type": "string",
                            "description": "Optional regex filter applied to function names before signing.",
                        },
                        "forceAnalysis": {
                            "type": "boolean",
                            "description": "Force re-analysis even if the program was analyzed before (default false).",
                        },
                    },
                    "required": ["binaryPath"],
                },
            ),
            types.Tool(
                name=Tool.RUN_BATCH_SAST_SCAN.value,
                description=(
                    "Tier 1 batch SAST scan via ghidrecomp: headless analyze + decompile + "
                    "Semgrep SARIF under sastPath. Skips gracefully when semgrep is not on PATH. "
                    "Does not require an open MCP session program."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "binaryPath": {
                            "type": "string",
                            "description": "Path to the binary to analyze and scan.",
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
                            "description": "Optional regex filter applied to function names before decompile.",
                        },
                        "forceAnalysis": {
                            "type": "boolean",
                            "description": "Force re-analysis even if the program was analyzed before (default false).",
                        },
                        "semgrepRules": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": (
                                "Optional Semgrep rule paths or pack names (default p/c when omitted)."
                            ),
                        },
                        "codeqlRules": {
                            "type": "string",
                            "description": "Comma-separated CodeQL query directory paths (placeholder in ghidrecomp).",
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

    async def _handle_run_batch_export_gzf(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug(
            "diag.enter %s",
            "mcp_server/providers/batch_analysis.py:BatchAnalysisToolProvider._handle_run_batch_export_gzf",
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
            gzf_path = self._get_str(args, "gzfPath", "gzf_path") or "gzfs"
            project_path = self._get_str(args, "projectPath", "project_path") or "ghidra_projects"
            force_analysis = self._get_bool(args, "forceAnalysis", "force_analysis", "fa", default=False)
            skip_symbols = self._get_bool(args, "skipSymbols", "skip_symbols", default=True)

            payload = build_batch_gzf_payload(
                Path(binary_path),
                output_path=output_path,
                gzf_path=gzf_path,
                project_path=project_path,
                force_analysis=force_analysis,
                skip_symbols=skip_symbols,
            )
            return create_success_response(payload)
        except FileNotFoundError as exc:
            return create_error_response(exc)
        except ValueError as exc:
            return create_error_response(exc)
        except OSError as exc:
            return create_error_response(exc)

    async def _handle_run_batch_bsim_signatures(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug(
            "diag.enter %s",
            "mcp_server/providers/batch_analysis.py:BatchAnalysisToolProvider._handle_run_batch_bsim_signatures",
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
            bsim_sig_path = self._get_str(args, "bsimSigPath", "bsim_sig_path") or "bsim-xmls"
            bsim_template = self._get_str(args, "bsimTemplate", "bsim_template") or "medium_nosize"
            project_path = self._get_str(args, "projectPath", "project_path") or "ghidra_projects"
            function_filter = self._get_str(args, "functionFilter", "function_filter", "filter")
            force_analysis = self._get_bool(args, "forceAnalysis", "force_analysis", "fa", default=False)
            raw_categories = self._get_list(args, "bsimCategories", "bsim_categories", "bsimCat")
            bsim_categories = [str(item) for item in raw_categories] if raw_categories else None

            payload = build_batch_bsim_payload(
                Path(binary_path),
                output_path=output_path,
                bsim_sig_path=bsim_sig_path,
                bsim_template=bsim_template,
                bsim_categories=bsim_categories,
                project_path=project_path,
                function_filter=function_filter or None,
                force_analysis=force_analysis,
            )
            return create_success_response(payload)
        except FileNotFoundError as exc:
            return create_error_response(exc)
        except ValueError as exc:
            return create_error_response(exc)
        except OSError as exc:
            return create_error_response(exc)

    async def _handle_run_batch_sast_scan(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug(
            "diag.enter %s",
            "mcp_server/providers/batch_analysis.py:BatchAnalysisToolProvider._handle_run_batch_sast_scan",
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
            force_analysis = self._get_bool(args, "forceAnalysis", "force_analysis", "fa", default=False)
            codeql_rules = self._get_str(args, "codeqlRules", "codeql_rules")
            raw_rules = self._get_list(args, "semgrepRules", "semgrep_rules")
            semgrep_rules = [str(item) for item in raw_rules] if raw_rules else None

            payload = build_batch_sast_payload(
                Path(binary_path),
                output_path=output_path,
                project_path=project_path,
                function_filter=function_filter or None,
                force_analysis=force_analysis,
                semgrep_rules=semgrep_rules,
                codeql_rules=codeql_rules,
            )
            return create_success_response(payload)
        except FileNotFoundError as exc:
            return create_error_response(exc)
        except ValueError as exc:
            return create_error_response(exc)
        except OSError as exc:
            return create_error_response(exc)
