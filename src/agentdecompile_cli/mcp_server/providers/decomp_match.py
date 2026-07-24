"""Decomp matching tools — Tier 1 m2c/objdiff/permuter without Ghidra MCP session."""

from __future__ import annotations

import logging
from typing import Any

from mcp import types

from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
    create_error_response,
    create_success_response,
)
from agentdecompile_cli.mcp_utils.decomp_match import (
    build_decomp_match_bundle_payload,
    build_decomp_match_payload,
)
from agentdecompile_cli.registry import Tool

logger = logging.getLogger(__name__)


class DecompMatchToolProvider(ToolProvider):
    """Provider for Tier 1 decomp matching (bytecode verify via objdiff, no JVM)."""

    HANDLERS = {
        "rundecompmatch": "_handle_run_decomp_match",
    }

    def list_tools(self) -> list[types.Tool]:
        logger.debug("diag.enter %s", "mcp_server/providers/decomp_match.py:DecompMatchToolProvider.list_tools")
        return [
            types.Tool(
                name=Tool.RUN_DECOMP_MATCH.value,
                description=(
                    "Tier 1 decomp matching: invoke m2c (asm→C), objdiff (bytecode/object match "
                    "verification), or decomp-permuter when on PATH. Does not require Ghidra or an "
                    "open MCP session program. For shared Ghidra Server projects, use Ghidra MCP only "
                    "for checkout/struct export/check-in — not for match verification."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "tool": {
                            "type": "string",
                            "enum": ["m2c", "objdiff", "permuter", "all"],
                            "description": (
                                "External decomp tool: m2c, objdiff (bytecode match), permuter, "
                                "or all (bundle; skips tools without required paths)."
                            ),
                        },
                        "tools": {
                            "type": "array",
                            "items": {"type": "string", "enum": ["m2c", "objdiff", "permuter", "all"]},
                            "description": "Optional explicit tool list for bundle mode.",
                        },
                        "assemblyPath": {
                            "type": "string",
                            "description": "Path to assembly (.s) for m2c.",
                        },
                        "functionName": {
                            "type": "string",
                            "description": "Optional m2c -f function filter.",
                        },
                        "target": {
                            "type": "string",
                            "description": "m2c --target (e.g. ppc-mwcc-c++, mips-ido-c).",
                        },
                        "contextPath": {
                            "type": "string",
                            "description": "m2c --context header file.",
                        },
                        "projectPath": {
                            "type": "string",
                            "description": "Decomp project root (objdiff.json) for objdiff report/diff.",
                        },
                        "unitName": {
                            "type": "string",
                            "description": "objdiff translation unit name filter.",
                        },
                        "targetObjectPath": {
                            "type": "string",
                            "description": "Expected/target .o for objdiff diff mode.",
                        },
                        "baseObjectPath": {
                            "type": "string",
                            "description": "Current/compiled .o for objdiff diff mode.",
                        },
                        "symbol": {
                            "type": "string",
                            "description": "Function symbol for objdiff diff mode.",
                        },
                        "objdiffMode": {
                            "type": "string",
                            "enum": ["report", "diff"],
                            "description": "objdiff report (project progress) or diff (one object). Default report.",
                        },
                        "permuterDir": {
                            "type": "string",
                            "description": "Permuter input directory (.c, .o, .sh, settings.toml).",
                        },
                        "permuterScript": {
                            "type": "string",
                            "description": "Optional path to permuter.py (default: permuter on PATH).",
                        },
                        "jobs": {
                            "type": "integer",
                            "description": "Permuter -j worker count.",
                        },
                        "extraArgs": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Extra CLI args forwarded to m2c or permuter.",
                        },
                        "outputLimit": {
                            "type": "integer",
                            "description": "Max output lines per tool (default 200).",
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Per-command timeout in milliseconds (default 120000).",
                        },
                    },
                },
            ),
        ]

    async def _handle_run_decomp_match(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug(
            "diag.enter %s",
            "mcp_server/providers/decomp_match.py:DecompMatchToolProvider._handle_run_decomp_match",
        )
        try:
            tool = self._get_str(args, "tool")
            raw_tools = self._get_list(args, "tools")
            tools = [str(item) for item in raw_tools] if raw_tools else None
            assembly_path = self._get_str(args, "assemblyPath", "assembly_path", "asmPath", "asm_path")
            function_name = self._get_str(args, "functionName", "function_name", "function")
            target = self._get_str(args, "target")
            context_path = self._get_str(args, "contextPath", "context_path", "context")
            project_path = self._get_str(args, "projectPath", "project_path", "project")
            unit_name = self._get_str(args, "unitName", "unit_name", "unit")
            target_object_path = self._get_str(
                args,
                "targetObjectPath",
                "target_object_path",
                "targetPath",
                "target_path",
            )
            base_object_path = self._get_str(
                args,
                "baseObjectPath",
                "base_object_path",
                "basePath",
                "base_path",
            )
            symbol = self._get_str(args, "symbol", "functionSymbol", "function_symbol")
            objdiff_mode = self._get_str(args, "objdiffMode", "objdiff_mode") or "report"
            permuter_dir = self._get_str(args, "permuterDir", "permuter_dir", "permuterPath")
            permuter_script = self._get_str(args, "permuterScript", "permuter_script")
            jobs = self._get_int(args, "jobs")
            raw_extra = self._get_list(args, "extraArgs", "extra_args")
            extra_args = [str(item) for item in raw_extra] if raw_extra else None
            output_limit = self._get_int(args, "outputLimit", "output_limit", "limit", default=200) or 200
            timeout_ms = self._get_int(args, "timeout", default=120_000) or 120_000

            common_kwargs = {
                "assembly_path": assembly_path,
                "function_name": function_name,
                "target": target,
                "context_path": context_path,
                "project_path": project_path,
                "unit_name": unit_name,
                "target_object_path": target_object_path,
                "base_object_path": base_object_path,
                "symbol": symbol,
                "objdiff_mode": objdiff_mode,
                "permuter_dir": permuter_dir,
                "permuter_script": permuter_script,
                "jobs": jobs,
                "extra_args": extra_args,
                "output_limit": max(0, int(output_limit)),
                "timeout_ms": max(1000, int(timeout_ms)),
            }

            if tools:
                payload = build_decomp_match_bundle_payload(tools=tools, **common_kwargs)
            elif tool:
                payload = build_decomp_match_payload(tool=tool, **common_kwargs)
            else:
                raise ValueError("Either tool or tools is required for run-decomp-match.")
            return create_success_response(payload)
        except FileNotFoundError as exc:
            return create_error_response(exc)
        except ValueError as exc:
            return create_error_response(exc)
        except OSError as exc:
            return create_error_response(exc)
