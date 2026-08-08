"""Tier-0 MCP tools for dismantling and acquisition context (VISION substrate).

Independent of reconstruct/status/claim-report. No open Ghidra program required.
"""

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
from agentdecompile_cli.registry import Tool

logger = logging.getLogger(__name__)

_EXPORT_CLAIM = (
    "export-context produces navigable layout/context trees and LLM indexes; "
    "advisory evidence only — not recovered source and not objdiff proof."
)
_ACQUISITION_CLAIM = (
    "acquisition-query returns advisory acquisition-bundle evidence only; "
    "compile and objdiff gates remain required for verified claims."
)


class ContextSubstrateToolProvider(ToolProvider):
    """Provider for export-context and acquisition-query."""

    HANDLERS = {
        "exportcontext": "_handle_export_context",
        "acquisitionquery": "_handle_acquisition_query",
    }

    def list_tools(self) -> list[types.Tool]:
        logger.debug(
            "diag.enter %s",
            "mcp_server/providers/context_substrate.py:ContextSubstrateToolProvider.list_tools",
        )
        return [
            types.Tool(
                name=Tool.EXPORT_CONTEXT.value,
                description=(
                    "Dismantle an app, installer, archive, or binary tree into navigable "
                    "context files (tree.json, TREE.md, LLM_CONTEXT.*, extracted/). "
                    "Does not require an open Ghidra program. Advisory layout context only — "
                    "not recovered source and not objdiff proof. Prefer conservative maxFiles "
                    "for large installers."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "inputPath": {
                            "type": "string",
                            "description": "File or folder to export (binary, archive, installer, or app tree).",
                        },
                        "outDir": {
                            "type": "string",
                            "description": "Output directory for manifest, tree, and per-file surrogates.",
                        },
                        "format": {
                            "type": "string",
                            "enum": ["json", "md"],
                            "description": "Per-file surrogate format (default json).",
                        },
                        "binaryAnalysis": {
                            "type": "string",
                            "enum": ["light", "standard", "deep"],
                            "description": "Binary analysis depth (default light for MCP responsiveness).",
                        },
                        "extractContainers": {
                            "type": "boolean",
                            "description": "Recursively extract archives/installers with 7z when available (default true).",
                        },
                        "includeLowSignalMembers": {
                            "type": "boolean",
                            "description": "Also export low-signal members such as cursor/icon resources (default false).",
                        },
                        "maxFiles": {
                            "type": "integer",
                            "description": "Maximum files to visit (default 250 on MCP).",
                        },
                        "maxDepth": {
                            "type": "integer",
                            "description": "Maximum recursive container extraction depth (default 3).",
                        },
                    },
                    "required": ["inputPath", "outDir"],
                },
            ),
            types.Tool(
                name=Tool.ACQUISITION_QUERY.value,
                description=(
                    "Read-only query against a registered or explicit acquisition bundle: "
                    "inspect, search-everything, get-function, get-global, get-type, get-xrefs. "
                    "Returns address-keyed advisory evidence and conflicts. "
                    "Does not require an open Ghidra program. Not verification."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "bundleDir": {
                            "type": "string",
                            "description": "Explicit acquisition-bundle directory. Omit to resolve latest registered bundle.",
                        },
                        "action": {
                            "type": "string",
                            "enum": [
                                "inspect",
                                "search-everything",
                                "get-function",
                                "get-global",
                                "get-type",
                                "get-xrefs",
                            ],
                            "description": "Query action (default inspect).",
                        },
                        "query": {
                            "type": "string",
                            "description": "Optional text query for search/get actions.",
                        },
                        "address": {
                            "type": "string",
                            "description": "Optional address (decimal or 0x-hex) to filter entities.",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum results (default 25).",
                        },
                    },
                    "required": [],
                },
            ),
        ]

    async def _handle_export_context(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug(
            "diag.enter %s",
            "mcp_server/providers/context_substrate.py:ContextSubstrateToolProvider._handle_export_context",
        )
        try:
            from agentdecompile_recovery.context_export import ExportConfig, export_context

            input_path = self._require_str(
                args, "inputPath", "input_path", "input", "path", name="inputPath"
            )
            out_dir = self._require_str(args, "outDir", "out_dir", "output", name="outDir")
            output_format = self._get_str(args, "format", "outputFormat", "output_format") or "json"
            binary_analysis = (
                self._get_str(args, "binaryAnalysis", "binary_analysis") or "light"
            )
            extract_containers = self._get_bool(args, "extractContainers", "extract_containers", default=True)
            include_low = self._get_bool(
                args, "includeLowSignalMembers", "include_low_signal_members", default=False
            )
            max_files = self._get_int(args, "maxFiles", "max_files", default=250)
            max_depth = self._get_int(args, "maxDepth", "max_depth", default=3)

            src = Path(input_path)
            if not src.exists():
                raise FileNotFoundError(f"inputPath not found: {src}")

            manifest = export_context(
                ExportConfig(
                    input_path=src,
                    out_dir=Path(out_dir),
                    output_format=output_format,
                    binary_analysis=binary_analysis,
                    extract_containers=bool(extract_containers),
                    include_low_signal_members=bool(include_low),
                    max_files=int(max_files) if max_files is not None else 250,
                    max_depth=int(max_depth) if max_depth is not None else 3,
                )
            )
            payload = {
                "tool": Tool.EXPORT_CONTEXT.value,
                "claimBoundary": _EXPORT_CLAIM,
                **manifest,
            }
            return create_success_response(payload)
        except FileNotFoundError as exc:
            return create_error_response(exc)
        except ValueError as exc:
            return create_error_response(exc)
        except OSError as exc:
            return create_error_response(exc)

    async def _handle_acquisition_query(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug(
            "diag.enter %s",
            "mcp_server/providers/context_substrate.py:ContextSubstrateToolProvider._handle_acquisition_query",
        )
        try:
            from agentdecompile_recovery import acquisition_registry
            from agentdecompile_recovery.acquisition_mcp import query_bundle

            bundle_dir = self._get_str(args, "bundleDir", "bundle_dir", "bundle")
            action = self._get_str(args, "action") or "inspect"
            query = self._get_str(args, "query")
            address_raw = self._get_str(args, "address")
            limit = self._get_int(args, "limit", default=25)

            address: int | None = None
            if address_raw:
                address = int(address_raw, 0)

            explicit = Path(bundle_dir) if bundle_dir else None
            if explicit is not None and not explicit.exists():
                raise FileNotFoundError(f"bundleDir not found: {explicit}")

            bundle = acquisition_registry.resolve_bundle(explicit=explicit, allow_latest=True)
            if bundle is None:
                raise FileNotFoundError(
                    "no acquisition bundle found; run acquire/reconstruct with context first "
                    "or pass bundleDir"
                )

            result = query_bundle(
                bundle,
                action=action,
                query=query,
                address=address,
                limit=int(limit) if limit is not None else 25,
            )
            payload = {
                "tool": Tool.ACQUISITION_QUERY.value,
                "bundleDir": str(bundle),
                "claimBoundary": result.get("claimBoundary") or _ACQUISITION_CLAIM,
                **result,
            }
            return create_success_response(payload)
        except FileNotFoundError as exc:
            return create_error_response(exc)
        except ValueError as exc:
            return create_error_response(exc)
        except OSError as exc:
            return create_error_response(exc)
