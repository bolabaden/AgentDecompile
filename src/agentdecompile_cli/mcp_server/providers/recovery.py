"""Curated recovery MCP tools — reconstruct / status / claim-report.

Tier 0 surface: no open Ghidra program required. Keep this provider to the three
default recovery tools; do not expand into vacuum/acquisition peer tools here.
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


class RecoveryToolProvider(ToolProvider):
    """Provider for curated recovery orchestration tools."""

    HANDLERS = {
        "reconstruct": "_handle_reconstruct",
        "status": "_handle_status",
        "claimreport": "_handle_claim_report",
    }

    def list_tools(self) -> list[types.Tool]:
        logger.debug("diag.enter %s", "mcp_server/providers/recovery.py:RecoveryToolProvider.list_tools")
        return [
            types.Tool(
                name=Tool.RECONSTRUCT.value,
                description=(
                    "One-shot AgentDecompile reconstruct: optional context acquisition plus recovery "
                    "orchestration for a binary/folder. Returns terminal status and claim-report "
                    "boundaries; does not claim semantic parity without objdiff proof. "
                    "Does not require an open Ghidra program. Prefer stopAfter for bounded smoke runs."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "binaryPath": {
                            "type": "string",
                            "description": "Binary, archive, installer, or app directory to recover.",
                        },
                        "workDir": {
                            "type": "string",
                            "description": "Optional reconstruct work directory.",
                        },
                        "preferredName": {
                            "type": "string",
                            "description": "Preferred executable basename when input is a folder.",
                        },
                        "contextPaths": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional context files/directories (notes, dumps, partial source).",
                        },
                        "contextPack": {
                            "type": "string",
                            "description": "Previously generated context-pack or acquisition-bundle directory.",
                        },
                        "acquisitionBundle": {
                            "type": "string",
                            "description": "Explicit acquisition-bundle directory.",
                        },
                        "stopAfter": {
                            "type": "string",
                            "description": "Stop after a named reconstruct stage (bounded runs).",
                        },
                        "autonomous": {
                            "type": "boolean",
                            "description": "Enable bounded vacuum/repair autonomy after core stages (default false).",
                        },
                        "force": {
                            "type": "boolean",
                            "description": "Rerun selected stages even when receipts exist.",
                        },
                        "resume": {
                            "type": "boolean",
                            "description": "Reuse complete stage receipts when true (default true).",
                        },
                    },
                    "required": ["binaryPath"],
                },
            ),
            types.Tool(
                name=Tool.STATUS.value,
                description=(
                    "Recovery run status for a reconstruct/recover work directory: terminal state, "
                    "stage, verified/advisory counts, and claim-report presence. "
                    "Orchestration progress only — not semantic parity. Distinct from checkout-status."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "workDir": {
                            "type": "string",
                            "description": "Reconstruct/recover work directory to inspect.",
                        },
                    },
                    "required": ["workDir"],
                },
            ),
            types.Tool(
                name=Tool.CLAIM_REPORT.value,
                description=(
                    "Emit an honest claim-report for a reconstruct/recover work directory. "
                    "Separates objdiff-verified-semantic from advisory/byte-authority/context-hint. "
                    "Optionally write claim-report.json into the work directory."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "workDir": {
                            "type": "string",
                            "description": "Reconstruct/recover work directory.",
                        },
                        "terminalStatus": {
                            "type": "string",
                            "description": "Optional terminal status override (matched/partial/failed/blocked:toolchain).",
                        },
                        "write": {
                            "type": "boolean",
                            "description": "When true, write claim-report.json into workDir (default false).",
                        },
                    },
                    "required": ["workDir"],
                },
            ),
        ]

    async def _handle_reconstruct(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/recovery.py:RecoveryToolProvider._handle_reconstruct")
        try:
            from agentdecompile_recovery.frontdoor import run_reconstruct_job

            binary_path = self._require_str(args, "binaryPath", "binary_path", "input", "path", name="binaryPath")
            work_dir = self._get_str(args, "workDir", "work_dir")
            preferred_name = self._get_str(args, "preferredName", "preferred_name")
            raw_context = self._get_list(args, "contextPaths", "context_paths", "context")
            context_paths = [Path(str(item)) for item in raw_context] if raw_context else None
            context_pack = self._get_str(args, "contextPack", "context_pack")
            acquisition_bundle = self._get_str(args, "acquisitionBundle", "acquisition_bundle")
            stop_after = self._get_str(args, "stopAfter", "stop_after")
            autonomous = self._get_bool(args, "autonomous", default=False)
            force = self._get_bool(args, "force", default=False)
            resume = self._get_bool(args, "resume", default=True)

            payload = run_reconstruct_job(
                Path(binary_path),
                work_dir=Path(work_dir) if work_dir else None,
                preferred_name=preferred_name or None,
                context=context_paths,
                context_pack=Path(context_pack) if context_pack else None,
                acquisition_bundle=Path(acquisition_bundle) if acquisition_bundle else None,
                stop_after=stop_after or None,
                autonomous=bool(autonomous),
                force=bool(force),
                resume=bool(resume),
            )
            return create_success_response(payload)
        except FileNotFoundError as exc:
            return create_error_response(exc)
        except ValueError as exc:
            return create_error_response(exc)
        except OSError as exc:
            return create_error_response(exc)

    async def _handle_status(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/recovery.py:RecoveryToolProvider._handle_status")
        try:
            from agentdecompile_recovery.recovery_status import build_recovery_status

            work_dir = self._require_str(args, "workDir", "work_dir", "path", name="workDir")
            path = Path(work_dir)
            if not path.exists():
                raise FileNotFoundError(f"workDir not found: {path}")
            payload = build_recovery_status(path)
            payload["tool"] = Tool.STATUS.value
            return create_success_response(payload)
        except FileNotFoundError as exc:
            return create_error_response(exc)
        except ValueError as exc:
            return create_error_response(exc)
        except OSError as exc:
            return create_error_response(exc)

    async def _handle_claim_report(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/recovery.py:RecoveryToolProvider._handle_claim_report")
        try:
            from agentdecompile_recovery.claim_report import build_claim_report, write_claim_report

            work_dir = self._require_str(args, "workDir", "work_dir", "path", name="workDir")
            terminal_status = self._get_str(args, "terminalStatus", "terminal_status", "status") or "partial"
            write = self._get_bool(args, "write", default=False)
            path = Path(work_dir)
            if not path.exists():
                raise FileNotFoundError(f"workDir not found: {path}")
            if write:
                out = write_claim_report(path, terminal_status=terminal_status)
                report = build_claim_report(work_dir=path, terminal_status=terminal_status)
                payload = {"tool": Tool.CLAIM_REPORT.value, "written": str(out), **report}
            else:
                report = build_claim_report(work_dir=path, terminal_status=terminal_status)
                payload = {"tool": Tool.CLAIM_REPORT.value, **report}
            return create_success_response(payload)
        except FileNotFoundError as exc:
            return create_error_response(exc)
        except ValueError as exc:
            return create_error_response(exc)
        except OSError as exc:
            return create_error_response(exc)
