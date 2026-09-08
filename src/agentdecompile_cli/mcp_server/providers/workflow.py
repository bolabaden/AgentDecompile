"""MCP access to the same durable workflow used by the workbench."""

from __future__ import annotations

import asyncio
from typing import Any

from mcp import types

from agentdecompile_cli.mcp_server.tool_providers import ToolProvider, create_error_response, create_success_response
from agentdecompile_cli.registry import Tool, get_effective_max_analysis_tier


class WorkflowToolProvider(ToolProvider):
    """Control configured workspace scheduling without opening a Ghidra program."""

    HANDLERS = {"manageworkflow": "_handle_workflow", "readworkspaceactivity": "_handle_snapshot"}

    def list_tools(self) -> list[types.Tool]:
        return [types.Tool(
            name=Tool.MANAGE_WORKFLOW.value,
            description=(
                "Read project/binary/function activity, export binary source ZIPs, or prepare, pause, resume, stop, and budget "
                "the shared automatic recovery workflow. Uses the server's configured corpus workspace "
                "and the same durable admissions as both dashboards. Does not require an open program. "
                "Completion is not byte verification; inspect proof receipts separately."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "operation": {"type": "string", "enum": ["snapshot", "prepare", "pause", "resume", "stop", "budget", "priority", "export-source", "export-status"]},
                    "locator": {"type": "string", "description": "Project locator. Required for prepare unless a registered binary slug is supplied. Snapshot retains workspace rollups and filters function detail."},
                    "slug": {"type": "string", "description": "Registered binary slug for preparation or snapshot function detail."},
                    "program": {"type": "string", "description": "Exact project program path for source export."},
                    "jobId": {"type": "string", "description": "Source export job ID to inspect with export-status."},
                    "preparationId": {"type": "string", "description": "Durable workflow ID returned by prepare or snapshot.preparations. Required for pause, resume, stop, and budget."},
                    "priority": {"type": "integer", "minimum": 0, "maximum": 100, "description": "Waiting project priority; higher values run first. Active operations are not interrupted."},
                    "seconds": {"type": ["integer", "null"], "minimum": 1, "maximum": 604800, "description": "Remaining wall-time allowance. Null removes the limit; finite seconds remain optional. This is not an ETA."},
                    "unlimited": {"type": "boolean", "description": "Set true with operation budget to remove the wall-time limit."},
                },
                "required": ["operation"],
            },
        ), types.Tool(
            name=Tool.READ_WORKSPACE_ACTIVITY.value,
            description=("Read the configured workspace's durable project, binary, and function activity, "
                         "progress, ETA evidence, and preparation IDs. Does not admit work or open a program."),
            inputSchema={
                "type": "object",
                "properties": {
                    "locator": {"type": "string", "description": "Project scope for function detail; workspace rollups remain visible."},
                    "slug": {"type": "string", "description": "Selected binary slug for function detail."},
                },
            },
        )]

    async def _handle_snapshot(self, args: dict[str, Any]) -> list[types.TextContent]:
        # Ignore any extra operation field: this capability can only read.
        return await self._handle_workflow({**args, "operation": "snapshot"})

    async def _handle_workflow(self, args: dict[str, Any]) -> list[types.TextContent]:
        try:
            from agentdecompile_recovery.corpus.dashboard import entity_activity, preparation

            operation = self._require_str(args, "operation", name="operation")
            if operation not in {"snapshot", "prepare", "pause", "resume", "stop", "budget", "priority", "export-source", "export-status"}:
                raise ValueError("Choose snapshot, prepare, pause, resume, stop, budget, priority, export-source, or export-status.")
            ceiling = get_effective_max_analysis_tier()
            if operation != "snapshot" and ceiling is not None and ceiling < 3:
                # Admission spawns durable work; caller policy cannot be dropped
                # by the manager's internal auto-prerequisite bypass.
                raise ValueError("Workflow controls require analysis tier 3.")
            locator = self._get_str(args, "locator")
            slug = self._get_str(args, "slug")
            if operation == "snapshot":
                payload = await asyncio.to_thread(entity_activity.snapshot, locator, slug)
                # Keep the scheduler IDs discoverable without admitting work.
                payload = {**payload, "preparations": await asyncio.to_thread(preparation.list_runs)}
            elif operation == "prepare":
                if not locator and not slug:
                    raise ValueError("Provide a project locator or registered binary slug.")
                payload = await asyncio.to_thread(preparation.submit, {"locator": locator, "slug": slug})
            elif operation in {"export-source", "export-status"}:
                from agentdecompile_recovery.corpus.dashboard.actions import jobs
                if operation == "export-source":
                    if not slug:
                        raise ValueError("Source export requires a registered binary slug.")
                    payload, status = await asyncio.to_thread(jobs.start_job, "workbench.export-source-zip", {
                        "slug": slug, "locator": locator, "program": self._get_str(args, "program"),
                    })
                    if status >= 400:
                        raise ValueError(payload.get("error") or "Source export was not admitted.")
                else:
                    job = jobs.get_job(self._require_str(args, "jobId", name="jobId"))
                    if job is None or job.action_id != "workbench.export-source-zip":
                        raise ValueError("Source export job not found.")
                    payload = {"job": job.to_dict()}
            else:
                run_id = self._require_str(args, "preparationId", name="preparationId")
                params: dict[str, Any] = {"preparation_id": run_id, "operation": operation}
                if operation == "priority":
                    priority = self._get(args, "priority")
                    if isinstance(priority, bool) or not isinstance(priority, int) or not 0 <= priority <= 100:
                        raise ValueError("Priority must be an integer from 0 to 100.")
                    params["priority"] = priority
                if operation == "budget":
                    missing = object()
                    seconds = self._get(args, "seconds", default=missing)
                    unlimited = self._get(args, 'unlimited') is True
                    if unlimited:
                        seconds = None
                    if seconds is missing:
                        raise ValueError('Supply seconds:null or unlimited:true to remove the limit, or a finite seconds value.')
                    if seconds is not None and (isinstance(seconds, bool) or not isinstance(seconds, int) or not 1 <= seconds <= 604800):
                        raise ValueError("Budget must be null for unlimited, or 1 to 604800 seconds.")
                    params["seconds"] = seconds
                payload = await asyncio.to_thread(preparation.control, params)
            return create_success_response(payload)
        except (ValueError, OSError, RuntimeError) as exc:
            return create_error_response(str(exc))
