"""First-class FastAPI / Swagger operations for every cataloged action."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, create_model

from agentdecompile_recovery.corpus.dashboard.actions.catalog import ActionSpec, list_actions
from agentdecompile_recovery.corpus.dashboard.actions.jobs import cancel_job, get_job, list_jobs, start_job

_KIND = {"str": str, "path": str, "int": int, "float": float, "bool": bool, "array": list[Any], "object": dict[str, Any]}
_META_KEYS = frozenset({"confirm", "dryRun", "dry_run", "context", "params"})


def _safe_ident(value: str) -> str:
    out = ["A"]
    for char in value:
        out.append(char if char.isalnum() else "_")
    return "".join(out)


def model_for(action: ActionSpec) -> type[BaseModel]:
    fields: dict[str, Any] = {}
    used: set[str] = {"confirm", "dry_run", "dryRun", "context"}
    for spec in action.fields:
        py = _KIND.get(spec.kind, str)
        alias = spec.name
        safe = alias.replace("-", "_").replace(".", "_")
        if safe in {"json", "schema", "model_config", "model_fields"}:
            safe = f"field_{safe}"
        if not safe or safe[0].isdigit():
            safe = f"f_{safe}"
        while safe in used:
            safe += "_"
        used.add(safe)
        default: Any
        if spec.required and not spec.from_context:
            default = ...
        elif spec.default not in (None, [], ()):
            default = spec.default
        else:
            default = None
        fields[safe] = (
            py | None,
            Field(default=default, alias=alias, description=spec.help or spec.name, json_schema_extra=spec.schema or {}),
        )
    fields["confirm"] = (bool, Field(default=False, description="Required for mutating or dangerous actions"))
    fields["dry_run"] = (bool, Field(default=False, alias="dryRun"))
    fields["context"] = (dict[str, Any] | None, Field(default=None))
    return create_model(
        _safe_ident(action.id),
        __config__=ConfigDict(populate_by_name=True, extra="forbid"),
        **fields,
    )


def create_actions_api_router() -> APIRouter:
    """Typed /api/v1/actions/* routes plus job aliases. Same runner as the dock."""
    router = APIRouter(tags=["actions"])

    @router.get("/api/v1/actions", summary="List every public CLI and MCP action")
    async def api_list_actions() -> JSONResponse:
        from agentdecompile_recovery.corpus.dashboard.actions.context import workbench_context

        return JSONResponse(
            {
                "ok": True,
                "actions": [item.to_dict() for item in list_actions()],
                "context": workbench_context(),
            }
        )

    @router.get("/api/v1/actions/{action_id}", summary="Describe one action")
    async def api_one_action(action_id: str) -> JSONResponse:
        from agentdecompile_recovery.corpus.dashboard.actions.catalog import action_by_id

        action = action_by_id(action_id)
        if action is None:
            return JSONResponse({"ok": False, "error": f"unknown action {action_id}"}, status_code=404)
        return JSONResponse({"ok": True, "action": action.to_dict()})

    @router.get("/api/v1/jobs", summary="List running and recent jobs")
    async def api_list_jobs() -> JSONResponse:
        rows = list_jobs()
        return JSONResponse({"ok": True, "jobs": [job.to_dict(include_log=False) for job in rows], "total": len(rows)})

    @router.get("/api/v1/jobs/{job_id}", summary="Job status and log")
    async def api_one_job(job_id: str) -> JSONResponse:
        job = get_job(job_id)
        if job is None:
            return JSONResponse({"ok": False, "error": f"unknown job {job_id}"}, status_code=404)
        return JSONResponse({"ok": True, "job": job.to_dict()})

    @router.post("/api/v1/jobs/{job_id}/cancel", summary="Cancel a queued or running job")
    async def api_cancel_job(job_id: str) -> JSONResponse:
        job = cancel_job(job_id)
        if job is None:
            return JSONResponse({"ok": False, "error": f"unknown job {job_id}"}, status_code=404)
        return JSONResponse({"ok": True, "job": job.to_dict()})

    for action in list_actions():
        _mount_action(router, action)
    return router


def _mount_action(router: APIRouter, action: ActionSpec) -> None:
    model_cls = model_for(action)
    group = action.group
    command = action.command or "one-shot"
    path = f"/api/v1/actions/{group}/{command}"

    async def handler(request: Request) -> JSONResponse:
        try:
            raw = await request.json()
        except Exception:
            raw = {}
        if raw in (None, ""):
            raw = {}
        if not isinstance(raw, dict):
            return JSONResponse({"error": "JSON object required"}, status_code=400)
        context = raw.get("context")
        if not isinstance(context, dict):
            context = {}
        params_only = {key: value for key, value in raw.items() if key not in _META_KEYS}
        nested = raw.get("params")
        if isinstance(nested, dict):
            params_only.update(nested)
        confirm = bool(raw.get("confirm"))
        dry = bool(raw.get("dryRun") or raw.get("dry_run"))
        payload, status = start_job(
            action.id,
            params_only,
            context=context,
            confirm=confirm,
            dry_run=dry,
        )
        return JSONResponse(payload, status_code=status)

    handler.__name__ = f"run_{_safe_ident(action.id)}"
    handler.__doc__ = action.summary or action.title
    router.add_api_route(
        path,
        handler,
        methods=["POST"],
        tags=[group],
        summary=action.title,
        description=action.summary or action.title,
        response_class=JSONResponse,
        openapi_extra={
            "operationId": action.id,
            "requestBody": {
                "required": True,
                "content": {
                    "application/json": {"schema": model_cls.model_json_schema(by_alias=True)},
                },
            },
        },
    )
