"""FastAPI router for the corpus dashboard. Does not bind a port."""

from __future__ import annotations

import mimetypes

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response

from agentdecompile_recovery.corpus.dashboard.pages import (
    CLAIM,
    PAGE_INDEX,
    SECTION_BY_ID,
    STATIC_ROOT,
    WORKSPACE_NAME,
    graph_to_function_target,
    is_partial_query,
    query_from_mapping,
    render_artifact,
    render_binary_page,
    render_database_evidence,
    render_function_page,
    render_functions_page,
    render_home,
    render_logical_page,
    render_page,
)

SECURITY_HEADERS = {
    "Cache-Control": "no-store, max-age=0",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    ),
}


def _html(body: str, status: int = 200, title: str | None = None) -> HTMLResponse:
    page = body if "<!doctype html>" in body[:80].lower() else render_page(body, title or WORKSPACE_NAME)
    response = HTMLResponse(page, status_code=status)
    for key, value in SECURITY_HEADERS.items():
        response.headers[key] = value
    return response


def _static(name: str) -> Response:
    if not name or "/" in name or "\\" in name or name.startswith("."):
        return PlainTextResponse("not found", status_code=404)
    target = STATIC_ROOT / name
    try:
        payload = target.read_bytes()
    except OSError:
        return PlainTextResponse("not found", status_code=404)
    ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
    if ctype.startswith("text/"):
        ctype = f"{ctype}; charset=utf-8"
    response = Response(content=payload, media_type=ctype)
    response.headers["Cache-Control"] = "public, max-age=60"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


def create_dashboard_router() -> APIRouter:
    """Routes under /dashboard. Compatibility aliases stay in unified_pages."""
    router = APIRouter(tags=["dashboard"])
    from agentdecompile_recovery.corpus.dashboard.actions.openapi import create_actions_api_router

    router.include_router(create_actions_api_router())

    @router.get("/dashboard", response_class=HTMLResponse)
    async def dashboard_home() -> HTMLResponse:
        from agentdecompile_recovery.corpus.dashboard.workbench import render_workbench

        response = HTMLResponse(render_workbench())
        for key, value in SECURITY_HEADERS.items():
            response.headers[key] = value
        return response

    @router.get("/dashboard/overview", response_class=HTMLResponse)
    async def dashboard_overview() -> HTMLResponse:
        return _html(render_home())

    @router.get("/dashboard/healthz")
    async def dashboard_healthz() -> JSONResponse:
        return JSONResponse(
            {"ok": True, "service": "dashboard", "pages": PAGE_INDEX, "claimBoundary": CLAIM}
        )

    def _browse_redirect(request: Request, fragment: str) -> RedirectResponse:
        qs = str(request.query_params)
        target = "/dashboard/functions"
        if qs:
            target += f"?{qs}"
        return RedirectResponse(f"{target}#{fragment}", status_code=302)

    @router.get("/dashboard/functions", response_class=HTMLResponse)
    async def dashboard_functions(request: Request) -> HTMLResponse:
        query = query_from_mapping(request.query_params)
        body, status = render_functions_page(query)
        if is_partial_query(query):
            response = HTMLResponse(body, status_code=status)
            for key, value in SECURITY_HEADERS.items():
                response.headers[key] = value
            return response
        return _html(body, status, f"Functions — {WORKSPACE_NAME}")

    @router.get("/dashboard/function/{slug}/{addr}", response_class=HTMLResponse)
    async def dashboard_function(slug: str, addr: str, request: Request) -> HTMLResponse:
        body, status = render_function_page(slug, addr, query_from_mapping(request.query_params))
        return _html(body, status, f"Function — {WORKSPACE_NAME}")

    @router.get("/dashboard/function-open")
    async def dashboard_function_open(request: Request) -> RedirectResponse:
        return RedirectResponse(graph_to_function_target(query_from_mapping(request.query_params)), status_code=302)

    @router.get("/dashboard/api/workbench/binaries")
    async def workbench_binaries() -> JSONResponse:
        from agentdecompile_recovery.corpus.dashboard.workbench import list_binaries

        payload = list_binaries()
        return JSONResponse(payload, status_code=200 if payload.get("ok") else 400)

    @router.post("/dashboard/api/workbench/binaries")
    async def workbench_add_binary(request: Request) -> JSONResponse:
        from agentdecompile_recovery.corpus.dashboard.workbench import (
            register_path_binary,
            save_upload_binary,
        )

        content_type = request.headers.get("content-type") or ""
        if "multipart/form-data" in content_type:
            form = await request.form()
            upload = form.get("file")
            if upload is None or not hasattr(upload, "read"):
                return JSONResponse({"ok": False, "error": "file is required"}, status_code=400)
            data = await upload.read()
            payload = save_upload_binary(
                getattr(upload, "filename", None) or "",
                data,
                slug=str(form.get("slug") or ""),
                role=str(form.get("role") or "member"),
                label=str(form.get("label") or ""),
            )
        else:
            body = await request.json()
            payload = register_path_binary(
                str(body.get("path") or ""),
                slug=str(body.get("slug") or ""),
                role=str(body.get("role") or "member"),
                label=str(body.get("label") or ""),
            )
        return JSONResponse(payload, status_code=200 if payload.get("ok") else 400)

    @router.delete("/dashboard/api/workbench/binaries/{slug}")
    async def workbench_remove_binary(slug: str, request: Request) -> JSONResponse:
        from agentdecompile_recovery.corpus.dashboard.workbench import remove_registered_binary

        body: dict = {}
        try:
            body = await request.json()
        except Exception:
            body = {}
        payload = remove_registered_binary(slug, confirm=bool(body.get("confirm")))
        return JSONResponse(payload, status_code=200 if payload.get("ok") else 400)

    @router.patch("/dashboard/api/workbench/binaries/{slug}")
    async def workbench_edit_binary(slug: str, request: Request) -> JSONResponse:
        from agentdecompile_recovery.corpus.dashboard.workbench import update_registered_binary

        body = await request.json()
        payload = update_registered_binary(
            slug,
            role=body.get("role"),
            label=body.get("label"),
        )
        return JSONResponse(payload, status_code=200 if payload.get("ok") else 400)

    @router.get("/dashboard/api/workbench/functions")
    async def workbench_functions(request: Request) -> JSONResponse:
        from agentdecompile_recovery.corpus.dashboard.workbench import list_functions

        payload = list_functions(
            request.query_params.get("slug") or request.query_params.get("binary") or "",
            q=request.query_params.get("q") or "",
            offset=int(request.query_params.get("offset") or 0),
            limit=int(request.query_params.get("limit") or 80),
        )
        return JSONResponse(payload, status_code=200 if payload.get("ok") else 400)

    @router.get("/dashboard/api/workbench/function")
    async def workbench_function(request: Request) -> JSONResponse:
        from agentdecompile_recovery.corpus.dashboard.workbench import function_detail

        payload = function_detail(
            request.query_params.get("slug") or request.query_params.get("binary") or "",
            request.query_params.get("addr") or "",
        )
        return JSONResponse(payload, status_code=200 if payload.get("ok") else 400)

    @router.get("/dashboard/api/function-choices")
    async def dashboard_function_choices(request: Request) -> JSONResponse:
        from agentdecompile_recovery.corpus.dashboard.function_choices import list_function_choices

        payload = list_function_choices(
            request.query_params.get("binary") or request.query_params.get("slug") or "",
            q=request.query_params.get("q") or "",
            around=request.query_params.get("around") or request.query_params.get("addr"),
            limit=request.query_params.get("limit") or 80,
        )
        return JSONResponse(payload, status_code=200 if payload.get("ok") else 400)

    @router.get("/dashboard/logical/{logical_id}", response_class=HTMLResponse)
    async def dashboard_logical_one(logical_id: str) -> HTMLResponse:
        body, status = render_logical_page(logical_id)
        return _html(body, status, f"Logical function — {WORKSPACE_NAME}")

    @router.get("/dashboard/binary/{slug}", response_class=HTMLResponse)
    async def dashboard_binary(slug: str) -> HTMLResponse:
        body, status = render_binary_page(slug)
        return _html(body, status, f"{slug} — {WORKSPACE_NAME}")

    @router.get("/dashboard/graph")
    async def dashboard_graph(request: Request) -> RedirectResponse:
        return RedirectResponse(graph_to_function_target(query_from_mapping(request.query_params)), status_code=302)

    @router.get("/dashboard/artifact", response_class=HTMLResponse)
    async def dashboard_artifact(request: Request) -> HTMLResponse:
        body, status = render_artifact(query_from_mapping(request.query_params))
        return _html(body, status, "Artifact")

    @router.get("/dashboard/builds")
    async def dashboard_builds() -> RedirectResponse:
        return RedirectResponse("/dashboard/functions#builds", status_code=302)

    @router.get("/dashboard/operations")
    async def dashboard_operations() -> RedirectResponse:
        return RedirectResponse("/dashboard#operations", status_code=302)

    @router.get("/dashboard/review")
    async def dashboard_review_redirect(request: Request) -> RedirectResponse:
        return _browse_redirect(request, "review")

    @router.get("/dashboard/actions")
    async def dashboard_actions_redirect() -> RedirectResponse:
        return RedirectResponse("/dashboard#run", status_code=302)

    @router.get("/dashboard/report")
    async def dashboard_report_redirect() -> RedirectResponse:
        return RedirectResponse("/dashboard#recovery", status_code=302)

    @router.get("/dashboard/logical")
    async def dashboard_logical_redirect() -> RedirectResponse:
        return RedirectResponse("/dashboard/functions#logical", status_code=302)

    @router.get("/dashboard/api/actions")
    async def dashboard_api_actions(request: Request) -> JSONResponse:
        from agentdecompile_recovery.corpus.dashboard.actions.catalog import list_actions
        from agentdecompile_recovery.corpus.dashboard.actions.context import workbench_context

        page = (request.query_params.get("page") or "").strip()
        actions = list_actions()
        if page and page not in {"home", "work"}:
            actions = [item for item in actions if page in item.pages]
        return JSONResponse(
            {
                "ok": True,
                "actions": [item.to_dict() for item in actions],
                "context": workbench_context(),
            }
        )

    @router.get("/dashboard/api/actions/{action_id}")
    async def dashboard_api_action(action_id: str) -> JSONResponse:
        from agentdecompile_recovery.corpus.dashboard.actions.catalog import action_by_id

        action = action_by_id(action_id)
        if action is None:
            return JSONResponse({"error": f"unknown action {action_id}"}, status_code=404)
        return JSONResponse({"ok": True, "action": action.to_dict()})

    @router.get("/dashboard/api/jobs")
    async def dashboard_api_jobs() -> JSONResponse:
        from agentdecompile_recovery.corpus.dashboard.actions.jobs import list_jobs

        return JSONResponse({"ok": True, "jobs": [job.to_dict(include_log=False) for job in list_jobs()]})

    @router.get("/dashboard/api/jobs/{job_id}")
    async def dashboard_api_job(job_id: str) -> JSONResponse:
        from agentdecompile_recovery.corpus.dashboard.actions.jobs import get_job

        job = get_job(job_id)
        if job is None:
            return JSONResponse({"error": f"unknown job {job_id}"}, status_code=404)
        return JSONResponse({"ok": True, "job": job.to_dict()})

    @router.post("/dashboard/api/jobs")
    async def dashboard_api_start_job(request: Request) -> JSONResponse:
        from agentdecompile_recovery.corpus.dashboard.actions.jobs import start_job

        try:
            body = await request.json()
        except Exception:
            body = {}
        if not isinstance(body, dict):
            return JSONResponse({"error": "JSON object required"}, status_code=400)
        payload, status = start_job(
            str(body.get("action") or body.get("actionId") or ""),
            body.get("params") if isinstance(body.get("params"), dict) else {},
            context=body.get("context") if isinstance(body.get("context"), dict) else {},
            confirm=bool(body.get("confirm")),
            dry_run=bool(body.get("dryRun") or body.get("dry_run")),
        )
        return JSONResponse(payload, status_code=status)

    @router.post("/dashboard/api/jobs/{job_id}/cancel")
    async def dashboard_api_cancel_job(job_id: str) -> JSONResponse:
        from agentdecompile_recovery.corpus.dashboard.actions.jobs import cancel_job

        job = cancel_job(job_id)
        if job is None:
            return JSONResponse({"error": f"unknown job {job_id}"}, status_code=404)
        return JSONResponse({"ok": True, "job": job.to_dict()})

    @router.get("/dashboard/evidence/database", response_class=HTMLResponse)
    async def dashboard_database_evidence() -> HTMLResponse:
        body, status = render_database_evidence()
        return _html(body, status, f"Database evidence — {WORKSPACE_NAME}")

    @router.get("/dashboard/fragment", response_class=HTMLResponse)
    async def dashboard_fragment() -> HTMLResponse:
        from agentdecompile_recovery.corpus.dashboard.pages import render_body
        return _html(render_body())

    @router.get("/dashboard/panel", response_class=HTMLResponse)
    async def dashboard_panel(request: Request) -> HTMLResponse:
        from agentdecompile_recovery.corpus.dashboard.pages import section_body_async

        sid = request.query_params.get("id") or ""
        section = SECTION_BY_ID.get(sid)
        if section is None:
            return HTMLResponse('<p class="miss">no such panel</p>', status_code=404)
        html, pending = section_body_async(section)
        return HTMLResponse(f'<div data-pending="{1 if pending else 0}">{html}</div>')

    @router.get("/dashboard/static/{name}")
    async def dashboard_static(name: str) -> Response:
        return _static(name)

    return router
