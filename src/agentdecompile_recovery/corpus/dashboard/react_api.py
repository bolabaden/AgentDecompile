"""React delivery and browser-independent, receipt-backed batch admission."""

from __future__ import annotations

import asyncio
import copy
from contextlib import contextmanager
import hashlib
import json
import os
import socket
import threading
import time
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, JSONResponse

from agentdecompile_recovery.corpus.dashboard.actions import jobs
from agentdecompile_recovery.corpus.dashboard.actions.catalog import action_by_id
from agentdecompile_recovery.corpus.dashboard.common import live_root

ASSETS = Path(__file__).parent / "static" / "react"
_LOCK = threading.RLock()
_ACTIVE: set[str] = set()
_CHAINING: set[str] = set()


def _root() -> Path:
    root = live_root()
    if root is None:
        raise ValueError("Configure a work directory before submitting a batch.")
    path = root / "workbench-batches"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _write(path: Path, data: dict) -> None:
    temp = path.with_name(path.name + f".{os.getpid()}.{threading.get_ident()}.tmp")
    temp.write_text(json.dumps(data), encoding="utf-8")
    temp.replace(path)


@contextmanager
def _batch_lease(path: Path, purpose: str, *, wait: bool = False):
    """Serialize receipt admission/continuation across HTTP server processes."""
    from .preparation import _lock_lease
    handle = path.with_suffix(f".{purpose}.lock").open("a+")
    acquired = False
    deadline = time.monotonic() + 5
    try:
        while True:
            try:
                _lock_lease(handle)
                acquired = True
                break
            except BlockingIOError:
                if not wait or time.monotonic() >= deadline:
                    break
                time.sleep(.01)
        yield acquired
    finally:
        handle.close()


def _cancel_requested(path: Path) -> bool:
    return path.with_suffix(".cancel").is_file()


def _load(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data["id"] not in _ACTIVE and data["status"] in {"queued", "running"}:
        from .preparation import _owner_alive
        # Another server reading the same workspace is not evidence of interruption.
        if data.get("ownerPid") and not _owner_alive(data):
            if data.get("action") == "mcp.import-binary":
                data["recoveryPending"] = True
                threading.Thread(target=_run, args=(path,), daemon=True).start()
            else:
                data.update(ownerUnavailable=True, status="blocked", error="The owning process stopped. Reconcile the accepted operation before submitting it again.")
    if data.get("prepareAfterImport") and data.get("preparations") is None and data["status"] in {"finished", "partial"}:
        threading.Thread(target=_continue_imports, args=(path,), daemon=True).start()
    if _cancel_requested(path) and data["status"] in {"queued", "running", "cancelling"}:
        data["status"] = "cancelling"
        data["cancellationRequested"] = True
    return data



def _continue_imports(path: Path) -> None:
    with _batch_lease(path, "continuation") as acquired:
        if acquired:
            _continue_imports_owned(path)


def _continue_imports_owned(path: Path) -> None:
    with _LOCK:
        batch = json.loads(path.read_text())
        if not batch.get("prepareAfterImport") or batch.get("preparations") is not None or batch["status"] not in {"finished", "partial"} or path.stem in _CHAINING:
            return
        _CHAINING.add(path.stem)
    try:
        from .preparation import inventory_changed
        locators = sorted({item["context"].get("locator", "") for item in batch["results"] if item["status"] == "ok"})
        preparations = []
        for locator in locators:
            if not locator:
                continue
            try:
                if _cancel_requested(path):
                    raise ValueError("Preparation continuation cancelled.")
                # Durable import generations coalesce with an active project
                # wave and survive browser/server disconnects. They preserve
                # the project's original deadline rather than starting a retry.
                run = inventory_changed(locator)
                preparations.append({"locator": locator, "id": run["id"], "status": run["status"]})
            except Exception as exc:
                preparations.append({"locator": locator, "status": "blocked", "error": str(exc)})
        with _LOCK:
            batch = json.loads(path.read_text())
            batch["preparations"] = preparations
            batch["preparationContinuation"] = {"status": "submitted" if all(item["status"] != "blocked" for item in preparations) else "blocked"}
            _write(path, batch)
    finally:
        with _LOCK:
            _CHAINING.discard(path.stem)


def _run(path: Path) -> None:
    from .preparation import _lock_lease, _process_start, _owner_alive
    lease = path.with_suffix(".lock").open("a+")
    try:
        try:
            _lock_lease(lease)
        except BlockingIOError:
            return
        with _LOCK:
            batch = json.loads(path.read_text())
            if batch["status"] not in {"queued", "running"}:
                return
            if batch["status"] == "running" and batch.get("ownerPid") and _owner_alive(batch):
                return
            batch.update(status="queued", ownerPid=os.getpid(), ownerHost=socket.gethostname(), ownerStart=_process_start(os.getpid()))
            _write(path, batch)
            _ACTIVE.add(path.stem)
        _run_owned(path)
    finally:
        lease.close()


def _run_owned(path: Path) -> None:
    try:
        with _LOCK:
            batch = json.loads(path.read_text())
            if batch["status"] != "queued":
                return
            batch["status"] = "running"
            _write(path, batch)
        for index in range(len(batch["results"])):
            with _LOCK:
                batch = json.loads(path.read_text())
                if _cancel_requested(path) or batch["status"] == "cancelled":
                    batch["status"] = "cancelled"
                    for pending in batch["results"]:
                        if pending["status"] == "queued":
                            pending["status"] = "cancelled"
                    _write(path, batch)
                    break
                row = batch["results"][index]
                if row["status"] in {"ok", "failed", "blocked", "cancelled", "budget-stop"}:
                    continue
                if batch.get('deadline') is not None and time.time() > batch['deadline']:
                    batch["status"] = "budget-stop"
                    _write(path, batch)
                    break
                payload, status = jobs.start_job(batch["action"], row["params"], context=row["context"], confirm=batch["confirm"])
                if status >= 400:
                    row.update(status="failed", error=payload.get("error", "Submission failed"))
                    _write(path, batch)
                    continue
                row.update(status="running", jobId=payload["job"]["id"])
                _write(path, batch)
            while True:
                job = jobs.get_job(row["jobId"])
                with _LOCK:
                    batch = json.loads(path.read_text())
                    cancelled = _cancel_requested(path) or batch["status"] == "cancelled"
                    stop = cancelled or (batch.get('deadline') is not None and time.time() > batch['deadline'])
                if stop:
                    jobs.cancel_job(row["jobId"])
                    # Keep ownership until native work has actually drained.
                    while job is not None and job.status in {"queued", "running", "cancelling"}:
                        time.sleep(.25)
                        job = jobs.get_job(row["jobId"])
                    with _LOCK:
                        batch = json.loads(path.read_text())
                        terminal = "cancelled" if cancelled else "budget-stop"
                        batch["results"][index].update(status=terminal, result=job.to_dict() if job else {})
                        batch["status"] = terminal
                        for pending in batch["results"]:
                            if pending["status"] == "queued":
                                pending["status"] = terminal
                        _write(path, batch)
                    break
                if job is None or job.status not in {"queued", "running", "cancelling"}:
                    with _LOCK:
                        batch = json.loads(path.read_text())
                        batch["results"][index].update(status=job.status if job else "interrupted", result=job.to_dict() if job else {})
                        _write(path, batch)
                    break
                time.sleep(0.25)
        with _LOCK:
            batch = json.loads(path.read_text())
            if batch["status"] == "running":
                batch["status"] = "finished" if all(r["status"] == "ok" for r in batch["results"]) else "partial"
            batch["finishedAt"] = time.time()
            _write(path, batch)
        _continue_imports(path)
    except Exception as exc:
        with _LOCK:
            batch = json.loads(path.read_text())
            batch.update(status="failed", error=str(exc))
            _write(path, batch)
    finally:
        with _LOCK:
            _ACTIVE.discard(path.stem)


def submit_batch(body: dict) -> tuple[dict, int]:
    targets = body.get("targets")
    if not isinstance(targets, list) or not 1 <= len(targets) <= 1000 or any(not isinstance(t, dict) for t in targets):
        return {"error": "Provide between 1 and 1000 target contexts."}, 400
    key = body.get("key")
    if not isinstance(key, str) or not 1 <= len(key) <= 128:
        return {"error": "A submission key is required."}, 400
    action = str(body.get("action") or "")
    params = body.get("params") or {}
    if not isinstance(params, dict):
        return {"error": "params must be an object"}, 400
    frozen = []
    for target in targets:
        overrides = target.get("params", {})
        if not isinstance(overrides, dict):
            return {"error": "Each target's params must be an object."}, 400
        # Import batches need distinct source paths and names; retries retain
        # these validated parameters just like per-function operations.
        merged = {**params, **overrides}
        # A batch binds each function explicitly, independent of the active UI row.
        for field in ("addr", "program", "slug", "locator"):
            if target.get(field):
                merged[field] = target[field]
        spec = action_by_id(action)
        if spec is not None:
            for field in spec.fields:
                if field.from_context in {"addr", "program", "slug"}:
                    value = target.get(field.from_context)
                    if field.from_context == "program":
                        value = value or target.get("slug")
                    if value:
                        merged[field.name] = value
        payload, status = jobs.start_job(action, merged, context=target, confirm=body.get("confirm") is True, dry_run=True)
        if status >= 400:
            return payload, status
        frozen.append({"context": copy.deepcopy(target), "params": payload["params"], "status": "queued"})
    if body.get("dryRun"):
        return {"ok": True, "dryRun": True, "results": frozen}, 200
    budget = body.get('budgetSeconds')
    if budget is not None and (isinstance(budget, bool) or not isinstance(budget, int) or not 1 <= budget <= 604800):
        return {'error': 'budgetSeconds must be null for unlimited, or 1 to 604800 seconds.'}, 400
    fingerprint = hashlib.sha256(json.dumps([action, frozen], sort_keys=True).encode()).hexdigest()
    batch_id = hashlib.sha256(key.encode()).hexdigest()[:32]
    path = _root() / f"{batch_id}.json"
    with _batch_lease(path, "admission", wait=True) as acquired:
        if not acquired:
            return {"error": "Another server is recording this submission; repeat with the same key."}, 503
        with _LOCK:
            if path.exists():
                existing = _load(path)
                if existing["fingerprint"] != fingerprint:
                    return {"error": "Submission key already belongs to different work."}, 409
                return {"ok": True, "batch": existing}, 200
            from .preparation import _process_start
            batch = {"id": batch_id, "ownerPid": os.getpid(), "ownerHost": socket.gethostname(), "ownerStart": _process_start(os.getpid()), "prepareAfterImport": action == "mcp.import-binary", "action": action, "fingerprint": fingerprint, "confirm": body.get("confirm") is True, "createdAt": time.time(), "budgetSeconds": budget, "deadline": time.time() + budget if budget is not None else None, "status": "queued", "results": frozen}
            _write(path, batch)
            threading.Thread(target=_run, args=(path,), daemon=True).start()
    return {"ok": True, "batch": batch}, 202


def create_react_router() -> APIRouter:
    router = APIRouter()
    from .entity_activity import create_activity_router
    router.include_router(create_activity_router())
    from .analysis_view import create_analysis_router
    router.include_router(create_analysis_router())
    from .source_archive import create_source_archive_router
    router.include_router(create_source_archive_router())

    @router.get("/dashboard/static/react")
    @router.get("/dashboard/static/react/")
    def react_index():
        """Serve the built app at its documented directory URL.

        Asset delivery also exposes ``index.html`` directly, but a browser
        opening the Vite-compatible base path must not receive a 404.
        """
        entry = ASSETS / "index.html"
        if not entry.is_file():
            return JSONResponse({"error": "React workbench assets are not built"}, status_code=503)
        return FileResponse(entry, headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "no-cache"})

    @router.post("/dashboard/api/workbench/prepare")
    async def prepare(request: Request):
        from .preparation import submit
        try:
            body = await request.json()
            if not isinstance(body, dict):
                raise ValueError("JSON object required")
            if not isinstance(body.get("resume", False), bool):
                raise ValueError("resume must be a boolean")
            row = submit({key: str(body.get(key) or "") for key in ("locator", "program", "slug")}, resume=body.get("resume", False))
            return JSONResponse({"ok": row["status"] != "blocked", "run": row}, status_code=202)
        except (ValueError, OSError) as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    @router.get("/dashboard/api/workbench/preparations")
    def preparations():
        from .preparation import list_runs
        try:
            return {"ok": True, "runs": list_runs()}
        except (ValueError, OSError) as exc:
            return JSONResponse({"ok": False, "runs": [], "error": str(exc)}, status_code=400)

    @router.get("/dashboard/static/react/{asset:path}")
    def asset(asset: str):
        target = (ASSETS / asset).resolve()
        if not target.is_relative_to(ASSETS.resolve()) or not target.is_file() or "\\" in asset:
            return JSONResponse({"error": "Asset not found"}, status_code=404)
        return FileResponse(target, headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "no-cache"})

    @router.get("/dashboard/api/workbench/types")
    def types(slug: str = "", q: str = "", source: str = "ghidra", offset: int = 0, limit: str = "all"):
        from agentdecompile_recovery.corpus.dashboard.common import page_window, query_db, table_exists

        table = "stabs_type" if source == "stabs" else "ghidra_type"
        if not table_exists(table):
            return {"ok": True, "rows": [], "total": 0, "state": "unavailable", "reason": f"No {source} type inventory has been recorded."}
        where = "WHERE 1=1"
        params = []
        if slug:
            where += " AND b.slug=?"
            params.append(slug)
        if q:
            where += " AND t.name LIKE ?"
            params.append("%" + q + "%")
        definition = "t.stab" if source == "stabs" else "t.definition"
        origin = "t.source_file" if source == "stabs" else "t.origin"
        counts, error = query_db(f"SELECT COUNT(*) FROM {table} t JOIN binary b ON b.id=t.binary_id {where}", tuple(params))
        start, cap = page_window(offset, limit)
        sql = f"SELECT b.slug,t.name,t.kind,{definition},{origin} FROM {table} t JOIN binary b ON b.id=t.binary_id {where} ORDER BY b.slug,t.name"
        if cap is None:
            rows, row_error = query_db(sql, tuple(params))
        else:
            rows, row_error = query_db(sql + " LIMIT ? OFFSET ?", (*params, cap, start))
        if error or row_error:
            return JSONResponse({"ok": False, "error": error or row_error}, status_code=503)
        total = counts[0][0]
        return {"ok": True, "rows": [dict(zip(("slug", "name", "kind", "definition", "origin"), row)) for row in rows], "total": total, "offset": start, "limit": "all" if cap is None else cap, "hasMore": cap is not None and start + len(rows) < total, "state": "populated" if total else "empty", "claim": "context hint"}

    @router.get("/dashboard/api/workbench/logical/{logical_id}")
    def logical(logical_id: str):
        from agentdecompile_recovery.corpus.dashboard.pages import logical_detail_json

        payload, status = logical_detail_json(logical_id)
        return JSONResponse(payload, status_code=status)

    @router.get("/api/v1/batches")
    def batches():
        try:
            with _LOCK:
                rows = [_load(p) for p in sorted(_root().glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:100]]
            for batch in rows:
                for row in batch["results"]:
                    if isinstance(row.get("result"), dict):
                        row["result"] = {key: value for key, value in row["result"].items() if key not in {"log", "argv"}}
            return {"ok": True, "batches": rows}
        except ValueError:
            return {"ok": True, "batches": []}

    @router.get("/api/v1/batches/{batch_id}/targets/{index}")
    def batch_target(batch_id: str, index: int):
        if len(batch_id) != 32 or any(c not in "0123456789abcdef" for c in batch_id):
            return JSONResponse({"error": "Not found"}, status_code=404)
        with _LOCK:
            path = _root() / f"{batch_id}.json"
            if not path.exists():
                return JSONResponse({"error": "Not found"}, status_code=404)
            batch = _load(path)
            if index < 0 or index >= len(batch["results"]):
                return JSONResponse({"error": "Target not found"}, status_code=404)
            return {"ok": True, "target": batch["results"][index], "batch": {
                key: batch.get(key) for key in ("id", "status", "error", "ownerUnavailable")
            }}

    @router.post("/api/v1/batches")
    async def batch(request: Request):
        try:
            body = await request.json()
            if not isinstance(body, dict):
                raise ValueError("JSON object required")
            payload, status = await asyncio.to_thread(submit_batch, body)
            return JSONResponse(payload, status_code=status)
        except (ValueError, TypeError) as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

    @router.post("/api/v1/batches/{batch_id}/cancel")
    def cancel(batch_id: str):
        if len(batch_id) != 32 or any(c not in "0123456789abcdef" for c in batch_id):
            return JSONResponse({"error": "Not found"}, status_code=404)
        with _LOCK:
            path = _root() / f"{batch_id}.json"
            if not path.exists():
                return JSONResponse({"error": "Not found"}, status_code=404)
            data = _load(path)
            if data["status"] in {"queued", "running", "cancelling"}:
                _write(path.with_suffix(".cancel"), {"operation": "cancel", "requestedAt": time.time()})
                for row in data["results"]:
                    if row.get("jobId") and row["status"] == "running":
                        jobs.cancel_job(row["jobId"])
                data.update(status="cancelling", cancellationRequested=True)
            return {"ok": True, "batch": data}

    return router
