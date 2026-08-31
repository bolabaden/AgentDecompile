"""In-process job runner for cataloged dashboard actions."""

from __future__ import annotations

import os
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from agentdecompile_recovery.corpus.dashboard.actions.catalog import (
    ActionSpec,
    action_by_id,
    apply_defaults,
    build_command,
    validate_params,
)
from agentdecompile_recovery.corpus.dashboard.common import live_root

MAX_JOBS = 50
MAX_CONCURRENT = 4
MAX_LOG_BYTES = 2 * 1024 * 1024
POLL_S = 0.25

Executor = Callable[[list[str], Path, threading.Event], tuple[int, str]]


@dataclass
class JobRecord:
    id: str
    action_id: str
    title: str
    argv: list[str]
    status: str = "queued"
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None
    returncode: int | None = None
    error: str = ""
    log: str = ""
    params: dict[str, Any] = field(default_factory=dict)

    def to_dict(self, *, include_log: bool = True) -> dict[str, Any]:
        payload = {
            "id": self.id,
            "actionId": self.action_id,
            "title": self.title,
            "argv": list(self.argv),
            "status": self.status,
            "createdAt": self.created_at,
            "startedAt": self.started_at,
            "finishedAt": self.finished_at,
            "returncode": self.returncode,
            "error": self.error,
            "params": dict(self.params),
        }
        if include_log:
            payload["log"] = self.log
        return payload


class JobStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._jobs: dict[str, JobRecord] = {}
        self._order: list[str] = []
        self._cancels: dict[str, threading.Event] = {}
        self._running = 0
        self.executor: Executor | None = None

    def list(self) -> list[JobRecord]:
        with self._lock:
            return [_copy_job(self._jobs[key]) for key in reversed(self._order) if key in self._jobs]

    def get(self, job_id: str) -> JobRecord | None:
        with self._lock:
            job = self._jobs.get(job_id)
            return None if job is None else _copy_job(job)

    def start(self, action: ActionSpec, params: dict[str, Any], argv: list[str]) -> JobRecord:
        job = JobRecord(
            id=uuid.uuid4().hex[:12],
            action_id=action.id,
            title=action.title,
            argv=list(argv),
            params=dict(params),
        )
        cancel = threading.Event()
        with self._lock:
            self._jobs[job.id] = job
            self._order.append(job.id)
            self._cancels[job.id] = cancel
            self._trim_locked()
        thread = threading.Thread(
            target=self._run,
            args=(job.id, cancel),
            name=f"dashboard-job-{job.id}",
            daemon=True,
        )
        thread.start()
        return self.get(job.id) or job

    def cancel(self, job_id: str) -> JobRecord | None:
        with self._lock:
            job = self._jobs.get(job_id)
            event = self._cancels.get(job_id)
            if job is None:
                return None
            if job.status in {"queued", "running"}:
                job.status = "cancelling"
            if event is not None:
                event.set()
            return _copy_job(job)

    def _run(self, job_id: str, cancel: threading.Event) -> None:
        while True:
            with self._lock:
                if cancel.is_set():
                    job = self._jobs[job_id]
                    job.status = "cancelled"
                    job.finished_at = time.time()
                    return
                if self._running < MAX_CONCURRENT:
                    self._running += 1
                    job = self._jobs[job_id]
                    job.status = "running"
                    job.started_at = time.time()
                    argv = list(job.argv)
                    break
            time.sleep(POLL_S)
        cwd = live_root() or Path.cwd()
        try:
            runner = self.executor or _default_executor
            code, log = runner(argv, cwd, cancel)
            with self._lock:
                job = self._jobs[job_id]
                job.log = log[-MAX_LOG_BYTES:]
                job.returncode = code
                job.finished_at = time.time()
                if cancel.is_set() and job.status != "cancelled":
                    job.status = "cancelled"
                elif code == 0:
                    job.status = "ok"
                else:
                    job.status = "failed"
        except Exception as exc:  # noqa: BLE001 — job must not kill the server
            with self._lock:
                job = self._jobs[job_id]
                job.error = str(exc)
                job.status = "failed"
                job.finished_at = time.time()
        finally:
            with self._lock:
                self._running = max(0, self._running - 1)

    def _trim_locked(self) -> None:
        while len(self._order) > MAX_JOBS:
            old = self._order.pop(0)
            job = self._jobs.get(old)
            if job is not None and job.status in {"queued", "running", "cancelling"}:
                self._order.insert(0, old)
                break
            self._jobs.pop(old, None)
            self._cancels.pop(old, None)


def _copy_job(job: JobRecord) -> JobRecord:
    return JobRecord(
        id=job.id,
        action_id=job.action_id,
        title=job.title,
        argv=list(job.argv),
        status=job.status,
        created_at=job.created_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
        returncode=job.returncode,
        error=job.error,
        log=job.log,
        params=dict(job.params),
    )


def _default_executor(argv: list[str], cwd: Path, cancel: threading.Event) -> tuple[int, str]:
    if not argv:
        return 2, "empty command"
    env = os.environ.copy()
    proc = subprocess.Popen(
        argv,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    chunks: list[str] = []
    assert proc.stdout is not None
    while True:
        if cancel.is_set() and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            chunks.append("\n[cancelled]\n")
            break
        line = proc.stdout.readline()
        if line:
            chunks.append(line)
            if sum(len(part) for part in chunks) > MAX_LOG_BYTES:
                chunks = chunks[-200:]
            continue
        if proc.poll() is not None:
            rest = proc.stdout.read()
            if rest:
                chunks.append(rest)
            break
        time.sleep(0.05)
    code = proc.wait()
    return int(code if code is not None else 1), "".join(chunks)


STORE = JobStore()


def start_job(
    action_id: str,
    params: dict[str, Any] | None = None,
    *,
    context: dict[str, Any] | None = None,
    confirm: bool = False,
    dry_run: bool = False,
) -> tuple[dict[str, Any], int]:
    action = action_by_id(action_id)
    if action is None:
        return {"error": f"unknown action {action_id}"}, 404
    filled = apply_defaults(action, dict(params or {}), context)
    errors = validate_params(action, filled, confirm=confirm)
    if errors:
        return {"error": "; ".join(errors), "actionId": action.id}, 400
    argv = build_command(action, filled)
    if dry_run:
        return {"ok": True, "dryRun": True, "action": action.to_dict(), "argv": argv, "params": filled}, 200
    job = STORE.start(action, filled, argv)
    return {"ok": True, "job": job.to_dict()}, 202


def list_jobs() -> list[JobRecord]:
    return STORE.list()


def get_job(job_id: str) -> JobRecord | None:
    return STORE.get(job_id)


def cancel_job(job_id: str) -> JobRecord | None:
    return STORE.cancel(job_id)
