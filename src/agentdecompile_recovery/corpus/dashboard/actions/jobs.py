"""In-process job runner for cataloged dashboard actions."""

from __future__ import annotations

import json
import os
import re
import queue
import signal
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
from agentdecompile_recovery.corpus.dashboard.common import live_db, live_root

from agentdecompile_recovery.corpus.dashboard.mcp_bridge import CONTEXT_LOCK

MAX_JOBS = 50
MAX_CONCURRENT = 4
MAX_LOG_BYTES = 2 * 1024 * 1024
POLL_S = 0.25

IDENTITY_WRITERS = frozenset({
    "corpus.logical-build",
    "workbench.merge-evidence",
    "corpus.match-pair",
    "corpus.propagate-corpus",
    "corpus.bind-identities",
    "corpus.merge-parts",
    "corpus.apply-stabs",
    "corpus.propagate-source",
})
GHIDRA_MUTATE = frozenset({
    "corpus.apply-annotations",
})

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
    history_only: bool = False
    owner_unavailable: bool = False
    history_source: str = ''
    log_state: str = 'available'
    log_reason: str = ''
    log_truncated: bool = False

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
            "historyOnly": self.history_only,
            "ownerUnavailable": self.owner_unavailable,
            "historySource": self.history_source,
            "logState": self.log_state if self.log or self.history_only else ('pending' if self.status in {'queued', 'running', 'cancelling'} else 'empty'),
            "logReason": self.log_reason,
            "logTruncated": self.log_truncated or len(self.log) >= MAX_LOG_BYTES,
        }
        if include_log:
            payload["log"] = self.log
        payload["progress"] = infer_job_progress(self.status, self.log)
        return payload


_PERCENT_RE = re.compile(r"(?<!\d)(\d{1,3})\s*%")


def infer_job_progress(status: str, log: str = "") -> int | None:
    """Return observed log progress; fall back to Ghidra percent lines and status hints."""
    for line in reversed(log.splitlines()):
        try:
            record = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(record, dict) or record.get("event") != "progress":
            continue
        done, total = record.get("completed"), record.get("total")
        if isinstance(done, (int, float)) and isinstance(total, (int, float)) and total > 0 and 0 <= done <= total:
            return int(100 * done / total)
    percent = _last_percent(log)
    if percent is not None:
        return percent
    if status == "ok":
        return 100
    if status == "queued":
        return 4
    return None


def _last_percent(log: str) -> int | None:
    matches = _PERCENT_RE.findall(log or "")
    if not matches:
        return None
    value = int(matches[-1])
    if 0 <= value <= 100:
        return value
    return None


class JobStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._jobs: dict[str, JobRecord] = {}
        self._order: list[str] = []
        self._cancels: dict[str, threading.Event] = {}
        self._running = 0
        self._identity_held: dict[str, str] = {}
        self._ghidra_held: dict[str, str] = {}
        self.executor: Executor | None = None
        self._persisted_at: dict[str, float] = {}

    def _persist_locked(self, job: JobRecord, *, force: bool = False) -> None:
        from . import job_history
        now = time.monotonic()
        if not force and now - self._persisted_at.get(job.id, 0) < .5:
            return
        payload = job.to_dict()
        payload.update(job_history.owner())
        payload['updatedAt'] = time.time()
        payload['logTruncated'] = job.log_truncated or len(job.log) >= MAX_LOG_BYTES
        try:
            job_history.write(payload)
            self._persisted_at[job.id] = now
        except OSError as exc:
            job.log_reason = f'Durable job output could not be saved: {exc}'

    def _watch_cancel(self, job_id: str, cancel: threading.Event) -> None:
        from .job_history import cancel_requested
        while not cancel.wait(.25):
            with self._lock:
                job = self._jobs.get(job_id)
                if job is None or job.status not in {'queued', 'running', 'cancelling'}:
                    return
            if cancel_requested(job_id):
                cancel.set()
                return

    def list(self) -> list[JobRecord]:
        from .job_history import records
        history = {key: _from_history(value) for key, value in records().items()}
        with self._lock:
            history.update({key: _copy_job(job) for key, job in self._jobs.items()})
        return sorted(history.values(), key=lambda job: job.created_at, reverse=True)

    def get(self, job_id: str) -> JobRecord | None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is not None:
                return _copy_job(job)
        from .job_history import historical
        payload = historical(job_id)
        return _from_history(payload) if payload else None

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
            self._persist_locked(job, force=True)
            self._trim_locked()
        threading.Thread(target=self._watch_cancel, args=(job.id, cancel), daemon=True).start()
        thread = threading.Thread(
            target=self._run,
            args=(job.id, cancel),
            name=f"dashboard-job-{job.id}",
            daemon=True,
        )
        thread.start()
        return self.get(job.id) or job

    def cancel(self, job_id: str) -> JobRecord | None:
        from .job_history import request_cancel
        known = self.get(job_id)
        if known is None:
            return None
        if known.history_only:
            if known.status in {'queued', 'running', 'cancelling'} and not known.owner_unavailable:
                request_cancel(job_id)
                known.status = 'cancelling'
            return known
        with self._lock:
            job = self._jobs.get(job_id)
            event = self._cancels.get(job_id)
            if job is None:
                return None
            if job.status in {"queued", "running"}:
                job.status = "cancelling"
            if event is not None:
                event.set()
            self._persist_locked(job, force=True)
            return _copy_job(job)

    def _run(self, job_id: str, cancel: threading.Event) -> None:
        identity_key = ""
        ghidra_key = ""
        while True:
            with self._lock:
                if cancel.is_set():
                    job = self._jobs[job_id]
                    job.status = "cancelled"
                    job.finished_at = time.time()
                    self._persist_locked(job, force=True)
                    return
                job = self._jobs[job_id]
                coordinator = job.action_id in {"workbench.prepare", "workbench.workflow-control", "workbench.activity-snapshot"}
                can_run = self._running < MAX_CONCURRENT
                if can_run and job.action_id in IDENTITY_WRITERS:
                    identity_key = identity_lock_key(job.params) or ""
                    holder = self._identity_held.get(identity_key)
                    if identity_key and holder and holder != job_id:
                        can_run = False
                action = action_by_id(job.action_id)
                mutates_ghidra = job.action_id in GHIDRA_MUTATE or (action is not None and action.backend == "mcp-cli" and action.mutating)
                if can_run and mutates_ghidra:
                    ghidra_key = ghidra_lock_key(job.params)
                    holder = self._ghidra_held.get(ghidra_key)
                    if ghidra_key and holder and holder != job_id:
                        can_run = False
                if can_run:
                    self._running += 1
                    if identity_key:
                        self._identity_held[identity_key] = job_id
                    if ghidra_key:
                        self._ghidra_held[ghidra_key] = job_id
                    job.status = "running"
                    job.started_at = time.time()
                    self._persist_locked(job, force=True)
                    argv = list(job.argv)
                    break
            time.sleep(POLL_S)
        cwd = live_root() or Path.cwd()
        try:
            action = action_by_id(job.action_id)
            if action is not None and action.backend == "preparation":
                from agentdecompile_recovery.corpus.dashboard.preparation import execute
                code, log = execute(dict(job.params), cancel)
            elif action is not None and action.backend == "merge-evidence":
                from agentdecompile_recovery.corpus.dashboard.workflow import merge_evidence
                code, log = 0, json.dumps(merge_evidence(str(job.params["db"]), str(job.params["run"])))
            elif action is not None and action.backend == "workflow-control":
                from agentdecompile_recovery.corpus.dashboard.preparation import control
                code, log = 0, json.dumps(control(dict(job.params)))
            elif action is not None and action.backend == "activity-snapshot":
                from agentdecompile_recovery.corpus.dashboard.entity_activity import snapshot
                code, log = 0, json.dumps(snapshot(locator=job.params.get("locator", ""), slug=job.params.get("slug", ""), program=job.params.get("program", "") or job.params.get("programPath", "")))
            elif action is not None and action.backend == "source-archive":
                from agentdecompile_recovery.corpus.dashboard.source_archive import build_archive
                def archive_progress(text: str) -> None:
                    with self._lock:
                        self._jobs[job_id].log = text[-MAX_LOG_BYTES:]
                        self._persist_locked(self._jobs[job_id])
                def export_program(output_path: Path, context: dict[str, Any]) -> dict[str, Any]:
                    return _export_archive_program(output_path, context, cancel)
                result = build_archive(dict(job.params), cancel, archive_progress, export_program=export_program)
                code, log = (0 if result.get("ok") else 1), json.dumps(result, default=str)
            elif action is not None and action.backend == "mcp-cli":
                code, log = _mcp_executor(action, dict(job.params), cancel)
            else:
                def publish_log(text: str) -> None:
                    with self._lock:
                        self._jobs[job_id].log = text[-MAX_LOG_BYTES:]
                        self._persist_locked(self._jobs[job_id])
                if self.executor:
                    code, log = self.executor(argv, cwd, cancel)
                else:
                    code, log = _default_executor(argv, cwd, cancel, on_output=publish_log)
                if action is not None and action.backend == "bsim-cli":
                    from agentdecompile_recovery.corpus.bsim_ops import _bsim_cli_error
                    if _bsim_cli_error(log, ""):
                        code = code or 1
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
                    job.error = next((line.strip() for line in reversed(job.log.splitlines()) if line.strip().lower().startswith(('error:', 'exception:', 'failed:'))), f'Operation exited with status {code}. Inspect its retained output for details.')
        except Exception as exc:  # noqa: BLE001 — job must not kill the server
            with self._lock:
                job = self._jobs[job_id]
                job.error = str(exc)
                job.status = "failed"
                job.finished_at = time.time()
        finally:
            with self._lock:
                self._persist_locked(self._jobs[job_id], force=True)
                if not coordinator:
                    self._running = max(0, self._running - 1)
                if identity_key and self._identity_held.get(identity_key) == job_id:
                    self._identity_held.pop(identity_key, None)
                if ghidra_key and self._ghidra_held.get(ghidra_key) == job_id:
                    self._ghidra_held.pop(ghidra_key, None)

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
        history_only=job.history_only, owner_unavailable=job.owner_unavailable,
        history_source=job.history_source, log_state=job.log_state,
        log_reason=job.log_reason, log_truncated=job.log_truncated,
    )


def _from_history(payload: dict) -> JobRecord:
    from ..preparation import _owner_alive
    status = str(payload.get('status') or 'unknown')
    unavailable = status in {'queued', 'running', 'cancelling'} and not _owner_alive(payload)
    error = str(payload.get('error') or '')
    if unavailable:
        status = 'interrupted'
        error = error or 'The owning process stopped before recording completion. Retained output is available; reconcile the operation before resubmitting.'
    return JobRecord(id=payload['id'], action_id=payload.get('actionId', ''), title=payload.get('title', ''),
                     argv=list(payload.get('argv') or []), status=status, created_at=payload.get('createdAt') or 0,
                     started_at=payload.get('startedAt'), finished_at=payload.get('finishedAt'), returncode=payload.get('returncode'),
                     error=error, log=payload.get('log') or '', params=dict(payload.get('params') or {}),
                     history_only=True, owner_unavailable=unavailable, history_source=payload.get('historySource') or 'durable-job-receipt',
                     log_state=payload.get('logState') or ('available' if payload.get('log') else 'unavailable'),
                     log_reason=payload.get('logReason') or '', log_truncated=bool(payload.get('logTruncated')))


def _export_archive_program(output_path: Path, context: dict[str, Any], cancel: threading.Event) -> dict[str, Any]:
    export, inspect = action_by_id("mcp.export"), action_by_id("mcp.execute-script")
    if export is None or inspect is None:
        return {"ok": False, "error": "Whole-program Ghidra export is unavailable."}
    target = {"locator": context.get("locator", ""), "programPath": context.get("program", "")}
    def payload(log: str) -> dict[str, Any]:
        try:
            data, _ = json.JSONDecoder().raw_decode(log[log.index("{"):])
            if isinstance(data, dict) and isinstance(data.get("result"), str):
                data = json.loads(data["result"])
            return data if isinstance(data, dict) else {}
        except (ValueError, TypeError):
            return {}
    # Inspection and export must retain one project/session ownership interval.
    with CONTEXT_LOCK:
        code, log = _mcp_executor_in_context(inspect, {**target, "_preparationProbe": True, "code":
            "import json\nfrom agentdecompile_cli.mcp_utils.program_analysis import program_needs_analysis\n"
            "__result__ = json.dumps({'md5': str(currentProgram.getExecutableMD5()), 'needsAnalysis': program_needs_analysis(currentProgram), "
            "'functionCount': int(currentProgram.getFunctionManager().getFunctionCount()), 'project': str(currentProgram.getDomainFile().getProjectLocator()), 'program': str(currentProgram.getDomainFile().getPathname())})",
            "timeout": 30}, cancel)
        observed = payload(log)
        if code or not observed.get("md5") or str(observed["md5"]).lower() != str(context.get("programFingerprint", "")).lower():
            return {"ok": False, "error": "The selected Ghidra program's fingerprint could not be matched to this binary.", "observation": observed}
        if observed.get("needsAnalysis") is not False:
            return {"ok": False, "error": "Analysis is pending. Whole-program source export will be available after analysis completes.", "observation": observed}
        code, log = _mcp_executor_in_context(export, {**target, "outputPath": str(output_path), "format": "c", "createHeader": True}, cancel)
        data = payload(log)
    accepted = code == 0 and data.get("success") is True and output_path.is_file()
    return {"ok": accepted, "tool": "export", "data": data, "observation": observed,
            "error": "" if accepted else data.get("error") or log[-4000:]}


def _mcp_executor(action: ActionSpec, params: dict[str, Any], cancel: threading.Event) -> tuple[int, str]:
    # Project context and the following action must use one uninterrupted session.
    # Compilation and non-Ghidra work remain independent of this lock.
    with CONTEXT_LOCK:
        return _mcp_executor_in_context(action, params, cancel)


def _mcp_executor_in_context(action: ActionSpec, params: dict[str, Any], cancel: threading.Event) -> tuple[int, str]:
    from agentdecompile_recovery.corpus.dashboard.mcp_bridge import call_tool, ensure_project

    if cancel.is_set():
        return 1, "[cancelled]\n"
    arguments = {
        key: value
        for key, value in params.items()
        if (value not in (None, "") or (value == "" and action.command == "manage-function" and str(params.get("mode", "")).replace("_", "").replace("-", "").lower() == "setproperties" and key.replace("_", "").lower() in {"namespace", "callfixup", "thunktarget"})) and key in {field.name for field in action.fields}
    }
    locator = str(params.get("locator") or "")
    if locator and action.command not in {"open", "connect-shared-project"}:
        opened = ensure_project(locator)
        if not opened.get("ok"):
            return 1, "Could not open the selected project without analysis.\n" + str(opened.get("error") or opened.get("text"))
        if cancel.is_set():
            return 1, "[cancelled before action]\n"
    if params.get("_preparationProbe") and action.command == "execute-script":
        arguments["autoPrereqInvocation"] = True
    if params.get('_functionEvidence') and action.command == 'get-function':
        arguments['autoPrereqInvocation'] = True
    arguments["responseFormat"] = "json"
    timeout = 600.0 if action.long_running else 120.0
    if action.command in {"analyze-program", "import-binary", "export"}:
        timeout = 1800.0
    if action.command == "execute-script":
        timeout = min(1800.0, max(timeout, float(arguments.get("timeout", 30)) + 30.0))
    hit = call_tool(action.command, arguments, timeout=timeout)
    text = hit.get("text") or ""
    parsed = hit.get("parsed")
    if hit.get("ok") and isinstance(parsed, dict) and action.command in {"get-function", "decompile-function"}:
        from agentdecompile_recovery.corpus.dashboard.function_evidence import record
        record(params, action.command, parsed)
    log_parts = [f"mcp {action.command}\n"]
    if parsed is not None:
        log_parts.append(json.dumps(parsed, indent=2, default=str)[: MAX_LOG_BYTES - 200])
        log_parts.append("\n")
    elif text:
        log_parts.append(text[: MAX_LOG_BYTES - 200])
        log_parts.append("\n")
    if hit.get("error"):
        log_parts.append(f"error: {hit['error']}\n")
    if hit.get('ok') and action.mutating and params.get('programPath') and not params.get('_preparationProbe') and not action.command.startswith(('get-', 'list-', 'search-', 'decompile-')) and action.command != 'export':
        from agentdecompile_recovery.corpus.dashboard.function_evidence import invalidate
        try:
            invalidate(params)
        except OSError as exc:
            log_parts.append(f'Function evidence refresh could not be recorded: {exc}\n')
    if cancel.is_set():
        return 1, "".join(log_parts) + "[cancelled]\n"
    return (0 if hit.get("ok") else 1), "".join(log_parts)


def isolated_job_env(argv: list[str], base: dict[str, str] | None = None) -> dict[str, str]:
    """Objdiff uses the recovery-toolchains dir and drops Wine from ghidra-bulk."""
    env = dict(base if base is not None else os.environ)
    if not any("objdiff-check" in str(part) for part in argv):
        return env
    env["AGENT_DECOMPILE_OBJDIFF_ISOLATED"] = "1"
    env.pop("WINEPREFIX", None)
    env.pop("WINE", None)
    repo = Path(__file__).resolve().parents[5]
    tool = repo / "scripts" / "recovery-toolchains"
    if tool.is_dir():
        env["PATH"] = str(tool) + os.pathsep + env.get("PATH", "")
    return env


def _default_executor(argv: list[str], cwd: Path, cancel: threading.Event, *, on_output: Callable[[str], None] | None = None) -> tuple[int, str]:
    """Drain output without blocking cancellation when a child is silent."""
    if not argv:
        return 2, "empty command"
    proc = subprocess.Popen(argv, cwd=str(cwd), stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, bufsize=1, env=isolated_job_env(argv),
        start_new_session=os.name != "nt")
    lines: queue.Queue[str | None] = queue.Queue(maxsize=1000)
    def read() -> None:
        assert proc.stdout is not None
        try:
            for line in proc.stdout:
                lines.put(line)
        finally:
            lines.put(None)
    threading.Thread(target=read, daemon=True).start()
    log = ""
    cancellation_at = None
    cancellation_forced = False
    while True:
        if cancel.is_set() and cancellation_at is None:
            cancellation_at = time.monotonic()
            try:
                if os.name != "nt":
                    # Descendants may still own the pipe after its leader exits.
                    os.killpg(proc.pid, signal.SIGTERM)
                elif proc.poll() is None:
                    proc.terminate()
            except ProcessLookupError:
                pass
            log += "\n[cancelled]\n"
        if cancellation_at is not None and not cancellation_forced and time.monotonic() - cancellation_at >= 5:
            cancellation_forced = True
            try:
                if os.name != "nt":
                    os.killpg(proc.pid, signal.SIGKILL)
                elif proc.poll() is None:
                    proc.kill()
            except ProcessLookupError:
                pass
        try:
            line = lines.get(timeout=.1)
        except queue.Empty:
            # Process exit can precede the reader thread delivering its final
            # buffered output. Only the pipe EOF sentinel proves it is drained.
            continue
        if line is None: break
        log = (log + line)[-MAX_LOG_BYTES:]
        if on_output: on_output(log)
    return int(proc.wait()), log


STORE = JobStore()


def identity_lock_key(params: dict[str, Any] | None) -> str | None:
    raw = (params or {}).get("db") or live_db()
    if not raw:
        return None
    try:
        return str(Path(raw).expanduser().resolve())
    except (OSError, RuntimeError, TypeError, ValueError):
        return None


def ghidra_lock_key(params: dict[str, Any] | None) -> str:
    row = params or {}
    return str(row.get("locator") or row.get("programPath") or row.get("program") or "")


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
    if action.id in IDENTITY_WRITERS:
        key = identity_lock_key(filled)
        if not key:
            return {"error": "identity writer needs --db", "actionId": action.id}, 400
        filled["db"] = key
    if action.backend == "preparation" and not dry_run:
        from agentdecompile_recovery.corpus.dashboard.preparation import submit
        try:
            run = submit(filled, resume=bool(filled.get("resume", False)))
        except (ValueError, OSError) as exc:
            return {"error": str(exc)}, 400
        job = get_job(run.get("jobId", ""))
        return {"ok": run["status"] != "blocked", "run": run, "job": job.to_dict() if job else {"id": run.get("jobId", ""), "status": run["status"]}}, 202
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
