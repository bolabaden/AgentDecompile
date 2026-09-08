"""Durable, missing-only project preparation shared by both frontends."""
from __future__ import annotations

import hashlib
import json
import os
import socket
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from .common import live_db, live_root, query_db
from .workflow import DEFAULT_BUDGET_SECONDS, MAX_BUDGET_SECONDS, STAGES as RECOVERY_STAGES, VERSION, transient_failure

_LOCK = threading.RLock()
_BSIM_LOCK = threading.Lock()
_ACTIVE: set[str] = set()
_LEASES: dict[str, Any] = {}
_WAITING: set[str] = set()
_ADMISSION_WAKE = threading.Event()
_ADMISSION_THREAD: threading.Thread | None = None
_STAGES = [('inspect', 'Read project'), ('protection', 'Prepare analysis image'),
           ('analysis', 'Analyze missing programs'), ('facts', 'Extract function facts'),
           ('bsim', 'Index similarity signatures'), ('matching', 'Match related builds')] + RECOVERY_STAGES


def _budget_expired(deadline: Any) -> bool:
    return deadline is not None and time.time() >= float(deadline)


def _merge_stages(previous: dict[str, Any]) -> list[dict[str, Any]]:
    by_key = {item.get('key'): dict(item) for item in previous.get('stages') or [] if item.get('key')}
    stages = []
    for key, title in _STAGES:
        if key in by_key:
            row = by_key[key]
            row['title'] = title
            stages.append(row)
        else:
            stages.append({'key': key, 'title': title, 'status': 'queued', 'completed': 0, 'total': None, 'reason': ''})
    return stages


def _ensure_stages(row: dict[str, Any]) -> bool:
    before = [item.get('key') for item in row.get('stages') or []]
    row['stages'] = _merge_stages(row)
    after = [item.get('key') for item in row['stages']]
    if after != before:
        row['workflowVersion'] = VERSION
        return True
    return False


def _lock_lease(lease: Any) -> None:
    if os.name == 'nt':
        import msvcrt
        lease.seek(0)
        if not lease.read(1):
            lease.write('0')
            lease.flush()
        lease.seek(0)
        try:
            msvcrt.locking(lease.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            raise BlockingIOError(str(exc)) from exc
    else:
        import fcntl
        fcntl.flock(lease.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _directory() -> Path:
    root = live_root()
    if root is None:
        raise ValueError('Choose a server workspace before preparing projects.')
    directory = root / 'preparations'
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _write(row: dict[str, Any]) -> None:
    row['updatedAt'] = time.time()
    path = _directory() / (row['id'] + '.json')
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(row), encoding='utf-8')
    temporary.replace(path)


def _read(run_id: str) -> dict[str, Any]:
    if len(run_id) != 32 or any(c not in '0123456789abcdef' for c in run_id):
        raise ValueError('Invalid preparation ID')
    return json.loads((_directory() / (run_id + '.json')).read_text(encoding='utf-8'))


def _process_start(pid: int) -> str | None:
    try:
        return Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19]
    except (OSError, IndexError):
        return None


def _owner_alive(row: dict[str, Any]) -> bool:
    if row.get('ownerHost') and row['ownerHost'] != socket.gethostname():
        return True
    pid = row.get('ownerPid')
    if not isinstance(pid, int) or pid <= 0:
        # Legacy receipts cannot establish that another server has stopped.
        return True
    try:
        os.kill(pid, 0)
        recorded_start = row.get('ownerStart')
        current_start = _process_start(pid)
        if recorded_start and current_start and recorded_start != current_start:
            return False
        return True
    except PermissionError:
        return True
    except ProcessLookupError:
        return False


def list_runs() -> list[dict[str, Any]]:
    from .actions import jobs
    with _LOCK:
        rows = []
        for path in sorted(_directory().glob('*.json'), key=lambda p: p.stat().st_mtime, reverse=True)[:100]:
            row = json.loads(path.read_text())
            job = jobs.get_job(row.get('jobId', ''))
            if row['id'] in _ACTIVE and job and job.status in {'cancelled', 'failed'}:
                _ACTIVE.discard(row['id'])
            _ensure_stages(row)
            if row['id'] not in _ACTIVE and not _owner_alive(row) and row['status'] in {'queued', 'running'}:
                row['status'] = 'interrupted'
                for stage in row['stages']:
                    if stage['status'] == 'running':
                        stage.update(status='interrupted', reason='The server stopped before this stage recorded completion.')
            command = _read_control(row['id'])
            if 'deadline' in command:
                row['deadline'] = command['deadline']
                row['budgetSeconds'] = command.get('budgetSeconds', row.get('budgetSeconds'))
                row['budgetOrigin'] = command.get('budgetOrigin', row.get('budgetOrigin', 'default'))
            row['queuePriority'] = command.get('priority', row.get('queuePriority', 50))
            row['priorityReason'] = command.get('priorityReason', 'FIFO among projects with equal priority.')
            rows.append(row)
        waiting = sorted((row for row in rows if row.get('admissionPending') and _read_control(row['id']).get('operation') not in {'pause', 'stop'}), key=_admission_order)
        positions = {row['id']: index + 1 for index, row in enumerate(waiting)}
        for row in rows:
            row['queuePosition'] = positions.get(row['id'])
        return rows


def _admission_order(row: dict[str, Any]) -> tuple[int, float, str]:
    command = _read_control(row['id'])
    return (-int(command.get('priority', row.get('queuePriority', 50))), float(row.get('createdAt', 0)), row['id'])


def _inventory_request(run_id: str) -> dict[str, Any]:
    try:
        return json.loads((_directory() / 'inventory' / (run_id + '.json')).read_text())
    except (OSError, ValueError):
        return {}


def inventory_changed(locator: str) -> dict[str, Any]:
    """Durably admit newly imported members, including during an active wave."""
    context = _project_context({'locator': locator})
    run_id = _context_id(context)
    request = {'id': run_id, 'locator': context['locator'], 'generation': uuid.uuid4().hex, 'updatedAt': time.time()}
    directory = _directory() / 'inventory'
    directory.mkdir(exist_ok=True)
    temporary = directory / (run_id + '.' + request['generation'] + '.tmp')
    temporary.write_text(json.dumps(request))
    temporary.replace(directory / (run_id + '.json'))
    with _LOCK:
        _start_admission_worker()
    return {'id': run_id, 'status': 'accepted', 'inventoryGeneration': request['generation']}


def _collect_inventory_admissions() -> None:
    # Requests have a separate atomic file so an executing wave cannot overwrite
    # a concurrent import notification with its in-memory receipt.
    for path in sorted((_directory() / 'inventory').glob('*.json'), key=lambda path: path.stat().st_mtime, reverse=True)[:100]:
        request = {}
        try:
            request = json.loads(path.read_text())
            row = _read(request['id'])
        except FileNotFoundError:
            if request.get('locator'):
                submit({'locator': request['locator']}, resume=True, _admit=True)
            continue
        except (OSError, ValueError):
            continue
        if row.get('inventoryGeneration') == request.get('generation') or row['id'] in _ACTIVE:
            continue
        if row.get('status') in {'queued', 'running', 'paused'} and _owner_alive(row) and not row.get('admissionPending'):
            continue
        command = _read_control(row['id'])
        if command.get('operation') in {'pause', 'stop'} or row.get('status') == 'cancelled':
            continue
        if _budget_expired(command.get('deadline', row.get('deadline'))):
            continue
        submit({'locator': request['locator']}, resume=True, _admit=True)


def _start_admission_worker() -> None:
    global _ADMISSION_THREAD
    if _ADMISSION_THREAD is None or not _ADMISSION_THREAD.is_alive():
        _ADMISSION_THREAD = threading.Thread(target=_drain_admissions, name='workflow-admission', daemon=True)
        _ADMISSION_THREAD.start()
    _ADMISSION_WAKE.set()


def _drain_admissions() -> None:
    while True:
        _ADMISSION_WAKE.wait(30)
        _ADMISSION_WAKE.clear()
        with _LOCK:
            if len(_ACTIVE) >= 4:
                continue
            pending = sorted((_read(key) for key in list(_WAITING)), key=_admission_order)
            for row in pending:
                if len(_ACTIVE) >= 4:
                    break
                command = _read_control(row['id'])
                if command.get('operation') == 'pause':
                    continue
                if command.get('operation') == 'stop' or _budget_expired(command.get('deadline', row.get('deadline'))):
                    row.update(status='cancelled' if command.get('operation') == 'stop' else 'budget-stop', admissionPending=False)
                    _write(row)
                    _WAITING.discard(row['id'])
                    continue
                try:
                    submit({key: row.get(key, '') for key in ('locator', 'program', 'slug')}, resume=True, _admit=True)
                except (OSError, ValueError) as exc:
                    row.update(status='blocked', admissionPending=False, error=str(exc))
                    _write(row)
                    _WAITING.discard(row['id'])
            try:
                _collect_inventory_admissions()
            except (OSError, ValueError):
                # A temporarily inaccessible project remains durably requested.
                pass


def _project_context(context: dict[str, Any]) -> dict[str, Any]:
    from agentdecompile_recovery.corpus.ghidra_project import classify_locator
    locator = str(context.get('locator') or '')
    if not locator:
        candidate = str(context.get('program') or '')
        if Path(candidate).is_absolute() and Path(candidate).suffix.lower() in {'.gpr', '.rep'}:
            project_info = classify_locator(candidate)
            if project_info.get('kind') == 'ghidra-project':
                locator = candidate
    info = classify_locator(locator) if locator else {}
    if info.get('kind') in {'ghidra-project', 'shared-project'}:
        locator = str(info.get('canonical') or locator)
        if info.get('gpr'):
            locator = str(Path(info['gpr']).resolve())
        return {**context, 'locator': locator, 'program': '', 'slug': ''}
    if locator and (locator.startswith('ghidra:') or Path(locator).suffix.lower() in {'.gpr', '.rep'} or Path(locator).is_dir()):
        return {**context, 'locator': locator, 'program': '', 'slug': ''}
    return dict(context)


def _context_id(context: dict[str, Any]) -> str:
    key = json.dumps([str(live_db()), str(context.get('locator') or ''), str(context.get('program') or ''), str(context.get('slug') or '')])
    return hashlib.sha256(key.encode()).hexdigest()[:32]


def _merge_legacy_contexts(previous: dict[str, Any], locator: str, canonical_id: str) -> dict[str, Any] | None:
    if not locator:
        return None
    candidates = []
    for path in sorted(_directory().glob('*.json'), key=lambda p: p.stat().st_mtime, reverse=True)[:100]:
        try:
            legacy = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        if legacy.get('id') == canonical_id or _project_context(legacy).get('locator') != locator or legacy.get('supersededBy'):
            continue
        candidates.append(legacy)
    for legacy in candidates:
        if legacy.get('status') in {'running', 'queued', 'paused'} and _owner_alive(legacy):
            return legacy
    preserve_deadline = 'deadline' in previous
    for legacy in candidates:
        previous['createdAt'] = min(previous.get('createdAt', legacy['createdAt']), legacy['createdAt'])
        if legacy.get('deadline') and not preserve_deadline:
            previous['deadline'] = min(previous.get('deadline', legacy['deadline']), legacy['deadline'])
        # Only a known executable fingerprint can carry evidence between old
        # selection-specific admissions. Do not adopt uncertain child actions.
        for program, checkpoint in legacy.get('checkpoints', {}).items():
            fingerprint = checkpoint.get('programFingerprint')
            if not fingerprint:
                continue
            saved = previous.setdefault('checkpoints', {}).get(program)
            if saved is None:
                previous['checkpoints'][program] = checkpoint
            elif saved.get('programFingerprint') == fingerprint:
                previous['checkpoints'][program] = {**checkpoint, **saved}
        legacy['supersededBy'] = canonical_id
        legacy['supersededReason'] = 'Project navigation now joins one project workflow. Original outcomes remain recorded.'
        _write(legacy)
    return None


def submit(context: dict[str, Any], *, resume: bool = False, _admit: bool = False) -> dict[str, Any]:
    context = _project_context(context)
    key = json.dumps([str(live_db()), str(context.get('locator') or ''), str(context.get('program') or ''), str(context.get('slug') or '')])
    run_id = hashlib.sha256(key.encode()).hexdigest()[:32]
    with _LOCK:
        if run_id in _ACTIVE:
            return _read(run_id)
        lease = (_directory() / (run_id + '.lock')).open('a+')
        try:
            _lock_lease(lease)
        except BlockingIOError:
            lease.close()
            for _ in range(20):
                try:
                    return _read(run_id)
                except FileNotFoundError:
                    time.sleep(0.01)
            return {'id': run_id, 'status': 'queued', 'locator': context.get('locator', ''),
                    'program': context.get('program', ''), 'slug': context.get('slug', ''),
                    'stages': [], 'events': [], 'reason': 'Another server is recording this preparation admission.'}
        _LEASES[run_id] = lease
        try:
            return _submit(context, resume=resume, _admit=_admit)
        finally:
            if run_id not in _ACTIVE:
                _release_lease(run_id)


def _release_lease(run_id: str) -> None:
    lease = _LEASES.pop(run_id, None)
    if lease is not None:
        lease.close()


def _submit(context: dict[str, Any], *, resume: bool = False, _admit: bool = False) -> dict[str, Any]:
    from .actions import jobs

    if not isinstance(resume, bool):
        raise ValueError('resume must be a boolean')
    locator = str(context.get('locator') or '')
    program = str(context.get('program') or '')
    slug = str(context.get('slug') or '')
    if not locator and not slug:
        raise ValueError('Open a project or select a registered binary first.')
    key = json.dumps([str(live_db()), locator, program, slug])
    run_id = hashlib.sha256(key.encode()).hexdigest()[:32]
    with _LOCK:
        list_runs()
        path = _directory() / (run_id + '.json')
        if path.exists():
            previous = _read(run_id)
            live_legacy = _merge_legacy_contexts(previous, locator, run_id)
            if live_legacy:
                return live_legacy
            if _ensure_stages(previous):
                previous['workflowVersion'] = VERSION
            _write(previous)
            if previous['status'] in {'queued', 'running'} and not _owner_alive(previous):
                previous['status'] = 'interrupted'
            if run_id in _ACTIVE or (_owner_alive(previous) and previous['status'] in {'queued', 'running'} and not (_admit and previous.get('admissionPending'))) or (not resume and previous['status'] not in {'interrupted'}):
                return previous
        else:
            previous = {}
            live_legacy = _merge_legacy_contexts(previous, locator, run_id)
            if live_legacy:
                return live_legacy
        row = {'id': run_id, 'locator': locator, 'program': program, 'slug': slug,
               'status': 'queued', 'scope': 'project' if locator and not program else 'binary', 'ownerPid': os.getpid(), 'ownerStart': _process_start(os.getpid()), 'ownerHost': socket.gethostname(),
               'createdAt': previous.get('createdAt', time.time()),
               'updatedAt': time.time(), 'workflowVersion': VERSION,
               'queuePriority': _read_control(run_id).get('priority', previous.get('queuePriority', 50)),
               'budgetSeconds': previous.get('budgetSeconds', max(1, previous['deadline'] - previous['createdAt']) if previous.get('deadline') and previous.get('createdAt') else DEFAULT_BUDGET_SECONDS),
               'inventoryGeneration': _inventory_request(run_id).get('generation'),
               'deadline': previous.get('deadline'),
               'budgetOrigin': previous.get('budgetOrigin', 'default'),
               'actions': previous.get('actions', {}), 'jobTimingContexts': previous.get('jobTimingContexts', {}),
               'events': previous.get('events', []), 'programs': [], 'checkpoints': previous.get('checkpoints', {}),
               'stages': _merge_stages(previous)}
        if resume:
            for stage in row['stages']:
                if stage.get('status') in {'blocked', 'cancelled', 'interrupted', 'cancelling'} and str(stage.get('reason', '')).startswith(('Workflow stopped', 'The server stopped')):
                    stage.update(status='queued', reason='Waiting for the renewed workflow to reach this stage.')
        if len(_ACTIVE) >= 4 or (_WAITING and not _admit):
            row.update(admissionPending=True, reason='Waiting for another project operation to release a worker.')
            _write(row)
            _WAITING.add(run_id)
            _start_admission_worker()
            return row
        row['admissionPending'] = False
        _WAITING.discard(run_id)
        _write(row)
        _ACTIVE.add(run_id)
        from .actions.catalog import action_by_id
        try:
            spec = action_by_id('workbench.prepare')
            if spec is None:
                raise ValueError('Preparation action is unavailable.')
            job = jobs.STORE.start(spec, {'locator': locator, 'program': program, 'slug': slug, 'preparation_id': run_id}, ['workbench.prepare'])
            row['jobId'] = job.id
        except Exception as exc:
            _ACTIVE.discard(run_id)
            row.update(status='blocked', error=str(exc))
        _write(row)
        return row


def execute(params: dict[str, Any], cancel: threading.Event) -> tuple[int, str]:
    from .actions import jobs
    from agentdecompile_recovery.corpus.ghidra_project import inspect_locator

    run_id = params['preparation_id']
    with _LOCK:
        row = _read(run_id)
        _ensure_stages(row)
        row['status'] = 'running'
        _write(row)
    comparison_inputs: dict[str, Any] = {}

    def update(key: str, status: str, reason: str = '', **values: Any) -> None:
        with _LOCK:
            stage = next((item for item in row['stages'] if item['key'] == key), None)
            if stage is None:
                title = next((name for item, name in _STAGES if item == key), key)
                stage = {'key': key, 'title': title, 'status': 'queued', 'completed': 0, 'total': None, 'reason': ''}
                row['stages'].append(stage)
            stage.update(status=status, reason=reason, **values)
            row.update(currentStage=key, currentProgram=values.get('currentProgram', stage.get('currentProgram', '')), currentAction=values.get('currentAction', stage.get('currentAction', '')))
            if reason:
                row['events'].append({'at': time.time(), 'stage': key, 'message': reason})
                row['events'] = row['events'][-250:]
            _write(row)

    def stopped() -> bool:
        command = _read_control(run_id)
        if 'deadline' in command:
            row['deadline'] = command['deadline']
            row['budgetSeconds'] = command.get('budgetSeconds', row['budgetSeconds'])
        while command.get('operation') == 'pause' and not cancel.is_set():
            row['status'] = 'paused'
            _write(row)
            if _budget_expired(row.get('deadline')):
                return True
            cancel.wait(1)
            command = _read_control(run_id)
            if 'deadline' in command:
                row.update(deadline=command['deadline'], budgetSeconds=command.get('budgetSeconds', row['budgetSeconds']))
        if row['status'] == 'paused':
            row['status'] = 'running'
            _write(row)
        if command.get('operation') == 'stop':
            cancel.set()
        return cancel.is_set() or _budget_expired(row.get('deadline'))

    def action(key: str, name: str, fields: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        # Admission and terminal receipts are durable. An uncertain external
        # mutation is blocked after owner death rather than replayed blindly.
        probe = bool(fields.get('_preparationProbe')) or name == 'workbench.merge-evidence'
        from .workflow import input_revision
        identity_parts = [name, fields, input_revision(fields), context.get('locator'), context.get('program'),
                          context.get('slug'), row['checkpoints'].get(context.get('program', ''), {}).get('programFingerprint')]
        if name == 'corpus.match-pair':
            identity_parts.append(_comparison_inventory(str(fields.get('src') or ''), str(fields.get('dst') or ''), comparison_inputs))
        identity = json.dumps(identity_parts, sort_keys=True)
        action_id = hashlib.sha256(identity.encode()).hexdigest()
        history = row.setdefault('actions', {})
        prior = history.get(action_id, {})
        if probe or (prior.get('status') == 'ok' and key in {'facts', 'calibrate-global', 'verify-byte-accuracy'}):
            prior = {}
        if not probe and prior.get('status') == 'ok' and key not in {'facts', 'calibrate-global', 'verify-byte-accuracy'}:
            return prior['result']
        # Inventory and analysis are idempotent under the owning native lock;
        # external subprocess mutations need a recovered terminal receipt.
        safe_replay = name in {'mcp.analyze-program', 'mcp.execute-script'}
        prior_job = jobs.get_job(prior.get('jobId', '')) if prior.get('jobId') else None
        unavailable = prior_job is None or getattr(prior_job, 'history_only', False) or getattr(prior_job, 'owner_unavailable', False) or prior_job.status == 'interrupted'
        if prior.get('status') in {'submitting', 'queued', 'running'} and unavailable and not safe_replay:
            return {'ok': False, 'error': 'interrupted-action: completion of the accepted job is unknown; reconcile its output before resubmission.', 'jobId': prior.get('jobId')}
        if not probe and prior.get('status') == 'failed' and not transient_failure(prior.get('result', {})):
            return prior['result']
        for attempt in range(int(prior.get('attempts', 0)), 3):
            if stopped():
                raise InterruptedError('Workflow stopped or its execution budget was reached.')
            history[action_id] = {'status': 'submitting', 'action': name, 'params': fields, 'target': context.get('program') or context.get('locator'), 'attempts': attempt + 1, 'at': time.time()}
            _write(row)
            response, status = jobs.start_job(name, fields, context=context, confirm=True)
            if status >= 400:
                outcome = {'ok': False, 'error': response.get('error')}
            else:
                job_id = response['job']['id']
                history[action_id].update(status='queued', jobId=job_id)
                checkpoint = row['checkpoints'].get(context.get('program', ''), {})
                row.setdefault('jobTimingContexts', {})[job_id] = {key: checkpoint.get(key) for key in ('architecture', 'ghidraVersion', 'workSize', 'toolchain')}
                row['jobTimingContexts'][job_id].update(actionId=name, createdAt=time.time())
                _write(row)
                target = str(fields.get('programPath') or fields.get('program') or context.get('program') or fields.get('src') or context.get('locator') or '')
                update(key, 'running', f'{name}: {target}' if target else name, jobId=job_id,
                       currentProgram=target, currentAction=name, jobStatus=response['job'].get('status', 'queued'), startedAt=time.time(), attempts=attempt + 1)
                previous_status = None
                wait_limit = float(fields.get('workflowWaitSeconds') or (900 if probe else 0))
                wait_deadline = time.monotonic() + wait_limit if wait_limit else None
                while True:
                    job = jobs.get_job(job_id)
                    progress_path = row.get('functionProgressFile')
                    if progress_path:
                        from .workflow import read_object
                        work_progress = read_object(Path(progress_path))
                        stage = next(item for item in row['stages'] if item['key'] == key)
                        if work_progress and work_progress != stage.get('workProgress'):
                            update(key, 'running', workProgress=work_progress)
                    if stopped():
                        jobs.cancel_job(job_id)
                        update(key, 'cancelling', 'Waiting for the accepted operation to stop before releasing project ownership.')
                        drain_deadline = time.monotonic() + 120
                        while job is not None and job.status in {'queued', 'running', 'cancelling'}:
                            if time.monotonic() > drain_deadline:
                                raise InterruptedError('Workflow stop timed out waiting for child job to cancel.')
                            time.sleep(.25)
                            job = jobs.get_job(job_id)
                        raise InterruptedError('Workflow stopped after its accepted operation drained.')
                    if job is None:
                        outcome = {'ok': False, 'error': 'The accepted stage job is unavailable; output reconciliation is required.', 'jobId': job_id}
                        break
                    if wait_deadline is not None and time.monotonic() >= wait_deadline:
                        jobs.cancel_job(job_id)
                        outcome = {'ok': False, 'error': f'{key}-timeout: the read-only probe exceeded {int(wait_limit)} seconds; it was cancelled before the next program was admitted.', 'jobId': job_id}
                        break
                    if job.status != previous_status:
                        previous_status = job.status
                        history[action_id]['status'] = job.status
                        update(key, 'running', jobStatus=job.status, lastJobUpdateAt=time.time())
                    if job.status not in {'queued', 'running', 'cancelling'}:
                        data = None
                        text = job.log.strip()
                        try:
                            data, _ = json.JSONDecoder().raw_decode(text[text.index('{'):])
                            if isinstance(data, dict) and isinstance(data.get('result'), str):
                                try:
                                    data = json.loads(data['result'])
                                except ValueError:
                                    pass
                        except (ValueError, TypeError):
                            pass
                        row['jobTimingContexts'][job_id].update(status=job.status, startedAt=job.started_at, finishedAt=job.finished_at)
                        outcome = {'ok': job.status == 'ok', 'data': data, 'log': text[-4000:], 'jobId': job_id, 'finishedAt': job.finished_at, 'error': job.error}
                        break
                    cancel.wait(.25)
            history[action_id].update(status='ok' if outcome['ok'] else 'failed', result=outcome)
            _write(row)
            if outcome['ok'] or not transient_failure(outcome) or attempt == 2:
                return outcome
            delay = 2 ** (attempt + 1)
            update(key, 'waiting', f'Temporary service failure. Another attempt follows in {delay} seconds.', attempts=attempt + 1, nextFallback='Retry transient service failure', retryAt=time.time() + delay)
            if cancel.wait(delay):
                raise InterruptedError('Workflow stopped during service backoff.')
        return prior.get('result') or {'ok': False, 'error': 'Transient retry budget exhausted.'}

    try:
        locator, selected = row['locator'], row['program']
        info = inspect_locator(locator) if locator else {'ok': True, 'programs': []}
        if not info.get('ok'):
            raise ValueError(info.get('error') or 'The project could not be inspected.')
        programs = [selected] if selected else [p if isinstance(p, str) else p.get('name') or p.get('path') for p in info.get('programs', [])]
        programs = list(dict.fromkeys(p for p in programs if p))
        if len(programs) > 256:
            raise ValueError('Select at most 256 programs per preparation run.')
        row['programs'] = programs
        update('inspect', 'completed', f'{len(programs)} programs available.', completed=len(programs), total=len(programs))

        protection_blocked = set()
        from .protection import inspect_protection, prepare_protected_binary
        if not programs:
            update('protection', 'completed', 'No programs to prepare.', completed=0, total=0)
            update('analysis', 'blocked', 'No Ghidra program is loaded. Import a binary or open its analyzed project.')
        else:
            prepared = 0
            for program in programs:
                context = {**row, 'program': program}
                checkpoint = row['checkpoints'].setdefault(program, {})
                checkpoint['analysisConfirmed'] = False
                update('protection', 'running', f'Checking protection for {program}.', completed=prepared, total=len(programs))
                # A resumed wave must not spend another Ghidra round-trip on a
                # program whose executable identity and protection observation
                # were already recorded.  The original bytes and the derived
                # image receipt remain in the checkpoint; only an unknown or
                # changed executable needs another read-only probe.
                recorded_protection = checkpoint.get('protection')
                if isinstance(recorded_protection, dict) and checkpoint.get('executablePath'):
                    if recorded_protection.get('handling') == 'blocked':
                        protection_blocked.add(program)
                    prepared += 1
                    update('protection', 'running', f'Reusing recorded protection inspection for {program}.', completed=prepared, total=len(programs))
                    continue
                state = action('protection', 'mcp.execute-script', {
                    'programPath': program, '_preparationProbe': True, 'workflowWaitSeconds': 900, 'code': "import json\nfrom agentdecompile_cli.mcp_utils.program_analysis import program_needs_analysis\nfrom ghidra.framework import Application\n__result__ = json.dumps({'needsAnalysis': program_needs_analysis(currentProgram), 'executablePath': str(currentProgram.getExecutablePath()), 'architecture': str(currentProgram.getLanguageID()), 'ghidraVersion': str(Application.getApplicationVersion()), 'workSize': int(currentProgram.getFunctionManager().getFunctionCount())})"
                }, context)
                payload = state.get('data') or {}
                if not state['ok'] or not isinstance(payload, dict) or 'executablePath' not in payload:
                    protection_blocked.add(program)
                    update('protection', 'blocked', f'Cannot read the executable path for {program}.')
                    continue
                checkpoint.update(executablePath=payload.get('executablePath'), analysisCheckedAt=time.time(),
                                  needsAnalysis=payload.get('needsAnalysis'),
                                  **{key: payload.get(key) for key in ('architecture', 'ghidraVersion', 'workSize')})
                source = payload.get('executablePath') or ''
                observed = inspect_protection(source)
                if observed.get('status') != 'detected':
                    checkpoint['protection'] = observed
                    prepared += 1
                    update('protection', 'running', f'{program}: no protection detected.', completed=prepared, total=len(programs))
                    continue
                prior = checkpoint.get('protection') or {}
                if prior.get('handling') == 'unpacked' and prior.get('receiptPath') and Path(prior['receiptPath']).is_file():
                    checkpoint['protection'] = prior
                    protection_blocked.add(program)
                    prepared += 1
                    continue
                derived = prepare_protected_binary(source, live_root() or _directory())
                checkpoint['protection'] = derived
                if derived.get('handling') == 'blocked':
                    protection_blocked.add(program)
                    reason = derived.get('reason') or derived.get('blocker') or 'protection-unavailable'
                    update('protection', 'blocked', f'{program}: {reason}')
                    continue
                protection_blocked.add(program)
                prepared += 1
                update('protection', 'running', f'{program}: prepared analysis image.', completed=prepared, total=len(programs))
            if prepared == len(programs):
                update('protection', 'completed', f'{prepared} of {len(programs)} programs have an analysis image.', completed=prepared, total=len(programs))
            elif prepared:
                update('protection', 'partial', f'{prepared} of {len(programs)} programs have an analysis image.', completed=prepared, total=len(programs))
            else:
                update('protection', 'blocked', next((item.get('reason') or 'protection-unavailable' for item in row['stages'] if item['key'] == 'protection' and item.get('reason')), 'protection-unavailable'), completed=0, total=len(programs))

            analyzed = 0
            for program in programs:
                if program in protection_blocked:
                    continue
                context = {**row, 'program': program}
                checkpoint = row['checkpoints'].setdefault(program, {})
                update('analysis', 'running', f'Checking existing analysis for {program}.', completed=analyzed, total=len(programs))
                if checkpoint.get('analysisConfirmed') and checkpoint.get('needsAnalysis') is False:
                    analyzed += 1
                    update('analysis', 'running', f'Reusing completed analysis for {program}.', completed=analyzed, total=len(programs))
                    continue
                if 'needsAnalysis' not in checkpoint:
                    state = action('analysis', 'mcp.execute-script', {
                    'programPath': program, '_preparationProbe': True, 'workflowWaitSeconds': 900, 'code': "import json\nfrom agentdecompile_cli.mcp_utils.program_analysis import program_needs_analysis\nfrom ghidra.framework import Application\n__result__ = json.dumps({'needsAnalysis': program_needs_analysis(currentProgram), 'executablePath': str(currentProgram.getExecutablePath()), 'architecture': str(currentProgram.getLanguageID()), 'ghidraVersion': str(Application.getApplicationVersion()), 'workSize': int(currentProgram.getFunctionManager().getFunctionCount())})"
                    }, context)
                    payload = state.get('data') or {}
                    if not state['ok'] or not isinstance(payload, dict) or 'needsAnalysis' not in payload:
                        update('analysis', 'blocked', f'Cannot determine existing analysis for {program}; analysis was not rerun.')
                        continue
                    checkpoint.update(executablePath=payload.get('executablePath'), analysisCheckedAt=time.time(),
                                      needsAnalysis=payload.get('needsAnalysis'),
                                      **{key: payload.get(key) for key in ('architecture', 'ghidraVersion', 'workSize')})
                if checkpoint.get('needsAnalysis') is False:
                    checkpoint['analysisConfirmed'] = True
                    analyzed += 1
                    update('analysis', 'running', f'Reusing completed analysis for {program}.', completed=analyzed, total=len(programs))
                    continue
                result = action('analysis', 'mcp.analyze-program', {'programPath': program}, context)
                if result['ok'] or (result.get('data') or {}).get('alreadyAnalyzed'):
                    checkpoint.update(analysisConfirmed=True, analysisCheckedAt=time.time(), needsAnalysis=False)
                    analyzed += 1
                else:
                    update('analysis', 'blocked', result.get('error') or result.get('log') or f'Analysis failed for {program}.')
            if analyzed == len(programs):
                update('analysis', 'completed', f'{analyzed} of {len(programs)} programs have analysis available.', completed=analyzed, total=len(programs))
            else:
                update('analysis', 'partial', f'{analyzed} of {len(programs)} programs have analysis available.', completed=analyzed, total=len(programs))

        # Use the canonical extractor and persistence functions in the live JVM.
        # A nonempty inventory is never replaced by automatic preparation.
        extracted = 0
        for program in programs:
            if program in protection_blocked or not row['checkpoints'].get(program, {}).get('analysisConfirmed'):
                continue
            checkpoint = row['checkpoints'].setdefault(program, {})
            facts_path = _directory() / f"{run_id}-{hashlib.sha256(program.encode()).hexdigest()[:12]}.facts"
            checkpoint.pop('programFingerprint', None)
            config = {'db': str(live_db()), 'locator': locator, 'program': program,
                      'slug': row['slug'] if len(programs) == 1 else '', 'factsPath': str(facts_path)}
            code = _inventory_script(config)
            result = action('facts', 'mcp.execute-script', {'programPath': program, 'code': code, 'timeout': 600}, {**row, 'program': program})
            payload = result.get('data') or {}
            if result['ok'] and isinstance(payload, dict) and payload.get('inventoryAvailable'):
                checkpoint.update(factsComplete=True, factsPath=str(facts_path), binaryId=payload['binaryId'], slug=payload['slug'], repoPath=payload['repoPath'], programFingerprint=payload.get('programFingerprint'), arch=payload.get('arch'), workSize=payload.get('count'))
                extracted += 1
                update('facts', 'running', f"{program}: {payload['count']} stored functions available.", completed=extracted, total=len(programs))
            else:
                update('facts', 'partial', result.get('error') or result.get('log') or f'{program}: feature extraction failed; existing corpus observations preserved.', completed=extracted, total=len(programs))
        update('facts', 'completed' if extracted == len(programs) and programs else 'partial', f'{extracted} programs have stored feature inventories.', completed=extracted, total=len(programs))
        records, error = query_db('SELECT id,slug,repo_path,game,func_count FROM binary WHERE EXISTS (SELECT 1 FROM func WHERE func.binary_id=binary.id)')
        records = records if not error else []
        prepared_ids = {c.get('binaryId') for program, c in row['checkpoints'].items() if program in programs and c.get('analysisConfirmed') and c.get('factsComplete')}
        candidates = [r for r in records if r[0] in prepared_ids]

        # A workspace-wide BSim database makes cross-build comparison possible.
        # Signature XML and receipts remain isolated by program and fingerprint.
        if programs and locator:
            committed = 0
            for program in programs:
                if program in protection_blocked:
                    continue
                if stopped():
                    raise InterruptedError('Preparation stopped before signature generation.')
                checkpoint = row['checkpoints'].setdefault(program, {})
                configured = os.environ.get('AGENT_DECOMPILE_BSIM_URL', '').strip()
                fingerprint = checkpoint.get('programFingerprint') or ''
                identity = hashlib.sha256(json.dumps([locator, program, fingerprint]).encode()).hexdigest()[:24]
                bsim_file = _directory().parent / 'bsim' / 'corpus' / 'signatures'
                bsim_file.parent.mkdir(parents=True, exist_ok=True)
                bsim_url = configured or f'file:{bsim_file}'
                program_dir = bsim_file.parent / 'programs' / identity
                program_dir.mkdir(parents=True, exist_ok=True)
                receipt = program_dir / 'ingest.json'
                while not _BSIM_LOCK.acquire(timeout=.25):
                    if stopped():
                        raise InterruptedError('Preparation stopped while waiting for similarity indexing.')
                try:
                    database_receipt = bsim_file.parent / 'created.json'
                    database_exists = bsim_file.exists() or Path(str(bsim_file) + '.mv.db').exists()
                    ready = bool(configured) or (database_receipt.exists() and database_exists)
                    if ready and fingerprint and receipt.exists():
                        try:
                            prior = json.loads(receipt.read_text())
                        except (OSError, ValueError):
                            prior = {}
                        if prior.get('status') == 'committed' and prior.get('url') == bsim_url and prior.get('programFingerprint') == fingerprint:
                            checkpoint.update(bsimComplete=True, bsimUrl=bsim_url, bsimReceipt=str(receipt), bsimFingerprint=fingerprint)
                            committed += 1
                            update('bsim', 'running', f'{program}: reusing indexed signatures for this fingerprint.', completed=committed, total=len(programs))
                            continue
                    if not ready:
                        created = action('bsim', 'corpus.bsim-createdatabase', {'bsim-url': bsim_url}, row)
                        ready = created['ok']
                        if ready:
                            database_receipt.write_text(json.dumps({'url': bsim_url, 'at': time.time()}))
                        else:
                            update('bsim', 'partial', created.get('error') or created.get('log') or 'Could not create the similarity database.')
                    if ready:
                        signature_dir = program_dir / 'xml'
                        generated = action('bsim', 'mcp.execute-script', {'programPath': program, 'code': _signature_script({'url': bsim_url, 'directory': str(signature_dir), 'locator': locator, 'template': '' if configured else 'medium_nosize'}), 'timeout': 1200}, {**row, 'program': program})
                        if generated['ok'] and (generated.get('data') or {}).get('signatureCount', 0) > 0:
                            result = action('bsim', 'workbench.commit-signatures', {'bsimUrl': bsim_url, 'signatureDirectory': str(signature_dir)}, row)
                        else:
                            result = {**generated, 'ok': False, 'error': generated.get('error') or generated.get('log') or 'No signatures were generated.'}
                        if result['ok']:
                            receipt.write_text(json.dumps({'program': program, 'status': 'committed', 'url': bsim_url, 'at': time.time(), 'programFingerprint': (generated.get('data') or {}).get('programFingerprint'), 'generation': generated.get('data')}))
                        if result['ok']:
                            checkpoint.update(bsimComplete=True, bsimUrl=bsim_url, bsimReceipt=str(receipt), bsimFingerprint=(generated.get('data') or {}).get('programFingerprint'))
                            committed += 1
                        update('bsim', 'running', f'{program}: signatures indexed.' if result['ok'] else f'{program}: {result.get("error") or result.get("log") or "signature generation failed"}', completed=committed, total=len(programs))
                finally:
                    _BSIM_LOCK.release()
            update('bsim', 'completed' if committed == len(programs) else 'partial', completed=committed, total=len(programs))
        else:
            update('bsim', 'blocked', 'Open the program project to generate similarity signatures.')

        from agentdecompile_recovery.corpus.corpus_config import load_match_pairs
        pairs = load_match_pairs()
        source_paths = {item[2] for item in candidates}
        pairs = [pair for pair in pairs if pair[0] in source_paths or pair[1] in source_paths]
        # Project membership selects the sources; stored corpus evidence supplies
        # comparison candidates even when the project has only one binary.
        # Similar inventory size only orders work, never establishes a relation.
        project_candidates = [item for item in candidates if item[4]]
        for src in sorted(project_candidates, key=lambda item: item[0]):
            peers = sorted((dst for dst in records if dst[0] != src[0] and dst[4]),
                           key=lambda dst: (abs(int(dst[4]) - int(src[4])), dst[0]))
            pairs += [(src[2], dst[2], 'workspace feature inventory; relationship unproven until comparison') for dst in peers]
        unique_pairs = {}
        for src, dst, note in pairs:
            if src != dst:
                key = (src, dst)
                unique_pairs.setdefault(key, (src, dst, note))
        pairs = list(unique_pairs.values())
        row['comparisonTargets'] = [{'source': src, 'target': dst, 'reason': note} for src, dst, note in pairs]
        row['comparisonTargetsFrozenAt'] = time.time()
        def input_progress(completed: int, total: int, source: str = '', functions_read: int = 0) -> None:
            if stopped():
                raise InterruptedError('Workflow stopped while reading comparison inputs.')
            detail = f' {Path(source).name}: {functions_read:,} functions read.' if source else ''
            update('matching', 'running', f'Reading comparison evidence: {completed} of {total} inventories.{detail}',
                   completed=completed, total=total, progressUnit='binary inventories',
                   currentProgram=programs[0] if len(programs) == 1 else '',
                   workProgress={'completed': completed, 'total': total, 'unit': 'binary inventories'})
        comparison_inputs.update(_matching_input_digests({path for src, dst, _ in pairs for path in (src, dst)}, input_progress))
        row['comparisonInputs'] = comparison_inputs
        update('matching', 'running', 'Comparison targets and input evidence frozen.', completed=0, total=len(pairs), progressUnit='comparisons', workProgress=None)
        _write(row)
        if not pairs:
            update('matching', 'blocked', 'No other binary has stored function features to compare. Import or analyze a comparison binary.')
        else:
            matched = 0
            admitted = 0
            deferred = 0
            for src, dst, note in pairs:
                existing = read_comparison_receipt(run_id, src, dst, comparison_inputs)
                if existing:
                    matched += 1
                    update('matching', 'running', f'Reusing completed comparison receipt: {Path(src).name} → {Path(dst).name}.', completed=matched, total=len(pairs))
                    continue
                admitted += 1
                result = action('matching', 'corpus.match-pair', {'db': str(live_db()), 'src': src, 'dst': dst, 'run': f'prepare-{run_id}', 'note': note}, row)
                if result['ok']:
                    record_comparison_receipt(run_id, src, dst, result, comparison_inputs)
                    matched += 1
                update('matching', 'running', result.get('error') or f'{Path(src).name} → {Path(dst).name}: {"compared" if result["ok"] else "failed"}.', completed=matched, total=len(pairs))
            update('matching', 'completed' if matched == len(pairs) else 'partial', f'{matched} of {len(pairs)} pairs compared. {deferred} comparisons await admission.' if deferred else f'{matched} of {len(pairs)} pairs compared.', completed=matched, total=len(pairs), deferred=deferred)
        if pairs and matched:
            merged = action('matching', 'workbench.merge-evidence', {'db': str(live_db()), 'run': f'prepare-{run_id}'}, row)
            update('matching', 'completed' if merged['ok'] and matched == len(pairs) else 'partial', 'Compared identities bound; existing human metadata retained.' if merged['ok'] else merged.get('error') or 'Knowledge binding could not finish.', completed=matched, total=len(pairs))
        from .workflow import continue_recovery
        continue_recovery(row, _directory().parent, live_db(), action, update)
        row['status'] = 'completed' if all(stage['status'] == 'completed' for stage in row['stages']) else 'partial'
    except InterruptedError as exc:
        row.update(status='cancelled' if cancel.is_set() else 'budget-stop', error=str(exc))
    except Exception as exc:
        row.update(status='blocked', error=str(exc))
    finally:
        with _LOCK:
            for stage in row['stages']:
                if stage['status'] in {'running', 'queued', 'waiting', 'cancelling'}:
                    stage.update(status='blocked', reason=row.get('error') or 'A prerequisite prevented this stage from running.')
            _write(row)
            _ACTIVE.discard(run_id)
            _release_lease(run_id)
            _ADMISSION_WAKE.set()
    return (0 if row['status'] in {'completed', 'partial'} else 1), json.dumps(row, indent=2)


def _inventory_script(config: dict[str, Any]) -> str:
    """Generate orchestration only; feature extraction remains in corpus.extract."""
    return "import json\nconfig = json.loads(" + repr(json.dumps(config)) + ")\n" + r"""
from pathlib import Path
import time
from agentdecompile_recovery.corpus.store import connect
from agentdecompile_recovery.corpus.extract import functions_from_program, upsert_binary, persist_functions, slugify
from ghidra.util.task import TimeoutTaskMonitor
from java.util.concurrent import TimeUnit
monitor = TimeoutTaskMonitor.timeoutIn(600, TimeUnit.SECONDS)
con = connect(config['db'])
try:
    con.execute('BEGIN IMMEDIATE')
    selected = con.execute('SELECT id,slug,repo_path FROM binary WHERE slug=?', (config['slug'],)).fetchone() if config['slug'] else None
    if selected is not None and str(selected[2]).rstrip('/') == config['locator'].rstrip('/'):
        # A project tab's slug identifies the container, not its first program.
        selected = None
    repo = config['locator'].rstrip('/') + '/' + config['program'].lstrip('/')
    if selected is None:
        selected = con.execute('SELECT id,slug,repo_path FROM binary WHERE repo_path=?', (repo,)).fetchone()
    if selected is None:
        executable = str(currentProgram.getExecutablePath())
        selected = con.execute('SELECT id,slug,repo_path FROM binary WHERE repo_path=?', (executable,)).fetchone()
    if selected is None:
        fingerprint = str(currentProgram.getExecutableMD5())
        columns = {column[1] for column in con.execute('PRAGMA table_info(binary)')}
        if 'md5' in columns and len(fingerprint) == 32 and all(c in '0123456789abcdefABCDEF' for c in fingerprint):
            matching = con.execute('SELECT id,slug,repo_path FROM binary WHERE lower(md5)=lower(?)', (fingerprint,)).fetchall()
            if len(matching) == 1:
                selected = matching[0]
            elif len(matching) > 1:
                raise ValueError('More than one registered build has this executable fingerprint. Select its registered binary before preparing.')
    if selected is None:
        binary_id = upsert_binary(con, repo_path=repo, slug=slugify(repo), program=currentProgram)
        selected = con.execute('SELECT id,slug,repo_path FROM binary WHERE id=?', (binary_id,)).fetchone()
    binary_id, slug, repo = tuple(selected)
    previous_md5 = con.execute('SELECT md5 FROM binary WHERE id=?', (binary_id,)).fetchone()[0]
    current_md5 = str(currentProgram.getExecutableMD5())
    if previous_md5 and current_md5 and str(previous_md5).lower() != current_md5.lower():
        raise ValueError('Selected corpus build has a different executable fingerprint. Select the matching build before indexing.')
    # Registration precedes analysis. Refresh measured program metadata even
    # when the roster row already exists, retaining operator classification.
    classification = con.execute('SELECT game,platform,variant,role FROM binary WHERE id=?', (binary_id,)).fetchone()
    upsert_binary(con, repo_path=repo, slug=slug, program=currentProgram,
                  meta=dict(zip(('game', 'platform', 'variant', 'role'), classification)))
    con.execute('CREATE TABLE IF NOT EXISTS program_binding (source_path TEXT NOT NULL, locator TEXT NOT NULL, program TEXT NOT NULL, updated REAL NOT NULL, PRIMARY KEY(source_path,locator))')
    con.execute('INSERT INTO program_binding VALUES(?,?,?,?) ON CONFLICT(source_path,locator) DO UPDATE SET program=excluded.program,updated=excluded.updated', (repo, config['locator'], config['program'], time.time()))
    con.commit()
    count = con.execute('SELECT COUNT(*) FROM func WHERE binary_id=?', (binary_id,)).fetchone()[0]
    reused = bool(count)
    if not count:
        functions = functions_from_program(currentProgram, monitor)
        monitor.checkCancelled()
        con.execute('BEGIN IMMEDIATE')
        # Another worker may have populated or curated this build during extraction.
        count = con.execute('SELECT COUNT(*) FROM func WHERE binary_id=?', (binary_id,)).fetchone()[0]
        if not count:
            count = persist_functions(con, binary_id, functions)
        else:
            reused = True
            con.rollback()
    receipt = {'binaryId': binary_id, 'slug': slug, 'repoPath': repo, 'count': count,
               'inventoryAvailable': count > 0, 'reused': reused, 'claim': 'advisory',
               'tool': 'corpus.extract.functions_from_program', 'program': config['program'],
               'programFingerprint': str(currentProgram.getExecutableMD5()), 'arch': str(currentProgram.getLanguageID())}
    target = Path(config['factsPath'])
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix('.tmp')
    temporary.write_text(json.dumps(receipt), encoding='utf-8')
    temporary.replace(target)
    __result__ = json.dumps(receipt)
finally:
    con.close()
"""


def _signature_script(config: dict[str, Any]) -> str:
    """Mirror Ghidra BulkSignatures on the already-owned currentProgram."""
    return "import json\nconfig = json.loads(" + repr(json.dumps(config)) + ")\n" + r"""
from pathlib import Path
from java.net import URL
from java.io import FileWriter
from ghidra.features.bsim.query import BSimClientFactory, FunctionDatabase, GenSignatures
from ghidra.util.task import TimeoutTaskMonitor
from java.util.concurrent import TimeUnit
monitor = TimeoutTaskMonitor.timeoutIn(1200, TimeUnit.SECONDS)
client = None
generator = None
try:
    if config.get('template'):
        configuration = FunctionDatabase.loadConfigurationTemplate(config['template'])
        info = configuration.info
        vectors = FunctionDatabase.generateLSHVectorFactory()
        vectors.set(configuration.weightfactory, configuration.idflookup, info.settings)
    else:
        client = BSimClientFactory.buildClient(URL(config['url']), False)
        if not client.initialize():
            raise RuntimeError(str(client.getLastError().message))
        info = client.getInfo()
        vectors = client.getLSHVectorFactory()
    generator = GenSignatures(True)
    generator.setVectorFactory(vectors)
    generator.addExecutableCategories(info.execats)
    generator.addFunctionTags(info.functionTags)
    generator.addDateColumnName(info.dateColumnName)
    repository = config['locator']
    if not repository.startswith('ghidra:'):
        project_path = Path(repository)
        if project_path.suffix.lower() == '.gpr':
            project_path = project_path.with_suffix('')
        repository = 'ghidra:' + str(project_path)
    generator.openProgram(currentProgram, None, None, None, repository, GenSignatures.getPathFromDomainFile(currentProgram))
    functions = currentProgram.getFunctionManager()
    generator.scanFunctions(functions.getFunctions(True), functions.getFunctionCount(), monitor)
    descriptions = generator.getDescriptionManager()
    count = int(descriptions.numFunctions())
    if count == 0:
        raise RuntimeError('The program produced no similarity signatures.')
    md5 = str(currentProgram.getExecutableMD5())
    if len(md5) != 32 or any(c not in '0123456789abcdefABCDEF' for c in md5):
        raise RuntimeError('A valid executable MD5 is required for BSim signature import.')
    directory = Path(config['directory'])
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / ('sigs_' + md5)
    temporary = target.with_suffix('.tmp')
    writer = FileWriter(str(temporary))
    try:
        descriptions.saveXml(writer)
    finally:
        writer.close()
    temporary.replace(target)
    __result__ = json.dumps({'signatureCount': count, 'path': str(target), 'program': str(currentProgram.getName()), 'programFingerprint': md5, 'claim': 'advisory'})
finally:
    if generator is not None:
        generator.dispose()
    if client is not None:
        client.close()
"""


def _comparison_path(run_id: str, src: str, dst: str) -> Path:
    if len(run_id) != 32 or any(c not in '0123456789abcdef' for c in run_id):
        raise ValueError('Invalid preparation ID')
    key = hashlib.sha256(json.dumps([str(live_db()), src, dst]).encode()).hexdigest()
    return _directory() / 'comparisons' / run_id / (key + '.json')


def _matching_input_digests(paths: set[str], progress: Any = None) -> dict[str, Any]:
    """Hash matcher inputs once per binary per wave, in one SQLite snapshot."""
    if not paths:
        return {}
    result = {}
    if progress:
        progress(0, len(paths))
    with sqlite3.connect(f'{Path(live_db()).resolve().as_uri()}?mode=ro', uri=True) as con:
        con.row_factory = sqlite3.Row
        con.execute('BEGIN')
        available = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for source in sorted(paths):
            if progress:
                progress(len(result), len(paths), source, 0)
            binary = con.execute('SELECT * FROM binary WHERE repo_path=?', (source,)).fetchone()
            if binary is None:
                result[source] = {'source': source, 'state': 'missing'}
                if progress:
                    progress(len(result), len(paths))
                continue
            digest = hashlib.sha256()
            count = 0
            def add(value: Any) -> None:
                digest.update(json.dumps(value, sort_keys=True, separators=(',', ':'), default=str).encode())
                digest.update(b'\n')
            add({'schema': 'matcher-input-v1', 'binary': dict(binary)})
            for row in con.execute('SELECT * FROM func WHERE binary_id=? ORDER BY addr,id', (binary['id'],)):
                add({'func': dict(row)})
                count += 1
                if progress and count % 5000 == 0:
                    progress(len(result), len(paths), source, count)
            if 'calledge' in available:
                for row in con.execute('SELECT caller_addr,callee_addr FROM calledge WHERE binary_id=? ORDER BY caller_addr,callee_addr', (binary['id'],)):
                    add({'edge': list(row)})
            if 'decomp' in available:
                for row in con.execute('SELECT addr,n_tokens,n_lines,max_nest,n_calls,n_locals,n_deref,n_index,n_field,ctrl,ops,skeleton_hash FROM decomp WHERE binary_id=? AND ok=1 ORDER BY addr', (binary['id'],)):
                    add({'decomp': dict(row)})
            result[source] = {'source': source, 'schema': 'matcher-input-v1', 'digest': digest.hexdigest(), 'functionCount': count, 'md5': binary['md5']}
            if progress:
                progress(len(result), len(paths))
    return result


def _comparison_inventory(src: str, dst: str, inputs: dict[str, Any] | None = None) -> list[Any]:
    if inputs is not None:
        return [inputs.get(path, {'source': path, 'state': 'missing'}) for path in (src, dst)]
    rows, error = query_db(
        'SELECT b.repo_path,b.md5,COUNT(f.id) FROM binary b LEFT JOIN func f ON f.binary_id=b.id '
        'WHERE b.repo_path IN (?,?) GROUP BY b.id ORDER BY b.repo_path', (src, dst))
    if error:
        raise ValueError(error)
    return [list(row) for row in rows]


def record_comparison_receipt(run_id: str, src: str, dst: str, result: dict[str, Any], inputs: dict[str, Any] | None = None) -> None:
    """Persist a completed shared job, with no byte-verification claim."""
    if not result.get('ok') or not result.get('jobId'):
        raise ValueError('A completed comparison job is required.')
    path = _comparison_path(run_id, src, dst)
    path.parent.mkdir(parents=True, exist_ok=True)
    receipt = {'preparationId': run_id, 'db': str(live_db()), 'source': src, 'target': dst,
               'jobId': result['jobId'], 'jobStatus': 'ok', 'completedAt': result.get('finishedAt'),
               'result': result.get('data'), 'claim': 'advisory', 'scope': 'completed-pair-comparison',
               'inventory': _comparison_inventory(src, dst, inputs),
               'freshnessLimit': 'Inputs are frozen once per matching wave. Later changes to function metadata, features, call edges, or decompilation metrics invalidate reuse on the next wave.'}
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(receipt), encoding='utf-8')
    temporary.replace(path)


def read_comparison_receipt(run_id: str, src: str, dst: str, inputs: dict[str, Any] | None = None) -> dict[str, Any] | None:
    try:
        receipt = json.loads(_comparison_path(run_id, src, dst).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return None
    if receipt.get('jobStatus') != 'ok' or receipt.get('source') != src or receipt.get('target') != dst or receipt.get('db') != str(live_db()) or receipt.get('preparationId') != run_id:
        return None
    if receipt.get('inventory') != _comparison_inventory(src, dst, inputs):
        return None
    return receipt


def _control_path(run_id: str) -> Path:
    if len(run_id) != 32 or any(c not in '0123456789abcdef' for c in run_id):
        raise ValueError('Invalid preparation ID')
    directory = _directory() / 'controls'
    directory.mkdir(exist_ok=True)
    return directory / (run_id + '.json')


def _read_control(run_id: str) -> dict[str, Any]:
    try:
        value = json.loads(_control_path(run_id).read_text())
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def control(params: dict[str, Any]) -> dict[str, Any]:
    """Shared pause/stop/budget controls, independent of the browser lifecycle."""
    run_id = str(params.get('preparation_id') or '')
    operation = str(params.get('operation') or '')
    if operation not in {'pause', 'resume', 'stop', 'budget', 'priority'}:
        raise ValueError('Choose pause, resume, stop, budget, or priority.')
    with _LOCK:
        row = _read(run_id)
        command = _read_control(run_id)
        if operation == 'priority':
            value = params.get('priority')
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100:
                raise ValueError('Priority must be an integer from 0 to 100; higher values run first.')
            command.update(priority=value, priorityReason=f'Operator priority {value}; applies to waiting admission, without interrupting active work.')
        elif operation == 'budget':
            value = params.get('seconds')
            if params.get('unlimited') is True:
                value = None
            if 'seconds' not in params and params.get('unlimited') is not True:
                raise ValueError('Supply seconds:null for unlimited, or 1 to 604800 seconds.')
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_BUDGET_SECONDS):
                raise ValueError('Budget must be null for unlimited, or 1 to 604800 seconds.')
            command.update(deadline=time.time() + value if value is not None else None, budgetSeconds=value, budgetOrigin='explicit')
        else:
            command['operation'] = operation
        command['updatedAt'] = time.time()
        path = _control_path(run_id)
        temporary = path.with_name(path.name + f'.{os.getpid()}.{threading.get_ident()}.tmp')
        temporary.write_text(json.dumps(command))
        temporary.replace(path)
        _ADMISSION_WAKE.set()
    # Pause takes effect between stages. An accepted native operation is allowed
    # to drain; releasing its project lock early would risk duplicated mutations.
    may_resume = operation == 'resume' or (operation == 'budget' and row['status'] == 'budget-stop' and command.get('operation') not in {'pause', 'stop'})
    if may_resume and run_id not in _ACTIVE and (not _owner_alive(row) or row['status'] not in {'running', 'queued', 'paused'}):
        if 'deadline' in command:
            row.update(deadline=command['deadline'], budgetSeconds=command.get('budgetSeconds'))
            _write(row)
        return submit({key: row.get(key, '') for key in ('locator', 'program', 'slug')}, resume=True)
    return {**row, 'deadline': command.get('deadline', row.get('deadline')), 'budgetSeconds': command.get('budgetSeconds', row.get('budgetSeconds')), 'queuePriority': command.get('priority', row.get('queuePriority', 50)), 'priorityReason': command.get('priorityReason', 'FIFO among projects with equal priority.'), 'control': command, 'controlAcknowledged': True}


def recover_interrupted() -> list[dict[str, Any]]:
    """Resume admissions whose owner is confirmed dead; never touch live owners."""
    recovered = []
    with _LOCK:
        _start_admission_worker()
    for row in sorted(list_runs(), key=_admission_order):
        if row.get('supersededBy') or row.get('status') != 'interrupted' or _owner_alive(row):
            continue
        if _read_control(row['id']).get('operation') in {'pause', 'stop'}:
            continue
        if _budget_expired(row.get('deadline')):
            continue
        recovered.append(submit({key: row.get(key, '') for key in ('locator', 'program', 'slug')}, resume=True, _admit=True))
    return recovered
