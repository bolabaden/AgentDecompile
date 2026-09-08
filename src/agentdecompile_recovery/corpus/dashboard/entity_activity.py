"""Evidence-scoped activity snapshots and resumable, durable event cursors.

This is a read model: it never starts analysis, changes names, or promotes proof.
The journal retains snapshots and timing observations across server restarts.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import math
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse

from .common import live_root, query_db

_LOCK = threading.RLock()
_LIBRARY: tuple[str, float, dict] = ('', 0, {})
_ACTIVE = {'running', 'queued', 'cancelling', 'waiting'}
PROOF_KINDS = frozenset({'recorded-proof', 'verified'})
HUMAN_ORIGINS = frozenset({'human', 'human-authored', 'user_defined', 'user', 'manual'})


def add_facet(entity: dict, facet: dict) -> None:
    """Keep every evidence kind. A later job must not replace STABS or names."""
    kind = str(facet.get('kind') or '')
    label = str(facet.get('label') or '')
    if not kind:
        return
    for existing in entity.setdefault('facets', []):
        if existing.get('kind') == kind and existing.get('label') == label:
            return
    entity['facets'].append(facet)


def origin_evidence(origin: Any, logical_id: Any = None) -> list[dict]:
    """Name origin, STABS, and identity are independent chips."""
    rows: list[dict] = []
    text = str(origin or '')
    lowered = text.lower()
    if lowered in HUMAN_ORIGINS:
        rows.append({'kind': 'human', 'label': 'Human name', 'source': 'func.name_origin'})
    if 'stabs' in lowered:
        rows.append({'kind': 'debug', 'label': 'STABS name', 'source': 'func.name_origin'})
    if logical_id not in (None, ''):
        rows.append({'kind': 'match', 'label': 'Cross-match recorded', 'source': 'identity.logical_id'})
    if text and not rows:
        rows.append({'kind': 'context', 'label': text, 'source': 'func.name_origin'})
    return rows


def attach_dimensions(entity: dict) -> dict:
    """Split activity, evidence, and proof. None of them owns the others."""
    facets = list(entity.get('facets') or [])
    evidence = [facet for facet in facets if facet.get('kind') not in PROOF_KINDS]
    proof = [facet for facet in facets if facet.get('kind') in PROOF_KINDS]
    for receipt in entity.get('proofReceipts') or []:
        row = {
            'kind': 'recorded-proof',
            'label': receipt.get('label') or 'Recorded receipt',
            'source': receipt.get('path') or receipt.get('href') or '',
        }
        if not any(item.get('source') == row['source'] and item.get('label') == row['label'] for item in proof):
            proof.append(row)
    entity['evidence'] = evidence
    entity['proof'] = proof
    entity.setdefault('protection', entity.get('protection') or {})
    entity['activity'] = {
        'status': entity.get('status') or 'idle',
        'stage': entity.get('stage') or 'Not queued',
        'action': entity.get('action') or '',
        'target': entity.get('target') or '',
        'jobId': entity.get('jobId'),
        'progress': entity.get('progress'),
        'eta': entity.get('eta'),
        'queue': entity.get('queue'),
        'error': entity.get('error') or '',
        'startedAt': entity.get('startedAt'),
        'updatedAt': entity.get('updatedAt'),
        'attempts': entity.get('attempts'),
        'nextFallback': entity.get('nextFallback'),
        'dependencies': entity.get('dependencies') or [],
        'budgetRemainingSeconds': entity.get('budgetRemainingSeconds'),
        'proofReceipts': entity.get('proofReceipts') or [],
    }
    return entity


def _journal() -> sqlite3.Connection:
    root = live_root()
    if root is None:
        raise ValueError('Configure a workspace to see durable activity.')
    root.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(root / 'workbench-activity.sqlite', timeout=10)
    con.execute('PRAGMA journal_mode=WAL')
    con.execute('CREATE TABLE IF NOT EXISTS activity_event (revision INTEGER PRIMARY KEY AUTOINCREMENT, scope TEXT NOT NULL, digest TEXT NOT NULL, payload TEXT NOT NULL, created REAL NOT NULL)')
    con.execute('CREATE INDEX IF NOT EXISTS activity_scope ON activity_event(scope,revision)')
    con.execute('CREATE TABLE IF NOT EXISTS activity_observation (job_id TEXT PRIMARY KEY, signature TEXT NOT NULL, duration REAL NOT NULL, finished REAL NOT NULL)')
    con.execute('CREATE INDEX IF NOT EXISTS activity_observation_signature ON activity_observation(signature,finished)')
    return con


def canonical_address(value: Any) -> str:
    if value is None or value == '':
        return ''
    try:
        return f'0x{(value if isinstance(value, int) else int(str(value), 16)):08x}'
    except (TypeError, ValueError):
        return str(value)


def _progress(status: str, completed: Any = None, total: Any = None) -> dict:
    measured = (isinstance(completed, (int, float)) and not isinstance(completed, bool)
                and isinstance(total, (int, float)) and not isinstance(total, bool)
                and math.isfinite(completed) and math.isfinite(total) and total > 0 and 0 <= completed <= total)
    kind = 'measured' if measured else 'indeterminate' if status == 'running' else 'unknown'
    return {'kind': kind, 'completed': completed if measured else None, 'total': total if measured else None}


def _unknown_eta(status: str) -> dict:
    label, basis = {
        'running': ('Estimating', 'Need five completed comparable operations before estimating remaining time.'),
        'queued': ('Waiting for worker', 'Execution has not started; the scheduler controls admission.'),
        'waiting': ('Waiting for dependency', 'A required preceding operation has not completed.'),
        'blocked': ('Waiting for prerequisite', 'The named prerequisite must be resolved before work can advance.'),
        'partial': ('Waiting for prerequisite', 'Useful work is retained; remaining stages have named prerequisites.'),
        'paused': ('Paused', 'Work is paused; elapsed budget and completion estimates are separate.'),
        'budget-stop': ('Budget exhausted', 'A new execution allowance is required before more work can be admitted.'),
        'cancelled': ('Stopped', 'No completion estimate applies to stopped work.'),
        'failed': ('ETA unavailable', 'The recorded failure must be resolved before estimating completion.'),
        'interrupted': ('Awaiting recovery', 'The workflow owner must recover its checkpoint before work can advance.'),
    }.get(status, ('ETA unavailable', 'No active operation is recorded for this entity.'))
    return {'lowerSeconds': None, 'upperSeconds': None, 'observations': 0, 'label': label, 'basis': basis}


def _journal_scope(locator: str, slug: str, program: str = '') -> str:
    if program:
        return json.dumps([locator, slug, program])
    return json.dumps([locator, slug])


def _program_bound(entity: dict, program: str) -> bool:
    needle = str(program or '').lstrip('/')
    if not needle:
        return False
    return any(str(binding.get('program') or '').lstrip('/') == needle for binding in entity.get('projectBindings') or [])


def _binary_selected(entity: dict, slug: str, program: str) -> bool:
    if slug and slug in (entity.get('aliasSlugs') or [entity.get('slug')]):
        return True
    return bool(program) and _program_bound(entity, program)


def _queue(params: dict, status: str) -> dict:
    rank = params.get('queuePosition')
    position = rank if isinstance(rank, int) and not isinstance(rank, bool) else None
    reason = params.get('priorityReason') or (
        'This job is waiting its turn.' if status == 'queued' else 'No admitted queue entry')
    return {'position': position, 'reason': reason}


def _signature(job: dict, binary: dict | None) -> str | None:
    params = job.get('params') or {}
    arch = params.get('architecture') or params.get('arch') or (binary or {}).get('arch')
    toolchain = params.get('compilerProfile') or params.get('compiler') or params.get('toolchain')
    # Analysis does not invoke a compiler, but must still have a known Ghidra version.
    if str(job.get('actionId', '')).startswith('mcp.'):
        toolchain = params.get('ghidraVersion') or toolchain
    size = params.get('workSize') or params.get('size')
    if not arch or not toolchain or not isinstance(size, (int, float)) or size <= 0:
        return None
    return json.dumps([job.get('actionId'), arch, toolchain, math.floor(math.log2(size))])


def _eta(con: sqlite3.Connection, job: dict, binary: dict | None) -> dict:
    result = _unknown_eta(job['status'])
    signature = _signature(job, binary)
    if not signature:
        return result
    rows = con.execute('SELECT duration FROM activity_observation WHERE signature=? ORDER BY finished DESC LIMIT 50', (signature,)).fetchall()
    result['observations'] = len(rows)
    if len(rows) < 5 or job['status'] != 'running':
        return result
    durations = sorted(row[0] for row in rows)
    elapsed = max(0, time.time() - (job.get('startedAt') or time.time()))
    lower = max(0, durations[len(rows) // 5] - elapsed)
    upper = max(0, durations[min(len(rows) - 1, math.ceil(len(rows) * .8))] - elapsed)
    if upper <= 0:
        result.update(label='Estimate exceeded', basis=f'This run is past the range from {len(rows)} completed jobs.')
        return result
    result.update(lowerSeconds=math.ceil(lower / 60) * 60, upperSeconds=math.ceil(upper / 60) * 60,
                  label=f'{max(1, math.ceil(lower / 60))}–{max(1, math.ceil(upper / 60))} min',
                  basis=f'Range from {len(rows)} completed jobs of the same work. This estimate is for the current run only.')
    return result


def _entity(kind: str, identity: str, **fields: Any) -> dict:
    row = {'id': identity, 'kind': kind, 'logicalId': '', 'locator': '', 'projectBindings': [],
           'slug': '', 'addr': '', 'name': '', 'sha256': None, 'sourceHash': None, 'revision': None,
           'status': 'idle', 'stage': 'Not queued', 'action': '', 'target': '', 'jobId': None, 'startedAt': None,
           'progress': _progress('idle'), 'eta': _unknown_eta('idle'), 'facets': [],
           'queue': {'position': None, 'reason': 'No admitted queue entry'}, 'error': '',
           'updatedAt': None, 'proofReceipts': [], 'dependencies': [], 'attempts': None,
           'nextFallback': None, 'budgetRemainingSeconds': None, 'protection': {}, **fields}
    if 'sourceHash' not in fields:
        row['sourceHash'] = row.get('sha256')
    return row


def _read_runs() -> list[dict]:
    if live_root() is None:
        return []
    # Use the scheduler's snapshot so queue position and priority have the
    # same meaning in Activity, the explorer, and workflow controls.
    from .preparation import list_runs
    return list_runs()


def _library() -> dict:
    global _LIBRARY
    root = str(live_root())
    if _LIBRARY[0] != root or time.monotonic() - _LIBRARY[1] > 15:
        # Do not rescan all recovered source/object trees for a two-second feed.
        # Identity is shared with the library; proof stays in explicit receipts.
        from .library_identity import canonical_library
        rows, error = query_db('SELECT id,slug,repo_path,variant,func_count,arch FROM binary ORDER BY id')
        bindings, _ = query_db('SELECT source_path,locator,program FROM program_binding', ignore_missing=True)
        by_source: dict[str, list[dict]] = {}
        for source, project, program in bindings:
            by_source.setdefault(source, []).append({'locator': project, 'program': program})
        prepared = []
        for binary_id, slug, path, label, count, arch in rows:
            path = path or ''
            memberships = by_source.get(path, [])
            prepared.append({'id': binary_id, 'slug': slug, 'repo': path, 'label': label or '',
                             'funcs': count or 0, 'arch': arch, 'kind': 'project' if path.endswith('.gpr') or Path(path).is_dir() else 'binary',
                             'imported': bool(memberships), 'projectBindings': memberships,
                             'locator': memberships[0]['locator'] if memberships else ''})
        canonical, unresolved = canonical_library(prepared)
        aliases, _ = query_db('SELECT source_path,binary_slug,sha256 FROM binary_source_alias', ignore_missing=True)
        for binary in canonical:
            for source, alias_slug, digest in aliases:
                if alias_slug in binary['aliasSlugs'] and digest == binary.get('sha256'):
                    for binding in by_source.get(source, []):
                        if binding not in binary['projectBindings']:
                            binary['projectBindings'].append(binding)
        _LIBRARY = (root, time.monotonic(), {'ok': not error, 'error': error or '', 'binaries': canonical, 'unresolvedBinaries': unresolved})
    return _LIBRARY[2]


def _build(con: sqlite3.Connection, locator: str, slug: str, program: str = '') -> dict:
    from .actions.jobs import list_jobs
    library = _library()
    binaries = library.get('binaries', [])
    runs = _read_runs()
    jobs = [job.to_dict() for job in list_jobs()]
    timing_contexts: dict[str, dict] = {}
    for run in reversed(runs):
        timing_contexts.update(run.get('jobTimingContexts') or {})
    # Timing metadata is observational and never sent as extra tool arguments.
    for job_id, context in timing_contexts.items():
        signature = _signature({'actionId': context.get('actionId'), 'params': context}, None)
        started, finished = context.get('startedAt'), context.get('finishedAt')
        if signature and context.get('status') == 'ok' and isinstance(started, (int, float)) and isinstance(finished, (int, float)) and finished > started:
            con.execute('INSERT OR IGNORE INTO activity_observation VALUES(?,?,?,?)', (job_id, signature, finished - started, finished))
    for job in jobs:
        if job['id'] in timing_contexts:
            job['params'] = {**job.get('params', {}), **{key: value for key, value in timing_contexts[job['id']].items() if key in {'architecture', 'arch', 'ghidraVersion', 'toolchain', 'workSize'}}}
    by_slug = {alias: row for row in binaries for alias in row.get('aliasSlugs', [row['slug']])}
    entities: dict[str, dict] = {}
    by_program: dict[tuple[str, str], dict] = {}
    for binary in binaries:
        bindings = binary.get('projectBindings') or []
        if binary.get('kind') == 'project':
            project_locator = binary.get('repo', '')
            if project_locator:
                entities.setdefault(f'project:{project_locator}', _entity('project', f'project:{project_locator}', locator=project_locator, name=binary.get('label') or binary['slug']))
            continue
        digest = binary.get('sha256')
        entity = _entity('binary', binary.get('libraryId') or f"binary:{binary['id']}", slug=binary['slug'],
                         name=binary.get('label') or binary['slug'], sha256=digest, sourceHash=digest,
                         locator=binary.get('locator', ''), projectBindings=bindings,
                         protection=binary.get('protection', {}), aliasSlugs=binary.get('aliasSlugs', [binary['slug']]))
        add_facet(entity, {'kind': 'analysis-unknown', 'label': 'Analysis state unknown'})
        # Protection facets come from the library's byte detector, not guessed here.
        if binary.get('decomp', {}).get('asm'):
            add_facet(entity, {'kind': 'assembly', 'label': f"Assembly substrate: {binary['decomp']['asm']}"})
        if binary.get('decomp', {}).get('c'):
            add_facet(entity, {'kind': 'advisory', 'label': f"C source: {binary['decomp']['c']} · proof not established"})
        ids = binary.get('binaryIds') or [binary['id']]
        marks = ','.join('?' for _ in ids)
        debug, _ = query_db(f'SELECT 1 FROM stabs_type WHERE binary_id IN ({marks}) LIMIT 1', tuple(ids), ignore_missing=True)
        if debug:
            add_facet(entity, {'kind': 'debug', 'label': 'STABS types', 'source': 'stabs_type'})
        human, _ = query_db(f"SELECT 1 FROM func WHERE binary_id IN ({marks}) AND name_origin IN ('human','human-authored','USER_DEFINED','manual','user') LIMIT 1", tuple(ids), ignore_missing=True)
        if human:
            add_facet(entity, {'kind': 'human', 'label': 'Human names preserved', 'source': 'func.name_origin'})
        matched, _ = query_db(
            f"SELECT 1 FROM identity i WHERE i.binary_id IN ({marks}) AND i.method LIKE 'match:%' LIMIT 1",
            tuple(ids),
            ignore_missing=True,
        )
        if matched:
            add_facet(entity, {'kind': 'match', 'label': 'Cross-match recorded', 'source': 'identity.method'})
        entities[entity['id']] = entity
        for binding in bindings:
            by_program[(binding['locator'], binding['program'].lstrip('/'))] = entity
    # Projects with no preparation yet still have a stable idle row.
    for entity in list(entities.values()):
        for binding in entity.get('projectBindings', []):
            project_locator = binding['locator']
            if project_locator:
                entities.setdefault(f'project:{project_locator}', _entity('project', f'project:{project_locator}', locator=project_locator, name=Path(project_locator).stem))
    for run in reversed(runs):
        if run.get('supersededBy'):
            continue  # Retain historical receipts without replacing the canonical live state.
        run_locator = run.get('locator', '')
        if not run_locator:
            continue
        stage = next((s for s in run['stages'] if s.get('key') == run.get('currentStage')), None)
        stage = stage or next((s for s in run['stages'] if s.get('status') == 'running'), None)
        stage = stage or next((s for s in run['stages'] if s.get('status') in {'blocked', 'partial', 'failed', 'interrupted', 'waiting'}), None)
        stage = stage or next((s for s in run['stages'] if s.get('status') == 'queued'), None) or (run['stages'][-1] if run['stages'] else {})
        status = run.get('status', 'unknown')
        project = _entity('project', f'project:{run_locator}', locator=run_locator, name=Path(run_locator).stem,
                          status=status, stage=stage.get('title', 'Preparation'), action=stage.get('currentAction', ''),
                          jobId=stage.get('jobId') or run.get('jobId'), target=stage.get('currentProgram', ''),
                          progress={**_progress(status, (stage.get('workProgress') or {}).get('completed', stage.get('completed')), (stage.get('workProgress') or {}).get('total', stage.get('total'))), 'unit': (stage.get('workProgress') or {}).get('unit')},
                          eta=_unknown_eta(status), startedAt=(stage.get('startedAt') or run.get('startedAt') or run.get('createdAt')) if status in _ACTIVE else None,
                          updatedAt=run.get('updatedAt'), error=run.get('error') or (stage.get('reason', '') if status in {'blocked', 'partial', 'failed', 'interrupted', 'budget-stop'} else ''),
                          message=stage.get('reason', ''),
                          stages=run['stages'], queue=_queue(run, status), attempts=stage.get('attempts'), nextFallback=stage.get('nextFallback'),
                          dependencies=stage.get('dependencies', []), budgetRemainingSeconds=max(0, math.floor((run.get('deadline', 0) - time.time()) / 60) * 60) if run.get('deadline') and status in _ACTIVE else None)
        entities[project['id']] = project
        for program, checkpoint in run.get('checkpoints', {}).items():
            entity = by_program.get((run_locator, program.lstrip('/')))
            if entity and checkpoint.get('analysisConfirmed') is True:
                entity['facets'] = [f for f in entity['facets'] if not str(f.get('kind', '')).startswith('analysis-')]
                add_facet(entity, {'kind': 'analysis', 'label': 'Analyzed', 'source': f'preparation:{run["id"]}'})
            if entity and entity.get('status') not in _ACTIVE and status in {'blocked', 'partial', 'failed', 'interrupted', 'budget-stop', 'paused', 'cancelled'}:
                # Terminal project stages often have no currentProgram. Keep
                # each member's actual outcome visible after its child job ends.
                relevant = next((candidate for candidate in run['stages']
                    if candidate.get('status') in {'blocked', 'partial', 'failed', 'interrupted', 'waiting'}
                    and (program in candidate.get('outcomes', {})
                         or candidate.get('currentProgram') == program
                         or not candidate.get('currentProgram'))), stage)
                outcome = relevant.get('outcomes', {}).get(program, {})
                reason = outcome.get('reason') or relevant.get('reason') or run.get('error') or ''
                entity.update(status=outcome.get('status') or status,
                    stage=relevant.get('title', 'Preparation'), action=relevant.get('currentAction', ''),
                    target=program, jobId=relevant.get('jobId') or run.get('jobId'),
                    progress=_progress(status), eta=_unknown_eta(status), startedAt=None,
                    updatedAt=run.get('updatedAt'), message=reason, error=reason,
                    queue=_queue(run, status), dependencies=outcome.get('dependencies', relevant.get('dependencies', [])),
                    nextFallback=outcome.get('nextAction') or relevant.get('nextFallback'))
        current = by_program.get((run_locator, str(stage.get('currentProgram', '')).lstrip('/')))
        if current is None and status in _ACTIVE and len(run.get('programs', [])) == 1:
            current = by_program.get((run_locator, str(run['programs'][0]).lstrip('/')))
        if current and status in _ACTIVE:
            current.update(status=stage.get('jobStatus') if stage.get('jobStatus') in _ACTIVE else status, stage=stage.get('title'), action=stage.get('currentAction', ''),
                           target=stage.get('currentProgram', ''), jobId=stage.get('jobId'),
                           progress={**_progress('running', (stage.get('workProgress') or {}).get('completed'), (stage.get('workProgress') or {}).get('total')), 'unit': (stage.get('workProgress') or {}).get('unit')}, eta=_unknown_eta('running'),
                           startedAt=stage.get('startedAt') or run.get('startedAt') or run.get('createdAt'),
                           updatedAt=run.get('updatedAt'), message=stage.get('reason', ''), error='')
    # Queue order is not implied by creation time: locks and concurrent admission can change it.
    # Only display a rank explicitly emitted by a scheduler.
    for job in reversed(jobs):
        params = job.get('params') or {}
        job_slug = str(params.get('slug') or '')
        job_locator = str(params.get('locator') or '')
        job_program = str(params.get('programPath') or params.get('program') or '').lstrip('/')
        binary = by_slug.get(job_slug)
        target = by_program.get((job_locator, job_program))
        if target is None and binary:
            target = entities.get(binary.get('libraryId') or f"binary:{binary['id']}")
        signature = _signature(job, binary)
        if signature and job['status'] == 'ok' and job.get('startedAt') and job.get('finishedAt'):
            duration = job['finishedAt'] - job['startedAt']
            if duration > 0:
                con.execute('INSERT OR IGNORE INTO activity_observation VALUES(?,?,?,?)', (job['id'], signature, duration, job['finishedAt']))
        if target is None:
            continue
        address_or_name = params.get('address') or params.get('addr') or params.get('functionAddress') or params.get('functionIdentifier') or params.get('addressOrSymbol')
        addr = canonical_address(address_or_name)
        if addr:
            try:
                int(addr, 16)
            except ValueError:
                matches, _ = query_db('SELECT f.addr FROM func f JOIN binary b ON b.id=f.binary_id WHERE b.slug=? AND f.name=? LIMIT 2', (target['slug'], str(address_or_name)), ignore_missing=True)
                addr = canonical_address(matches[0][0]) if len(matches) == 1 else ''
        if addr:
            if locator and job_locator != locator:
                continue
            if not _binary_selected(target, slug, program):
                continue  # Only selected-binary function jobs; all project/binary rollups stay visible.
            identity = f"function:{target['id']}:{addr}"
            digest = target.get('sourceHash') or target.get('sha256')
            target = entities.setdefault(identity, _entity('function', identity, locator=job_locator or target.get('locator', ''),
                slug=target['slug'], addr=addr, name=addr, sha256=digest, sourceHash=digest,
                projectBindings=list(target.get('projectBindings') or []), aliasSlugs=target.get('aliasSlugs', [target['slug']])))
            evidence, _ = query_db('SELECT f.name,f.name_origin,i.logical_id FROM func f LEFT JOIN identity i ON i.binary_id=f.binary_id AND i.addr=f.addr JOIN binary b ON b.id=f.binary_id WHERE b.slug=? AND f.addr=?', (target['slug'], int(addr, 16)), ignore_missing=True)
            if evidence:
                name, origin, logical = evidence[0]
                target.update(name=name or addr, logicalId=str(logical) if logical is not None else '')
                for facet in origin_evidence(origin, logical):
                    add_facet(target, facet)
        elif job['status'] not in _ACTIVE:
            continue
        if target.get('status') in _ACTIVE and job['status'] not in _ACTIVE:
            continue
        measured = None
        for line in reversed(job.get('log', '').splitlines()):
            try:
                row = json.loads(line)
                if isinstance(row, dict) and row.get('event') == 'progress':
                    measured = row
                    break
            except ValueError:
                continue
        job_active = job['status'] in _ACTIVE
        target.update(status=job['status'], stage=job['title'], action=job['actionId'],
                      target=job_program or addr or job_slug,
                      jobId=job['id'],
                      progress=_progress(job['status'], (measured or {}).get('completed'), (measured or {}).get('total')),
                      eta=_eta(con, job, binary), error=job.get('error', ''),
                      startedAt=job.get('startedAt') if job_active else None,
                      updatedAt=job.get('finishedAt') or job.get('startedAt') or job.get('createdAt'),
                      queue=_queue(params, job['status']))
    selected_binary = by_slug.get(slug) if slug and slug in by_slug else None
    if selected_binary is None and program:
        selected_binary = next((row for row in binaries if row.get('kind') != 'project' and _program_bound(row, program)), None)
    if selected_binary is not None:
        from .activity_receipts import recorded_receipts
        selected_id = selected_binary.get('libraryId') or f"binary:{selected_binary['id']}"
        selected_entity = entities.get(selected_id)
        root = live_root()
        if selected_entity and root:
            references = recorded_receipts(root, selected_binary, runs)
            selected_entity['proofReceipts'] = references
            function_receipts = 0
            for reference in references:
                for address in reference['addresses']:
                    if function_receipts >= 1024:
                        selected_entity['proofReceiptsTruncated'] = True
                        break
                    function_receipts += 1
                    identity = f"function:{selected_id}:{address}"
                    digest = selected_binary.get('sha256')
                    function = entities.setdefault(identity, _entity('function', identity,
                        locator=locator or selected_binary.get('locator', ''), slug=selected_binary['slug'],
                        addr=address, name=address, sha256=digest, sourceHash=digest,
                        projectBindings=list(selected_binary.get('projectBindings') or []),
                        aliasSlugs=selected_binary.get('aliasSlugs', [])))
                    function['proofReceipts'].append(reference)
                    add_facet(function, {'kind': 'recorded-proof', 'label': 'Recorded receipt', 'source': reference.get('path') or ''})
    for project in [entity for entity in entities.values() if entity['kind'] == 'project']:
        states: dict[str, int] = {}
        for binary in entities.values():
            if binary['kind'] == 'binary' and any(binding['locator'] == project['locator'] for binding in binary.get('projectBindings', [])):
                states[binary['status']] = states.get(binary['status'], 0) + 1
        project['stateCounts'] = states
    for entity in entities.values():
        attach_dimensions(entity)
    scope = {'locator': locator, 'slug': slug}
    if program:
        scope['program'] = program
    return {'ok': bool(library.get('ok')), 'error': library.get('error', ''), 'entities': list(entities.values()),
            'scope': scope}


def snapshot(locator: str = '', slug: str = '', program: str = '') -> dict:
    scope = _journal_scope(locator, slug, program)
    with _LOCK:
        con = _journal()
        try:
            payload = _build(con, locator, slug, program)
            encoded = json.dumps(payload, sort_keys=True, separators=(',', ':'))
            digest = hashlib.sha256(encoded.encode()).hexdigest()
            con.execute('BEGIN IMMEDIATE') if not con.in_transaction else None
            previous = con.execute('SELECT revision,digest FROM activity_event WHERE scope=? ORDER BY revision DESC LIMIT 1', (scope,)).fetchone()
            if previous and previous[1] == digest:
                revision = previous[0]
            else:
                cursor = con.execute('INSERT INTO activity_event(scope,digest,payload,created) VALUES(?,?,?,?)', (scope, digest, encoded, time.time()))
                revision = cursor.lastrowid
                con.execute('DELETE FROM activity_event WHERE scope=? AND revision NOT IN (SELECT revision FROM activity_event WHERE scope=? ORDER BY revision DESC LIMIT 128)', (scope, scope))
            con.commit()
            return {**payload, 'revision': revision}
        finally:
            con.close()


def _replay(locator: str, slug: str, after: int, program: str = '') -> list[dict] | None:
    with _LOCK:
        con = _journal()
        try:
            scope = _journal_scope(locator, slug, program)
            known = con.execute('SELECT 1 FROM activity_event WHERE scope=? AND revision=?', (scope, after)).fetchone()
            if not known:
                return None
            rows = con.execute('SELECT revision,payload FROM activity_event WHERE scope=? AND revision>? ORDER BY revision', (scope, after)).fetchall()
            return [{**json.loads(payload), 'revision': revision} for revision, payload in rows]
        finally:
            con.close()


def create_activity_router() -> APIRouter:
    router = APIRouter()

    @router.get('/dashboard/api/workbench/activity')
    async def activity(locator: str = '', slug: str = '', program: str = ''):
        try:
            return await asyncio.to_thread(snapshot, locator, slug, program)
        except (ValueError, OSError, sqlite3.Error) as exc:
            return JSONResponse({'ok': False, 'error': str(exc), 'entities': []}, status_code=503)

    @router.get('/dashboard/api/workbench/activity/events')
    async def events(request: Request, locator: str = '', slug: str = '', program: str = '', after: int = 0):
        try:
            cursor = max(0, int(request.headers.get('last-event-id') or after))
        except ValueError:
            cursor = 0

        async def stream():
            nonlocal cursor
            while not await request.is_disconnected():
                try:
                    latest = await asyncio.to_thread(snapshot, locator, slug, program)
                    if latest['revision'] != cursor:
                        changes = await asyncio.to_thread(_replay, locator, slug, cursor, program) if cursor else None
                        for item in changes if changes is not None else [latest]:
                            cursor = item['revision']
                            event = 'snapshot' if changes is None else 'activity'
                            yield f'id: {cursor}\nevent: {event}\ndata: {json.dumps(item)}\n\n'
                    else:
                        yield f'event: heartbeat\ndata: {json.dumps({"revision": cursor})}\n\n'
                except (ValueError, OSError, sqlite3.Error) as exc:
                    yield f'event: unavailable\ndata: {json.dumps({"error": str(exc)})}\n\n'
                await asyncio.sleep(2)
        return StreamingResponse(stream(), media_type='text/event-stream', headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})

    return router
