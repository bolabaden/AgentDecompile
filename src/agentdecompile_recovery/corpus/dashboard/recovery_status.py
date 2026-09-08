"""Selection-scoped recovery observations from the shared store and workflow.

Historical corpus exports are optional witnesses. Their absence does not make
an imported Ghidra project invalid, and their totals never describe that project.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from .common import live_db, live_root


def _program(value: Any) -> str:
    return str(value or '').strip().lstrip('/')


def _runs(locator: str, slug: str, program: str, all_corpora: bool) -> list[dict]:
    from .preparation import list_runs
    rows = [row for row in list_runs() if not row.get('supersededBy')]
    if not all_corpora:
        rows = [row for row in rows if (row.get('locator', '').rstrip('/') == locator if locator else bool(slug) and (row.get('slug') == slug or any(c.get('slug') == slug for c in (row.get('checkpoints') or {}).values())))]
        if program:
            rows = [row for row in rows if _program(row.get('program')) == _program(program) or _program(program) in {_program(p) for p in row.get('programs', [])}]
    # A canonical project coordinator already includes its program checkpoints.
    projects = {row.get('locator') for row in rows if not row.get('program')}
    rows = [row for row in rows if not row.get('program') or row.get('locator') not in projects]
    return sorted(rows, key=lambda row: float(row.get('updatedAt') or 0), reverse=True)


def _public_run(run: dict) -> dict:
    # Action histories can contain megabytes of captured source. The job API
    # retains those details; the status response carries the active workflow.
    return {key: value for key, value in run.items() if key not in {'actions', 'jobTimingContexts', 'comparisonInputs'}}


def _scope(con: sqlite3.Connection, tables: set[str], locator: str, slug: str, program: str,
           all_corpora: bool, runs: list[dict]) -> tuple[dict, list[dict]]:
    selected = con.execute('SELECT * FROM binary WHERE slug=?', (slug,)).fetchone() if slug else None
    ids: set[int] = set()
    if all_corpora:
        ids = {row[0] for row in con.execute('SELECT id FROM binary')}
    elif locator:
        if 'program_binding' in tables:
            for row in con.execute('SELECT b.id,p.program FROM program_binding p JOIN binary b ON b.repo_path=p.source_path WHERE rtrim(p.locator,\'/\')=?', (locator,)):
                if not program or _program(row['program']) == _program(program):
                    ids.add(row['id'])
        for run in runs:
            for key, checkpoint in (run.get('checkpoints') or {}).items():
                if program and _program(key) != _program(program):
                    continue
                if _program(key) not in {_program(p) for p in run.get('programs', [])}:
                    continue
                binary_id = checkpoint.get('binaryId')
                row = con.execute('SELECT id,slug,repo_path FROM binary WHERE id=?', (binary_id,)).fetchone()
                if row and row['slug'] == checkpoint.get('slug') and row['repo_path'] == checkpoint.get('repoPath'):
                    ids.add(row['id'])
        if selected is not None and selected['id'] in ids:
            ids = {selected['id']}
        elif selected is not None and str(selected['repo_path']).rstrip('/') != locator:
            # A valid but unrelated build slug cannot silently show this
            # project's other binary as if it were the requested selection.
            ids = set()
    elif selected is not None:
        ids = {selected['id']}
    builds = [dict(row) for row in con.execute('SELECT * FROM binary ORDER BY slug') if row['id'] in ids]
    for build in builds:
        bindings = [dict(row) for row in con.execute('SELECT locator,program FROM program_binding WHERE source_path=?', (build['repo_path'],))] if 'program_binding' in tables else []
        for run in runs:
            for key, checkpoint in (run.get('checkpoints') or {}).items():
                if checkpoint.get('binaryId') == build['id'] and checkpoint.get('repoPath') == build['repo_path'] and _program(key) in {_program(p) for p in run.get('programs', [])}:
                    binding = {'locator': run.get('locator', ''), 'program': key}
                    if binding not in bindings:
                        bindings.append(binding)
        candidates = {(item['locator'], _program(item['program'])): item for item in bindings if (not locator or item['locator'].rstrip('/') == locator) and (not program or _program(item['program']) == _program(program))}
        chosen = next(iter(candidates.values())) if len(candidates) == 1 else None
        build.update(projectBindings=bindings, program=chosen['program'] if chosen else '', locator=chosen['locator'] if chosen else '',
                     programBindingReason='' if chosen else 'No unique project/program binding is recorded for this binary.')
    kind = 'all' if all_corpora else 'binary' if len(ids) == 1 and (program or selected is not None and selected['id'] in ids) else 'project' if locator else 'unresolved'
    scope = {'kind': kind, 'locator': locator, 'slug': slug, 'program': program, 'binaryIds': sorted(ids),
             'reason': '' if builds else 'No stored binary inventory is bound to this selection yet.'}
    return scope, builds


def corpus_status(*, locator: str = '', slug: str = '', program: str = '', scope: str = '') -> dict[str, Any]:
    """Read selected project state without native calls or legacy prerequisites."""
    locator = str(locator or '').strip().rstrip('/')
    program = str(program or '').strip()
    slug = str(slug or '').strip()
    if not locator and program.lower().endswith('.gpr'):
        locator, program = program.rstrip('/'), ''
    if program.rstrip('/') == locator:
        program = ''
    all_corpora = scope == 'all'
    errors: list[str] = []
    try:
        runs = _runs(locator, slug, program, all_corpora)
    except (OSError, ValueError, KeyError) as exc:
        runs = []
        errors.append(f'Workflow state unavailable: {exc}')
    report: dict[str, Any] = {'ok': True, 'by_build': [], 'functions': [], 'artifacts': None, 'logical': None, 'unplaced': None, 'unbound': None, 'errors': []}
    selection = {'kind': 'unresolved', 'locator': locator, 'slug': slug, 'program': program, 'binaryIds': [], 'reason': 'Stored project inventory unavailable.'}
    builds: list[dict] = []
    matching: dict[str, int] = {}
    totals = {'functions': 0, 'named': 0, 'bound': 0, 'sourceRecords': 0, 'sourceWitnesses': 0}
    source_measured = False
    try:
        with sqlite3.connect(f'{Path(live_db()).resolve().as_uri()}?mode=ro', uri=True) as con:
            con.row_factory = sqlite3.Row
            con.execute('BEGIN')
            tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            selection, builds = _scope(con, tables, locator, slug, program, all_corpora, runs)
            source_measured = 'recovered_function' in tables
            for build in builds:
                bid = build['id']
                count, named = con.execute("SELECT COUNT(*),COALESCE(SUM(name IS NOT NULL AND name!='' AND name NOT GLOB 'FUN_*' AND name NOT GLOB 'LAB_*'),0) FROM func WHERE binary_id=?", (bid,)).fetchone()
                bound = con.execute('SELECT COUNT(DISTINCT addr) FROM identity WHERE binary_id=?', (bid,)).fetchone()[0] if 'identity' in tables else 0
                artifacts, logical, concrete = con.execute('SELECT COUNT(*),COUNT(DISTINCT logical_id),COUNT(DISTINCT addr) FROM recovered_function WHERE binary_id=? AND real_c=1', (bid,)).fetchone() if source_measured else (None, None, None)
                witnesses = con.execute('SELECT COUNT(DISTINCT addr) FROM decomp WHERE binary_id=? AND ok=1', (bid,)).fetchone()[0] if 'decomp' in tables else None
                build.update(func_count=count, named_count=named, bound=bound, real_c=concrete, sourceWitnesses=witnesses, byte_verified=None)
                report['by_build'].append({'slug': build['slug'], 'binary_id': bid, 'artifacts': artifacts, 'logical': logical, 'concrete': concrete, 'functions': count, 'sourceWitnesses': witnesses, 'compiles': None, 'byte_verified': None})
                for key, value in (('functions', count), ('named', named), ('bound', bound), ('sourceRecords', concrete), ('sourceWitnesses', witnesses)):
                    totals[key] += int(value or 0)
            ids = selection['binaryIds']
            if ids and 'match' in tables:
                marks = ','.join('?' for _ in ids)
                matching = {str(row[0]): row[1] for row in con.execute(f'SELECT status,COUNT(*) FROM match WHERE src_binary IN ({marks}) OR dst_binary IN ({marks}) GROUP BY status', (*ids, *ids))}
            if ids and source_measured:
                marks = ','.join('?' for _ in ids)
                row = con.execute(f'SELECT COUNT(*),COUNT(DISTINCT logical_id),COALESCE(SUM(logical_id IS NULL),0),COALESCE(SUM(addr IS NULL),0) FROM recovered_function WHERE real_c=1 AND binary_id IN ({marks})', ids).fetchone()
                report.update(artifacts=row[0], logical=row[1], unbound=row[2], unplaced=row[3])
    except (sqlite3.Error, OSError, ValueError, TypeError) as exc:
        errors.append(f'Stored project inventory unavailable: {exc}')
    public_runs = [_public_run(run) for run in runs]
    stages = public_runs[0].get('stages', []) if len(public_runs) == 1 else []
    evidence_sources = []
    root = live_root()
    if root is not None:
        for relative in ('output/work_queue/logical_queue_summary.json', 'output/exact_universal/_coverage.json'):
            path = root / relative
            evidence_sources.append({'path': str(path), 'status': 'available' if path.is_file() else 'not-produced', 'required': False,
                                     'reason': 'Optional historical corpus report. Current project progress comes from workflow receipts and stored function records.'})
    recovery = {
        'sourceAvailability': {'count': totals['sourceRecords'] if source_measured else None, 'total': totals['functions'], 'claim': 'recorded-source-availability', 'reason': 'Recorded assembly-free source rows; compilation and byte identity are separate.' if source_measured else 'No recovered-source records have been produced for this workspace yet.'},
        'compilation': {'count': None, 'reason': 'Compilation is reported by each workflow stage; no aggregate function compilation measurement is available.'},
        'verification': {'count': None, 'reason': 'No aggregate receipt-validated byte proof has been established for this selection. Matching tiers are advisory.'},
        'matching': {'byStatus': matching, 'claim': 'advisory', 'unit': 'recorded directed pair observations', 'reason': 'Recorded pair observations across matching runs, not unique functions or current-wave totals. The verify tier means a candidate needs verification; it is not byte proof.'},
        'totals': totals,
    }
    return {'ok': True, 'available': not errors, 'scope': selection, 'workflow': {'runs': public_runs, 'source': 'durable-workflow'}, 'recovery': recovery,
            'claimBoundary': 'Source availability, compilation, and byte verification are separate claims.',
            'headline': {'real_c': totals['sourceRecords'] if source_measured else None, 'byte_exact': 'unmeasured', 'placed_concrete': totals['bound'], 'unplaced_real_c': None, 'queued': None},
            'builds': builds, 'ladder': {'binaries': builds, 'corpus_steps': [], 'project_steps': stages, 'errors': []},
            'report': report, 'review': {'by_status': matching, 'rows': [], 'errors': []}, 'evidenceSources': evidence_sources,
            'errors': errors, 'probes': [], 'mission': {}, 'atlas': {'in_tree': '/atlas'}}


def recover_status(**selection: str) -> dict[str, Any]:
    status = corpus_status(**selection)
    runs = status['workflow']['runs']
    current = runs[0] if runs else {}
    stage = next((item for item in current.get('stages', []) if item.get('key') == current.get('currentStage')), {})
    fallback = f"{stage.get('title') or current.get('currentStage') or 'Workflow'}: {current.get('status') or 'recorded'}." if current else 'Stored evidence is available. No active recovery workflow is recorded.'
    return {'ok': status['ok'], 'scope': status['scope'], 'state': current.get('status') or 'not-queued',
            'summary': stage.get('reason') or status['scope']['reason'] or fallback,
            'path': '', 'files': [], 'count': status['recovery']['sourceAvailability']['count'], 'leftoverCount': None,
            'workflow': status['workflow'], 'recovery': status['recovery'], 'evidenceSources': status['evidenceSources'], 'errors': status['errors']}
