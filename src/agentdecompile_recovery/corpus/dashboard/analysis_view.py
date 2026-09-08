"""Read-only structural projection and complexity ranking of recorded function facts."""
from __future__ import annotations

import asyncio
import bisect
import json
import math
import re
import sqlite3
import threading
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

from agentdecompile_recovery.corpus.export_atlas_db import VECTOR_FIELDS
from .common import live_db, live_root, page_window

_MAX_POINTS = 12000
_CACHE: dict[tuple, dict] = {}
_LOCK = threading.Lock()
_METRICS = {'instructions': 'n_instr', 'edges': 'n_edges', 'blocks': 'n_blocks', 'cyclomatic': 'cyclomatic', 'callees': 'n_callees', 'size': 'size'}


def _number(value: Any) -> float | None:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0 else None


def _knowledge_sources(con: sqlite3.Connection, binary: sqlite3.Row, tables: set[str], locator: str, program: str) -> tuple[list[dict], list[Path]]:
    """Resolve source witnesses by recorded membership and current target fingerprint.

    Legacy global stores have only a basename identity. They are usable only
    when that name identifies one corpus binary. Workflow stores instead keep
    their exact program key and must match the receipt, membership and bytes.
    """
    from .actions.catalog import env_defaults
    from .activity_receipts import _md5

    databases: list[dict] = []
    observed: list[Path] = []
    source = Path(binary['repo_path'])
    basename = source.name
    global_path = str(env_defaults().get('kb') or '')
    if global_path:
        kb = Path(global_path).expanduser()
        observed.extend([kb, Path(str(kb) + '-wal')])
        collisions = [row[0] for row in con.execute('SELECT repo_path FROM binary') if Path(row[0]).name == basename]
        if kb.is_file() and len(collisions) == 1:
            databases.append({'path': str(kb.resolve()), 'program': basename, 'kind': 'unique-basename knowledge store'})
    root = live_root()
    if root is None or 'program_binding' not in tables:
        return databases, observed
    workspace = root.resolve()
    bindings = {(row[0], str(row[1]).lstrip('/')) for row in con.execute(
        'SELECT locator,program FROM program_binding WHERE source_path=?', (binary['repo_path'],))}
    fingerprint = ''
    for receipt_path in sorted((workspace / 'preparations').glob('*.json')):
        if not re.fullmatch(r'[0-9a-f]{32}', receipt_path.stem):
            continue
        observed.append(receipt_path)
        try:
            if receipt_path.stat().st_size > 4 * 1024 * 1024:
                continue
            receipt = json.loads(receipt_path.read_text())
            if not isinstance(receipt, dict) or receipt.get('id') != receipt_path.stem:
                continue
            run_locator = receipt.get('locator')
            if locator and run_locator != locator:
                continue
            checkpoints = receipt.get('checkpoints') or {}
            if not isinstance(checkpoints, dict):
                continue
            for recorded_program, checkpoint in checkpoints.items():
                if not isinstance(checkpoint, dict) or not isinstance(recorded_program, str):
                    continue
                if program and recorded_program.lstrip('/') != program.lstrip('/'):
                    continue
                if (run_locator, recorded_program.lstrip('/')) not in bindings:
                    continue
                if str(checkpoint.get('binaryId')) != str(binary['id']) or checkpoint.get('slug') != binary['slug']:
                    continue
                if Path(str(checkpoint.get('repoPath') or '')).resolve() != source.resolve():
                    continue
                recorded_fingerprint = str(checkpoint.get('programFingerprint') or '')
                if not re.fullmatch(r'[0-9a-f]{32}', recorded_fingerprint) or checkpoint.get('knowledgeFingerprint') != recorded_fingerprint:
                    continue
                fingerprint = fingerprint or _md5(source)
                if not fingerprint or recorded_fingerprint != fingerprint:
                    continue
                expected = workspace / 'recovery' / receipt_path.stem / str(binary['id']) / ('knowledge-' + fingerprint + '.sqlite')
                kb = Path(str(checkpoint.get('knowledgeDb') or '')).expanduser()
                # Reject escaped/symlinked output directories, even if a receipt
                # points at another valid SQLite file under the workspace.
                if expected.resolve() != expected or kb.resolve() != expected:
                    continue
                observed.extend([source, expected, Path(str(expected) + '-wal')])
                if expected.is_file():
                    databases.append({'path': str(expected), 'program': recorded_program, 'kind': 'fingerprint-bound workflow knowledge',
                                      'runId': receipt_path.stem, 'binaryId': binary['id'], 'programFingerprint': fingerprint})
        except (OSError, ValueError, TypeError):
            continue
    return databases, observed


def read_function_witness(slug: str, addr: int, locator: str = '', program: str = '') -> dict:
    """Read one exact function's source for the editor, without loading its corpus.

    Source ZIPs retain full text. Interactive responses cap each text field at
    200,000 characters and carry the original length and truncation boundary.
    No names, annotations or proof states are replaced by this response.
    """
    path = live_db()
    if path is None or not path.is_file() or not isinstance(addr, int) or addr < 0:
        return {}
    con = sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, timeout=5)
    con.row_factory = sqlite3.Row
    try:
        tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        binary = con.execute('SELECT * FROM binary WHERE slug=?', (slug,)).fetchone() if slug else None
        if binary is None and locator and program and 'program_binding' in tables:
            rows = con.execute("SELECT b.* FROM binary b JOIN program_binding p ON p.source_path=b.repo_path WHERE p.locator=? AND ltrim(p.program,'/')=?", (locator, program.lstrip('/'))).fetchall()
            if len(rows) == 1:
                binary = rows[0]
        if binary is None:
            return {}
        witnesses, _ = _knowledge_sources(con, binary, tables, locator, program)
    finally:
        con.close()
    cap = 200000
    aliases = set()
    for value in {f'{addr:x}', f'{addr:08x}', f'{addr:016x}'}:
        aliases.update({value, value.upper(), '0x'+value, '0X'+value.upper(), '0x'+value.upper()})
    # Project/fingerprint-bound witnesses take precedence over a legacy basename
    # store. A single indexed lookup per store is independent of inventory size.
    witnesses.sort(key=lambda row: row['kind'] == 'fingerprint-bound workflow knowledge', reverse=True)
    result: dict[str, Any] = {}
    provenance: list[dict] = []
    for witness in witnesses:
        try:
            with sqlite3.connect(Path(witness['path']).as_uri()+'?mode=ro', uri=True, timeout=3) as knowledge:
                rows = knowledge.execute('SELECT entry_hex,substr(decompiled,1,?),length(decompiled),substr(asm,1,?),length(asm) FROM func_knowledge WHERE program=? AND entry_hex IN ('+','.join('?' for _ in aliases)+')',
                                         (cap, cap, witness['program'], *sorted(aliases))).fetchall()
            for entry, source, source_length, assembly, assembly_length in rows:
                fields = []
                if source and source.strip() and 'decompile' not in result:
                    result['decompile'] = {'text': source, 'truncated': source_length > cap, 'characterLimit': cap,
                                           'totalCharacters': source_length, 'path': witness['path'], 'source': 'recorded-knowledge'}
                    fields.append('decompile')
                if assembly and assembly.strip() and 'assembly' not in result:
                    result['assembly'] = {'text': assembly, 'truncated': assembly_length > cap, 'characterLimit': cap,
                                          'totalCharacters': assembly_length, 'path': witness['path']}
                    fields.append('assembly')
                if fields:
                    provenance.append({**witness, 'entryHex': entry, 'fields': fields, 'claim': 'advisory source or tool observation; no compilation or byte proof'})
            if 'decompile' in result and 'assembly' in result:
                break
        except (sqlite3.Error, OSError, ValueError):
            continue
    if result:
        result['provenance'] = {'kind': 'recorded function witnesses', 'addr': f'0x{addr:08x}', 'sources': provenance,
                                'claim': 'Advisory. Source availability does not establish compilation or byte verification.'}
    return result


def _pca(vectors: list[list[float]]) -> tuple[list[list[float]], list[float], list[list[float]], list[float]]:
    """Jacobi eigendecomposition of the eight-dimensional log1p covariance."""
    n, d = len(vectors), len(VECTOR_FIELDS)
    if n < 2:
        return [[0.0, 0.0] for _ in vectors], [0.0, 0.0], [[0.0]*d, [0.0]*d], vectors[0] if vectors else [0.0]*d
    means = [sum(row[i] for row in vectors) / n for i in range(d)]
    centered = [[x - means[i] for i, x in enumerate(row)] for row in vectors]
    matrix = [[sum(row[i] * row[j] for row in centered) / (n - 1) for j in range(d)] for i in range(d)]
    axes = [[float(i == j) for j in range(d)] for i in range(d)]
    for _ in range(256):
        p, q = max(((i, j) for i in range(d) for j in range(i + 1, d)), key=lambda ij: abs(matrix[ij[0]][ij[1]]))
        if abs(matrix[p][q]) < 1e-12:
            break
        angle = .5 * math.atan2(2 * matrix[p][q], matrix[q][q] - matrix[p][p])
        c, s = math.cos(angle), math.sin(angle)
        app, aqq, apq = matrix[p][p], matrix[q][q], matrix[p][q]
        matrix[p][p] = c*c*app - 2*s*c*apq + s*s*aqq
        matrix[q][q] = s*s*app + 2*s*c*apq + c*c*aqq
        matrix[p][q] = matrix[q][p] = 0.0
        for i in range(d):
            if i not in (p, q):
                ip, iq = matrix[i][p], matrix[i][q]
                matrix[i][p] = matrix[p][i] = c*ip - s*iq
                matrix[i][q] = matrix[q][i] = s*ip + c*iq
            ip, iq = axes[i][p], axes[i][q]
            axes[i][p], axes[i][q] = c*ip - s*iq, s*ip + c*iq
    order = sorted(range(d), key=lambda i: (-matrix[i][i], i))[:2]
    total = sum(max(0, matrix[i][i]) for i in range(d))
    basis = []
    for axis in order:
        values = [axes[i][axis] for i in range(d)]
        sign = 1 if values[max(range(d), key=lambda i: abs(values[i]))] >= 0 else -1
        basis.append([x * sign for x in values])
    return [[sum(x*y for x,y in zip(row, axis)) for axis in basis] for row in centered], [max(0, matrix[i][i]) / total if total > 1e-12 else 0.0 for i in order], basis, means


def _read(slug: str, locator: str, program: str) -> dict:
    path = live_db()
    if path is None or not path.is_file():
        raise ValueError('The workspace has no recorded corpus facts yet.')
    con = sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, timeout=10)
    con.row_factory = sqlite3.Row
    try:
        tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        binary = con.execute('SELECT * FROM binary WHERE slug=?', (slug,)).fetchone() if slug else None
        if binary is None and locator and program and 'program_binding' in tables:
            candidates = con.execute('SELECT b.* FROM binary b JOIN program_binding p ON p.source_path=b.repo_path WHERE p.locator=? AND ltrim(p.program,\'/\')=?', (locator, program.lstrip('/'))).fetchall()
            if len(candidates) == 1:
                binary = candidates[0]
        if binary is None:
            raise ValueError('Select a registered binary with extracted function facts. Project names alone do not identify a binary.')
        knowledge_sources, observed = _knowledge_sources(con, binary, tables, locator, program)
        observed_paths = [path, Path(str(path) + '-wal'), *observed]
        revision = []
        for observed_path in observed_paths:
            try:
                stat = observed_path.stat()
                revision.append((str(observed_path), stat.st_mtime_ns, stat.st_size, stat.st_ino))
            except FileNotFoundError:
                revision.append((str(observed_path), None))
        key = (str(path.resolve()), tuple(revision), slug, locator, program)
        with _LOCK:
            if key in _CACHE:
                return _CACHE[key]
        bid = binary['id']
        binding = '(SELECT i.logical_id FROM identity i WHERE i.binary_id=f.binary_id AND i.addr=f.addr ORDER BY i.confidence DESC,i.logical_id LIMIT 1)'
        name = "COALESCE(f.name,'')"
        if 'logical_name' in tables:
            name = "CASE WHEN (f.source='USER_DEFINED' OR lower(COALESCE(f.name_origin,'')) IN ('human','human-authored','user','user_defined')) AND COALESCE(f.name,'')!='' THEN f.name ELSE COALESCE((SELECT ln.name FROM identity i JOIN logical_name ln ON ln.logical_id=i.logical_id WHERE i.binary_id=f.binary_id AND i.addr=f.addr ORDER BY i.confidence DESC,i.logical_id LIMIT 1),f.name,'') END"
        fields = ','.join('f.' + field for field in ['addr', *VECTOR_FIELDS])
        records = [dict(row) for row in con.execute(f'SELECT {fields},{name} AS display_name,{binding} AS logical_id FROM func f WHERE f.binary_id=? ORDER BY f.addr', (bid,))]
        sources = {}
        if 'recovered_function' in tables:
            for row in con.execute('SELECT addr,real_c,machine_code FROM recovered_function WHERE binary_id=? AND addr IS NOT NULL', (bid,)):
                state = 'advisory-source' if row['real_c'] == 1 else 'assembly-substrate' if row['machine_code'] else 'unknown'
                if sources.get(row['addr']) != 'advisory-source':
                    sources[row['addr']] = state
        for witness in knowledge_sources:
            kb = Path(witness['path'])
            try:
                with sqlite3.connect(kb.resolve().as_uri() + '?mode=ro', uri=True, timeout=2) as knowledge:
                    for addr, has_c, has_asm in knowledge.execute("SELECT entry_hex,length(trim(COALESCE(decompiled,'')))>0,length(trim(COALESCE(asm,'')))>0 FROM func_knowledge WHERE program=?", (witness['program'],)):
                        try:
                            address = int(str(addr), 16)
                        except ValueError:
                            continue
                        if has_c:
                            sources[address] = 'advisory-source'
                        elif has_asm and sources.get(address, 'unknown') == 'unknown':
                            sources[address] = 'assembly-only'
            except (sqlite3.Error, ValueError):
                pass  # Missing source evidence remains unknown; metrics stay useful.
    finally:
        con.close()
    dimensions = {field: sorted(value for row in records if (value := _number(row[field])) is not None) for field in ['n_instr', 'n_edges', 'n_blocks', 'cyclomatic']}
    rows = []
    for row in records:
        percentiles = []
        for field, values in dimensions.items():
            value = _number(row[field])
            if value is not None and values:
                # Midrank handles ties. A constant metric contributes no ranking evidence.
                if values[0] != values[-1]:
                    percentiles.append(100 * (bisect.bisect_left(values, value) + bisect.bisect_right(values, value) - 1) / (2 * (len(values) - 1)))
        addr = f"0x{row['addr']:0{max(8, (binary['bits'] or 32)//4)}x}"
        rows.append({'addr': addr, 'name': row['display_name'] or f"FUN_{addr[2:]}", 'logicalId': row['logical_id'], 'sourceState': sources.get(row['addr'], 'unknown'),
                     'score': round(sum(percentiles)/len(percentiles), 3) if percentiles else None,
                     'metrics': {label: _number(row[field]) for label, field in _METRICS.items()},
                     'vector': [_number(row[field]) for field in VECTOR_FIELDS]})
    values = sorted(row['score'] for row in rows if row['score'] is not None)
    thresholds = [values[len(values)//3], values[2*len(values)//3]] if len(values) >= 3 else []
    if thresholds and (thresholds[0] == thresholds[1] or thresholds[0] == values[0]):
        thresholds = []  # Tied terciles cannot establish three distinct groups.
    ordered = sorted(rows, key=lambda row: (row['score'] is None, -(row['score'] or 0), row['addr']))
    previous_score, shared_rank = None, None
    for rank, row in enumerate(ordered, 1):
        if row['score'] is not None and row['score'] != previous_score:
            shared_rank = rank
        row['rank'] = shared_rank if row['score'] is not None else None
        previous_score = row['score']
        row['tier'] = 'unknown' if row['score'] is None else ('lower' if row['score'] < thresholds[0] else 'middle' if row['score'] < thresholds[1] else 'higher') if thresholds else 'unclassified'
    complete = [row for row in rows if all(v is not None for v in row['vector'])]
    sampled = complete if len(complete) <= _MAX_POINTS else [complete[i*(len(complete)-1)//(_MAX_POINTS-1)] for i in range(_MAX_POINTS)]
    _, explained, axes, means = _pca([[math.log1p(v) for v in row['vector']] for row in sampled])
    coords = [[sum((math.log1p(value)-mean)*weight for value,mean,weight in zip(row['vector'],means,axis)) for axis in axes] for row in complete]
    points = [{key: row[key] for key in ['addr','name','sourceState','logicalId']} | {'x': xy[0], 'y': xy[1]} for row, xy in zip(complete, coords)]
    result = {'rows': rows, 'points': points, 'thresholds': thresholds, 'explained': explained, 'complete': len(complete), 'slug': binary['slug'], 'revision': str(revision), 'sourceEvidence': knowledge_sources}
    with _LOCK:
        if len(_CACHE) >= 4:
            _CACHE.pop(next(iter(_CACHE)))
        _CACHE[key] = result
    return result


def analysis(slug: str = '', locator: str = '', program: str = '', view: str = 'embeddings', q: str = '', offset: int = 0, limit: int | str = 'all', sort: str = 'score-desc') -> dict:
    if view not in {'embeddings', 'scoring'}:
        raise ValueError('Choose embeddings or scoring.')
    data = _read(slug, locator, program)
    needle = q.strip().casefold()
    try:
        address_query = int(needle, 16) if needle.startswith('0x') else None
    except ValueError:
        address_query = None
    matches = lambda row: not needle or needle in row['name'].casefold() or needle in row['addr'].casefold() or (address_query is not None and int(row['addr'], 16) == address_query)
    base = {'ok': True, 'slug': data['slug'], 'view': view, 'revision': data['revision'], 'binaryTotal': len(data['rows']), 'sourceEvidence': data['sourceEvidence'], 'claim': 'Advisory structure only. Neither projection nor complexity proves function identity, recovery, compilation, or byte parity.'}
    if view == 'embeddings':
        points = [row for row in data['points'] if matches(row)]
        matched_points = len(points)
        if len(points) > _MAX_POINTS:
            points = [points[i*(len(points)-1)//(_MAX_POINTS-1)] for i in range(_MAX_POINTS)]
        total = sum(matches(row) for row in data['rows'])
        return {**base, 'points': points, 'total': total, 'hasMore': False, 'projection': {'method': 'PCA of log1p structural facts', 'source': 'corpus func table', 'explainedVariance': data['explained'], 'basis': VECTOR_FIELDS,
                'limits': {'maxPoints': _MAX_POINTS, 'eligibleFunctions': data['complete'], 'sampledPoints': min(_MAX_POINTS, data['complete']), 'returnedPoints': len(points), 'matchingEligibleFunctions': matched_points, 'missingMetricFunctions': len(data['rows'])-data['complete']},
                'sampling': 'Fit on evenly spaced addresses across complete records; search covers all functions and projects matching complete records onto the same axes. At most 12000 matching addresses are returned.', 'reason': ('The measured vectors have no variance; overlapping points do not establish clusters.' if points and sum(data['explained']) == 0 else '') if points else 'No projected functions match. All eight recorded metrics are required; missing values are not replaced with zero.', 'claim': base['claim']}}
    rows = [row for row in data['rows'] if matches(row)]
    if sort not in {'score-desc','score-asc','name','address'}:
        raise ValueError('Choose score-desc, score-asc, name, or address sorting.')
    rows.sort(key=(lambda row: (row['name'].casefold(),row['addr'])) if sort == 'name' else (lambda row: row['addr']) if sort == 'address' else (lambda row: (row['score'] is None, (row['score'] or 0) * (1 if sort == 'score-asc' else -1),row['addr'])))
    start, cap = page_window(offset, limit)
    sliced = rows if cap is None else rows[start:start+cap]
    return {**base, 'results': [{k:v for k,v in row.items() if k!='vector'} for row in sliced], 'total': len(rows), 'offset': start, 'limit': 'all' if cap is None else cap, 'hasMore': cap is not None and start+cap<len(rows),
            'model': {'method': 'Mean within-binary midrank percentile of available nonconstant metrics', 'basis': ['instructions','edges','blocks','cyclomatic'], 'thresholds': data['thresholds'], 'tiers': 'Within-binary score terciles; unclassified when tied cutoffs cannot establish three distinct groups.', 'claim': 'Structural complexity, not trained difficulty or a probability of recovery.', 'missingValues': 'Excluded from the mean; no varying measured metrics means an unknown score.'}}


def create_analysis_router() -> APIRouter:
    router = APIRouter()

    @router.get('/dashboard/api/workbench/analysis')
    async def read_analysis(slug: str = '', program: str = '', locator: str = '', view: str = 'embeddings', q: str = '', offset: int = Query(0, ge=0), limit: str = Query('all'), sort: str = 'score-desc'):
        try:
            return await asyncio.to_thread(analysis, slug, locator, program, view, q, offset, limit, sort)
        except (ValueError, sqlite3.Error, OSError) as exc:
            return JSONResponse({'ok': False, 'error': str(exc), 'points': [], 'results': [], 'total': 0, 'hasMore': False}, status_code=422)
    return router
