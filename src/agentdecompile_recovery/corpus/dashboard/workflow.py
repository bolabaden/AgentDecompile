"""Missing-only recovery continuation for the shared preparation coordinator.

All execution uses catalog jobs. An action returning zero is not a proof gate;
receipts and target prerequisites decide the visible result of each stage.
"""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import time
from pathlib import Path
from typing import Any, Callable

STAGES = [
    ('calibrate-global', 'Check compiler and layout'),
    ('assembly-floor', 'Create source project'),
    ('recover-source', 'Compiling C replacement'),
    ('apply-cross-build', 'Place compiling C in equivalent builds'),
    ('leftover-recover', 'Targeted recovery'),
    ('verify-byte-accuracy', 'Byte audit'),
]
DEFAULT_BUDGET_SECONDS = None
MAX_BUDGET_SECONDS = 7 * 24 * 60 * 60
VERSION = 3


def read_object(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def transient_failure(result: dict[str, Any]) -> bool:
    """Retry only failures with evidence that another attempt can help.

    Timeouts are deliberately excluded: an MCP request can time out while its
    native mutation continues, and repeating it could duplicate accepted work.
    """
    text = str(result.get('error') or result.get('log') or '').lower()
    deterministic = ('invalid', 'unsupported', 'permission denied', 'not found', 'unknown tool', 'syntaxerror', 'timeout', 'timed out')
    return not any(word in text for word in deterministic) and any(word in text for word in (
        'connection refused', 'temporarily unavailable', 'database is locked', 'resource busy', 'http 503', 'http 429',
    ))


def _compiler(profile: dict[str, Any]) -> str | None:
    value = profile.get('compilerScript')
    if not isinstance(value, str) or not value:
        return None
    path = Path(value).expanduser()
    return str(path) if path.is_file() else shutil.which(value)


def _leftover_queue(work: Path, root: Path) -> Path | None:
    for candidate in (work / 'logical_queue.jsonl', root / 'output' / 'work_queue' / 'logical_queue.jsonl'):
        if candidate.is_file():
            return candidate
    return None


def _knowledge_has_program(path: Path, program: str) -> bool:
    if not path.is_file():
        return False
    try:
        with sqlite3.connect(f'{path.as_uri()}?mode=ro', uri=True) as con:
            return bool(con.execute('SELECT 1 FROM func_knowledge WHERE program=? LIMIT 1', (program,)).fetchone())
    except (sqlite3.Error, ValueError):
        return False


def continue_recovery(row: dict[str, Any], root: Path, db: Path,
                      action: Callable[..., dict[str, Any]], update: Callable[..., None]) -> None:
    """Keep every stage visible and execute only the capabilities we can supply."""
    programs = row.get('programs') or []
    totals = {key: 0 for key, _ in STAGES}
    for program in programs:
        checkpoint = row['checkpoints'].setdefault(program, {})
        states = checkpoint.setdefault('workflow', {})
        work = root / 'recovery' / row['id'] / str(checkpoint.get('binaryId') or 'unresolved')
        context = {'locator': row['locator'], 'program': program, 'slug': checkpoint.get('slug') or '', 'repo': checkpoint.get('repoPath') or ''}

        def result(key: str, status: str, reason: str, **details: Any) -> None:
            states[key] = {'status': status, 'reason': reason, 'updatedAt': time.time(), **details}
            if status == 'completed':
                totals[key] += 1
            update(key, 'running', f'{program}: {reason}', completed=totals[key], total=len(programs),
                   currentProgram=program, outcomes={p: row['checkpoints'].get(p, {}).get('workflow', {}).get(key, {}) for p in programs})

        def block_after(start: str, reason: str) -> None:
            keys = [key for key, _ in STAGES]
            for key in keys[keys.index(start):]:
                result(key, 'blocked', reason, dependencies=[start])

        if not checkpoint.get('analysisConfirmed') or not checkpoint.get('factsComplete'):
            block_after('calibrate-global', 'Waiting for confirmed analysis and function facts.')
            continue
        work.mkdir(parents=True, exist_ok=True)
        profile_path = work / 'compiler-profile.json'
        # A project can supply its measured configuration at workspace level.
        configured = os.environ.get('AGENT_DECOMPILE_COMPILER_PROFILE', '').strip()
        if configured:
            profile_path = Path(configured).expanduser()
        elif not profile_path.exists():
            profile_path = root / 'compiler-profile.json'
        profile = read_object(profile_path)
        header = work / 'ghidra_types.h'
        layout_config = {'db': str(db), 'binaryId': checkpoint['binaryId'], 'program': program, 'header': str(header)}
        exported_types = action('calibrate-global', 'mcp.execute-script', {'programPath': program, '_preparationProbe': True, 'code': layout_script(layout_config), 'timeout': 180}, context)
        type_data = exported_types.get('data') or {}
        fields = {'work-dir': str(work)}
        if exported_types['ok'] and isinstance(type_data, dict) and type_data.get('types', 0) > 0:
            fields['types-header'] = str(header)
        else:
            if header.exists():
                header.replace(work / 'types-unavailable.h')
            result('calibrate-global', 'blocked', exported_types.get('error') or 'Target layout evidence is unavailable. Existing metadata has been retained.', jobId=exported_types.get('jobId'))
            block_after('assembly-floor', 'Waiting for target layout evidence.')
            continue
        if profile:
            fields['compiler-profile'] = str(profile_path)
        calibration = action('calibrate-global', 'corpus.calibrate-global', fields, context)
        calibration_receipt = read_object(work / 'calibrate-global.json')
        compiler = _compiler(profile)
        target_bound = (profile.get('programFingerprint') and profile['programFingerprint'] == checkpoint.get('programFingerprint')) or (profile.get('architecture') and profile['architecture'] == checkpoint.get('architecture'))
        if not target_bound:
            compiler = None
        if not calibration['ok'] or calibration_receipt.get('state') != 'done' or not compiler:
            gaps = calibration_receipt.get('gaps') or []
            if not profile:
                compiler_gap = 'Target compiler profile missing: installed compilers do not establish this binary\'s compiler, flags, or ABI.'
            elif not target_bound:
                compiler_gap = 'Compiler profile is not bound to this target fingerprint or architecture.'
            elif not compiler:
                compiler_gap = 'Configured compiler script is unavailable.'
            else:
                compiler_gap = 'Calibration evidence missing: ' + ', '.join(gaps)
            reason = calibration.get('error') or compiler_gap
            result('calibrate-global', 'blocked', reason, receipt=str(work / 'calibrate-global.json'), nextAction='Configure target compiler and layout evidence')
            block_after('assembly-floor', 'Waiting for target compiler and layout evidence.')
            continue
        checkpoint['toolchain'] = compiler
        result('calibrate-global', 'completed', 'Compiler and layout inputs available; calibration receipt retained.', receipt=str(work / 'calibrate-global.json'))

        source = work / 'source'
        layout = action('assembly-floor', 'corpus.workspace', {'db': str(db), 'donor-slug': checkpoint['slug'], 'out': str(source)}, context)
        if not layout['ok']:
            result('assembly-floor', 'blocked', layout.get('error') or layout.get('log') or 'Project layout could not be written.', jobId=layout.get('jobId'))
        else:
            # workspace writes compilation-unit stubs, not executable assembly.
            result('assembly-floor', 'partial', 'Source layout created. No linked assembly-floor receipt exists.', jobId=layout.get('jobId'), sourceDirectory=str(source))
        # Fresh programs produce their own source cache in the live JVM. It is
        # scoped to the executable fingerprint rather than a reused basename.
        fingerprint = checkpoint.get('programFingerprint') or 'unknown'
        program_kb = work / ('knowledge-' + fingerprint + '.sqlite')
        progress_path = work / 'decompilation-progress.json'
        if (checkpoint.get('knowledgeFingerprint') != fingerprint or
                checkpoint.get('knowledgeDb') != str(program_kb) or not program_kb.is_file()):
            # Cursor and completion describe this exact cache, never another run's path.
            for key in ('knowledgeCursor', 'knowledgeComplete', 'knowledgeAvailable'):
                checkpoint.pop(key, None)
        cursor = checkpoint.get('knowledgeCursor', '')
        row['functionProgressFile'] = str(progress_path)
        try:
            while not checkpoint.get('knowledgeComplete') or checkpoint.get('knowledgeFingerprint') != fingerprint:
                config = {'kb': str(program_kb), 'program': program, 'cursor': cursor, 'progress': str(progress_path)}
                decompiled = action('recover-source', 'mcp.execute-script', {'programPath': program, '_preparationProbe': True, 'code': knowledge_script(config), 'timeout': 180}, context)
                payload = decompiled.get('data') or {}
                if not decompiled['ok'] or not isinstance(payload, dict) or 'more' not in payload:
                    result('recover-source', 'partial', decompiled.get('error') or 'Source extraction stopped; completed functions were retained.', jobId=decompiled.get('jobId'))
                    break
                cursor = payload['cursor']
                checkpoint.update(knowledgeCursor=cursor, knowledgeComplete=not payload['more'], knowledgeFingerprint=fingerprint,
                                  knowledgeDb=str(program_kb), knowledgeAvailable=payload['available'])
                update('recover-source', 'running', f'{program}: {payload["attempted"]} of {payload["total"]} functions attempted.',
                       workProgress={'completed':payload['attempted'],'total':payload['total'],'unit':'functions'})
        finally:
            row.pop('functionProgressFile', None)
        if not _knowledge_has_program(program_kb, program):
            block_after('recover-source', 'No decompiled C is available after the recorded extraction attempts.')
            continue
        generated = action('recover-source', 'corpus.ghidra-bulk', {
            'program': program, 'repo': checkpoint['repoPath'], 'db': str(db), 'out-dir': str(source),
            'kb': str(program_kb), 'compiler': compiler, 'mode': 'compile-only', 'workers': 1,
            **({'extract-raw': checkpoint['executablePath']} if checkpoint.get('executablePath') else {}),
        }, context)
        result('recover-source', 'completed' if generated['ok'] else 'partial',
               'C replacement attempts finished; compilation and proof remain separate.' if generated['ok'] else generated.get('error') or generated.get('log') or 'C replacement left unresolved functions.', jobId=generated.get('jobId'))
        # Successful source from partial runs is useful and can be placed.
        placed = action('apply-cross-build', 'corpus.cross-place', {
            'from': program, 'db': str(db), 'out-dir': str(source), 'repo': checkpoint['repoPath'],
        }, context)
        result('apply-cross-build', 'completed' if placed['ok'] else 'partial',
               'Placement attempts finished; each recipient still requires compilation and proof.' if placed['ok'] else placed.get('error') or placed.get('log') or 'No source could be placed.', jobId=placed.get('jobId'))

        original = Path(checkpoint.get('executablePath') or '')
        if not original.is_file():
            block_after('leftover-recover', 'Original executable unavailable for target extraction and byte comparison.')
            continue
        remaining = max(1, int(row['deadline'] - time.time())) if row.get('deadline') is not None else None
        recovered = action('leftover-recover', 'reconstruct.one-shot', {
            'input': str(original), 'work-dir': str(work / 'proof'), 'project': row['locator'],
            'project-program': program, 'autonomous': True,
            **({'autonomous-max-wall-seconds': remaining} if remaining is not None else {}),
            'resume': True, 'skip-enrichment': True, 'dump-source': str(work / 'readable'),
        }, context)
        fallback = None
        if not recovered['ok']:
            fallback = 'corpus.genproject'
            queue = _leftover_queue(work, root)
            repo = checkpoint.get('repoPath') or context.get('repo') or ''
            if queue is not None and repo:
                result('leftover-recover', 'partial', recovered.get('error') or 'Reconstruct left unresolved functions.',
                       jobId=recovered.get('jobId'), nextFallback=fallback)
                generated = action('leftover-recover', 'corpus.genproject', {
                    'queue': str(queue), 'out': str(work / 'leftover-project'), 'db': str(db),
                    'raw': str(original), 'repo-path': repo, 'leftover-only': True,
                }, context)
                if generated['ok']:
                    fallback = 'corpus.compile-link'
                    result('leftover-recover', 'partial', 'Wrote leftover project.',
                           jobId=generated.get('jobId'), nextFallback=fallback)
            if source.is_dir():
                fallback = 'corpus.compile-link'
                result('leftover-recover', 'partial', recovered.get('error') or 'Compile remaining leftover units.',
                       jobId=recovered.get('jobId'), nextFallback=fallback)
                linked = action('leftover-recover', 'corpus.compile-link', {
                    'src-dir': str(source), 'out': str(work / 'leftover-link'),
                    **({'compiler': compiler} if compiler else {}),
                }, context)
                if linked['ok']:
                    fallback = None
                    recovered = linked
        result('leftover-recover', 'completed' if recovered['ok'] else 'partial',
               'Bounded recovery finished; proof receipts decide accepted coverage.' if recovered['ok'] else recovered.get('error') or recovered.get('log') or 'Recovery stopped with unresolved functions.',
               jobId=recovered.get('jobId'), **({'nextFallback': fallback} if fallback else {}))
        # This gate uses the canonical independent receipt audit. It does not
        # infer byte identity from process completion, source files, or linking.
        audit = action('verify-byte-accuracy', 'recover.claim-report', {'work-dir': str(work / 'proof')}, context)
        data = audit.get('data') or {}
        verified = sum(int(claim.get('count') or 0) for claim in data.get('claims', []) if claim.get('class') == 'objdiff-verified-semantic') if isinstance(data, dict) else 0
        result('verify-byte-accuracy', 'partial' if verified else 'blocked',
               f'{verified} receipt-backed semantic functions; full binary byte identity is not established.' if verified else 'No accepted byte-verification receipts. Compilation is not a match.',
               jobId=audit.get('jobId'), verifiedFunctions=verified, byteExact=False)

    for key, _ in STAGES:
        outcomes = [row['checkpoints'].get(p, {}).get('workflow', {}).get(key, {}) for p in programs]
        completed = totals[key]
        status = 'completed' if programs and completed == len(programs) else ('partial' if any(r.get('status') in {'partial', 'completed'} for r in outcomes) else 'blocked')
        reasons = list(dict.fromkeys(r.get('reason', '') for r in outcomes if r.get('status') != 'completed'))
        update(key, status, '; '.join(reasons[:3]) or f'{completed} programs completed this stage.', completed=completed, total=len(programs), currentProgram='', currentAction='')


def merge_evidence(db: str, run: str) -> dict[str, Any]:
    """Add match-supported identities without rebuilding or renumbering them.

    An edge cannot merge two existing logical IDs or put different functions
    from the same build into one new identity. Such conflicts remain available
    in the match table. Concrete human metadata is never rewritten.
    """
    from agentdecompile_recovery.corpus.store import connect
    from agentdecompile_recovery.corpus.stabs_link import ensure_columns, propagate_source_files

    con = connect(Path(db))
    try:
        ensure_columns(con)
        con.execute('BEGIN IMMEDIATE')
        existing = {(r['binary_id'], r['addr']): r['logical_id'] for r in con.execute('SELECT * FROM identity')}
        parent, anchors, binaries, witnesses = {}, {}, {}, {}

        def find(node):
            if node not in parent:
                parent[node] = node
                anchors[node] = {existing[node]} if node in existing else set()
                binaries[node] = {node[0]}
            root = node
            while parent[root] != root:
                root = parent[root]
            while parent[node] != node:
                old = parent[node]
                parent[node] = root
                node = old
            return root

        conflicts = 0
        for match in con.execute("SELECT * FROM match WHERE run=? AND status IN ('auto','verify') ORDER BY score DESC", (run,)):
            source, target = (match['src_binary'], match['src_addr']), (match['dst_binary'], match['dst_addr'])
            left, right = find(source), find(target)
            if left != right:
                if len(anchors[left] | anchors[right]) > 1 or binaries[left] & binaries[right]:
                    conflicts += 1
                    continue
                parent[right] = left
                anchors[left] |= anchors[right]
                binaries[left] |= binaries[right]
            evidence = {'run': run, 'source': source, 'target': target, 'score': match['score'], 'status': match['status'], 'witness': match['evidence']}
            for node in (source, target):
                witnesses.setdefault(node, evidence)
        groups = {}
        for node in parent:
            groups.setdefault(find(node), []).append(node)
        created = bound = 0
        touched = set()
        for root, members in groups.items():
            if len(members) < 2:
                continue
            old_ids = anchors[find(root)]
            logical = next(iter(old_ids)) if old_ids else None
            if logical is None:
                # Prefer a human-authored name when choosing the display witness.
                facts = [con.execute('SELECT f.*,b.game FROM func f JOIN binary b ON b.id=f.binary_id WHERE f.binary_id=? AND f.addr=?', node).fetchone() for node in members]
                facts = [fact for fact in facts if fact is not None]
                if not facts:
                    continue
                facts.sort(key=lambda fact: (str(fact['name_origin']).lower() not in {'human','user_defined','user'}, str(fact['name'] or '').startswith('FUN_')))
                chosen = facts[0]
                logical = con.execute('INSERT INTO logical_function (canon_key,canon_class,canon_method,game,best_name,best_signature,source_file,object_file,n_members,notes) VALUES(?,?,?,?,?,?,?,?,0,?)',
                    tuple(chosen[key] for key in ('canon_key','canon_class','canon_method','game','name','signature','source_file','object_file')) + ('Match-supported identity; concrete metadata preserved.',)).lastrowid
                created += 1
            touched.add(logical)
            group_score = min(float(witnesses[node]['score'] or 0) for node in members if node in witnesses)
            group_status = 'verify' if any(witnesses[node]['status'] == 'verify' for node in members if node in witnesses) else 'auto'
            for node in members:
                if node in existing or node not in witnesses:
                    continue
                witness = witnesses[node]
                witness = {**witness, 'componentMinimumScore': group_score, 'componentStatus': group_status}
                confidence = round(.5 + .5 * group_score if group_status == 'auto' else .35 + .45 * group_score, 4)
                con.execute('INSERT INTO identity(logical_id,binary_id,addr,confidence,method,evidence) VALUES(?,?,?,?,?,?)',
                    (logical, *node, confidence, 'match:' + run + ':' + witness['status'], json.dumps(witness)))
                bound += 1
        for logical in touched:
            con.execute('UPDATE logical_function SET n_members=(SELECT COUNT(*) FROM identity WHERE logical_id=?) WHERE id=?', (logical, logical))
        con.commit()
        carried = propagate_source_files(con)
        return {'createdIdentities': created, 'boundFunctions': bound, 'retainedConflicts': conflicts, 'sourceAttributions': carried,
                'claim': 'advisory', 'metadataPolicy': 'Existing identities and concrete names, labels, comments, and structures retained.'}
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def input_revision(fields: dict[str, Any]) -> list[Any]:
    """A repaired input at the same path is a new attempt, not a stale failure."""
    import hashlib
    revisions = []
    for key in ('compiler-profile', 'types-header', 'compiler', 'input', 'binary', 'source', 'kb'):
        value = fields.get(key)
        if not isinstance(value, str) or not value:
            continue
        path = Path(value).expanduser()
        try:
            stat = path.stat()
            digest = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() and stat.st_size <= 4 * 1024 * 1024 else None
            revisions.append([key, str(path), stat.st_size, stat.st_mtime_ns, digest])
        except OSError:
            revisions.append([key, str(path), 'unavailable'])
    return revisions


def knowledge_script(config: dict[str, Any]) -> str:
    """Decompile one bounded missing-only chunk in the existing owned JVM."""
    return 'import json\nconfig = json.loads(' + repr(json.dumps(config)) + ')\n' + r'''
import time, sqlite3
from pathlib import Path
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import TimeoutTaskMonitor
from java.util.concurrent import TimeUnit
from agentdecompile_recovery.corpus.ingest_ghidra_knowledge import SCHEMA
monitor = TimeoutTaskMonitor.timeoutIn(120, TimeUnit.SECONDS)
con = sqlite3.connect(config['kb'])
con.executescript(SCHEMA)
con.execute('CREATE TABLE IF NOT EXISTS knowledge_attempt (program TEXT, entry_hex TEXT, error TEXT, PRIMARY KEY(program,entry_hex))')
decompiler = DecompInterface()
started = time.time()
count = 0
last = config['cursor']
failed = 0
try:
    if not decompiler.openProgram(currentProgram):
        raise RuntimeError('The decompiler could not open the already analyzed program.')
    manager = currentProgram.getFunctionManager()
    total = int(manager.getFunctionCount())
    iterator = manager.getFunctions(toAddr(config['cursor']), True) if config['cursor'] else manager.getFunctions(True)
    while iterator.hasNext() and count < 64 and time.time() - started < 90:
        function = iterator.next()
        entry = function.getEntryPoint()
        address = str(entry)
        last = hex(int(str(entry), 16) + 1)
        if con.execute('SELECT 1 FROM knowledge_attempt WHERE program=? AND entry_hex=?', (config['program'], address)).fetchone():
            continue
        if con.execute("SELECT 1 FROM func_knowledge WHERE program=? AND entry_hex=? AND decompiled IS NOT NULL AND decompiled<>''", (config['program'], address)).fetchone():
            continue
        outcome = decompiler.decompileFunction(function, 20, monitor)
        if outcome.decompileCompleted() and outcome.getDecompiledFunction() is not None:
            code = str(outcome.getDecompiledFunction().getC())
            offset = None
            try:
                info = currentProgram.getMemory().getAddressSourceInfo(entry)
                offset = int(info.getFileOffset()) if info is not None else None
            except Exception:
                pass
            values = (config['program'], address, str(function.getName()), int(function.getBody().getNumAddresses()), offset,
                      str(function.getCallingConventionName()), str(function.getPrototypeString(False,False)), code, None, None, None)
            # The KB is fingerprint-scoped. Existing source and authored metadata
            # are retained; this stage fills only records not already available.
            con.execute('INSERT OR IGNORE INTO func_knowledge VALUES(?,?,?,?,?,?,?,?,?,?,?)', values)
            error = ''
        else:
            error = str(outcome.getErrorMessage() or 'Decompiler produced no source')
            failed += 1
        con.execute('INSERT OR IGNORE INTO knowledge_attempt VALUES(?,?,?)', (config['program'], address, error))
        con.commit()
        count += 1
        done = int(con.execute('SELECT COUNT(*) FROM knowledge_attempt WHERE program=?', (config['program'],)).fetchone()[0])
        target = Path(config['progress'])
        temporary = target.with_suffix('.tmp')
        temporary.write_text(json.dumps({'completed':done,'total':total,'unit':'functions','program':config['program'],'updatedAt':time.time()}))
        temporary.replace(target)
    more = bool(iterator.hasNext())
    available = int(con.execute("SELECT COUNT(*) FROM func_knowledge WHERE program=? AND decompiled IS NOT NULL AND decompiled<>''", (config['program'],)).fetchone()[0])
    done = int(con.execute('SELECT COUNT(*) FROM knowledge_attempt WHERE program=?', (config['program'],)).fetchone()[0])
    con.execute('INSERT OR REPLACE INTO ingest_status VALUES(?,?,?,?,?)', (config['program'],done,total,time.time()-started,int(not more)))
    con.commit()
    __result__ = json.dumps({'cursor':last,'more':more,'attempted':done,'total':total,'available':available,'chunkFailed':failed,'claim':'advisory','programFingerprint':str(currentProgram.getExecutableMD5())})
finally:
    decompiler.dispose()
    con.close()
'''


def layout_script(config: dict[str, Any]) -> str:
    """Export missing type evidence without replacing curated stored layouts."""
    return 'import json\nconfig = json.loads(' + repr(json.dumps(config)) + ')\n' + r'''
from agentdecompile_recovery.corpus.store import connect
from agentdecompile_recovery.corpus.export_types import SCHEMA, emit_struct, emit_enum, c_ident
from agentdecompile_recovery.corpus.build_types_header import build_header
from ghidra.program.model.data import Enum, Structure, Union
from ghidra.util.task import TimeoutTaskMonitor
from java.util.concurrent import TimeUnit
monitor = TimeoutTaskMonitor.timeoutIn(120, TimeUnit.SECONDS)
con = connect(config['db'])
try:
    con.executescript(SCHEMA)
    inserted = 0
    for data_type in currentProgram.getDataTypeManager().getAllDataTypes():
        monitor.checkCancelled()
        if isinstance(data_type, (Structure, Union)):
            rendered = emit_struct(data_type)
            kind = 'union' if isinstance(data_type, Union) else 'struct'
        elif isinstance(data_type, Enum):
            rendered = emit_enum(data_type)
            kind = 'enum'
        else:
            continue
        if rendered is None:
            continue
        definition, fields = rendered
        changed = con.execute('INSERT OR IGNORE INTO ghidra_type(binary_id,name,kind,size,definition,n_fields) VALUES(?,?,?,?,?,?)',
            (config['binaryId'],c_ident(data_type.getName()),kind,int(data_type.getLength()),definition,fields))
        inserted += changed.rowcount
    con.commit()
    result = build_header(con, config['binaryId'], config['header'], program=config['program'])
    result.update(inserted=inserted, claim='context-hint', metadataPolicy='Existing stored layouts retained')
    __result__ = json.dumps(result)
finally:
    con.close()
'''
