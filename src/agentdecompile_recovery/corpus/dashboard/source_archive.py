"""Export a whole-program C generation and complete recorded source snapshot.

The manifest inventories every recorded function, including missing source.
Compilation, function coverage and byte proof are deliberately separate claims.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
import time
import uuid
import zipfile
from pathlib import Path
from typing import Any, Callable

from fastapi import APIRouter
from fastapi.responses import FileResponse, JSONResponse

from agentdecompile_recovery.corpus.source_claims import is_machine_code_shim
from .analysis_view import _knowledge_sources
from .common import live_db, live_root

_SOURCE_SUFFIXES = {'.c', '.cc', '.cpp', '.cxx', '.h', '.hh', '.hpp', '.hxx', '.s', '.asm', '.inc', '.cmake', '.vcxproj', '.sln', '.def'}
_BUILD_NAMES = {'CMakeLists.txt', 'Makefile', 'makefile', 'meson.build', 'meson_options.txt'}


def _checked(cancel: threading.Event) -> None:
    if cancel.is_set():
        raise InterruptedError('Source archive cancelled; no completed download was published.')


def _hashes(path: Path, cancel: threading.Event) -> tuple[str, str]:
    before = path.stat()
    sha, md5 = hashlib.sha256(), hashlib.md5()
    with path.open('rb') as stream:
        while chunk := stream.read(1024 * 1024):
            _checked(cancel)
            sha.update(chunk)
            md5.update(chunk)
    after = path.stat()
    if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError('The selected binary changed while its identity was being read.')
    return sha.hexdigest(), md5.hexdigest()


def _safe_file(path: Path, roots: list[Path]) -> Path | None:
    """Require a regular file whose entire path stays inside an allowed root."""
    try:
        absolute = path.absolute()
        resolved = path.resolve(strict=True)
        if absolute != resolved or not resolved.is_file():
            return None
        return resolved if any(resolved.is_relative_to(root) for root in roots) else None
    except (OSError, ValueError):
        return None


def _body_kind(text: str, assembly: bool = False) -> str:
    if assembly:
        return 'assembly-listing'
    if is_machine_code_shim(text):
        return 'assembly-substrate'
    # A declaration, error string or comment-only skeleton is useful context,
    # but cannot count as a function source body.
    code = re.sub(r'/\*.*?\*/|//[^\n]*', '', text, flags=re.S).strip()
    return 'advisory-c' if '{' in code and '}' in code else 'context-only'


def build_archive(params: dict[str, Any], cancel: threading.Event, on_output: Callable[[str], None] | None = None,
                  export_program: Callable[[Path, dict[str, Any]], dict[str, Any]] | None = None) -> dict[str, Any]:
    """Generate/export using the caller's shared native job path, then atomically ZIP.

    ``export_program(output_path, context)`` must return an ``ok`` boolean and
    diagnostic metadata. It receives an exact stored project/program binding.
    Existing program exports are never silently substituted for this invocation.
    """
    logs: list[str] = []

    def progress(message: str) -> None:
        logs.append(message)
        if on_output:
            on_output('\n'.join(logs[-80:]))

    _checked(cancel)
    root, db = live_root(), live_db()
    if root is None or db is None or not db.is_file():
        raise ValueError('A workspace with a recorded binary inventory is required.')
    workspace = root.resolve()
    slug = str(params.get('slug') or '').strip()
    locator = str(params.get('locator') or '').strip()
    program = str(params.get('program') or params.get('programPath') or '').strip()
    progress('Reading the complete recorded function inventory.')
    con = sqlite3.connect(db.resolve().as_uri() + '?mode=ro', uri=True, timeout=10)
    con.row_factory = sqlite3.Row
    try:
        con.execute('BEGIN')
        tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        binary = con.execute('SELECT * FROM binary WHERE slug=?', (slug,)).fetchone() if slug else None
        if binary is None and locator and program and 'program_binding' in tables:
            candidates = con.execute("SELECT b.* FROM binary b JOIN program_binding p ON p.source_path=b.repo_path WHERE p.locator=? AND ltrim(p.program,'/')=?", (locator, program.lstrip('/'))).fetchall()
            if len(candidates) == 1:
                binary = candidates[0]
        if binary is None:
            raise ValueError('Select one registered binary. A project name does not identify a source export target.')
        source = Path(binary['repo_path']).expanduser().resolve()
        sha256, fingerprint = _hashes(source, cancel)
        recorded_md5 = str(dict(binary).get('md5') or '').lower()
        inventory_bound = bool(re.fullmatch(r'[0-9a-f]{32}', recorded_md5))
        if inventory_bound and recorded_md5 != fingerprint:
            raise ValueError('The binary bytes no longer match the imported function inventory. Reimport the changed binary before exporting source.')
        bindings = [] if 'program_binding' not in tables else [dict(row) for row in con.execute('SELECT locator,program FROM program_binding WHERE source_path=?', (binary['repo_path'],))]
        exact = [row for row in bindings if (not locator or row['locator'] == locator) and (not program or str(row['program']).lstrip('/') == program.lstrip('/'))]
        context = {'slug': binary['slug'], 'binaryId': binary['id'], 'repo': str(source), 'sourceSha256': sha256, 'programFingerprint': fingerprint}
        if len(exact) == 1:
            context.update(exact[0])
        knowledge, _ = _knowledge_sources(con, binary, tables, locator, program)
        columns = {row[1] for row in con.execute('PRAGMA table_info(func)')}
        selected = [name for name in ('addr', 'name', 'name_origin', 'source', 'source_file', 'namespace', 'signature') if name in columns]
        inventory = [dict(row) for row in con.execute('SELECT '+','.join(selected)+' FROM func WHERE binary_id=? ORDER BY addr', (binary['id'],))]
        recovered = [dict(row) for row in con.execute('SELECT addr,path FROM recovered_function WHERE binary_id=? AND addr IS NOT NULL', (binary['id'],))] if 'recovered_function' in tables else []
        if 'logical_name' in tables and 'identity' in tables:
            for row in inventory:
                human = row.get('source') == 'USER_DEFINED' or str(row.get('name_origin') or '').lower() in {'human', 'human-authored', 'user', 'user_defined'}
                if human and row.get('name'):
                    continue
                name = con.execute('SELECT ln.name FROM identity i JOIN logical_name ln ON ln.logical_id=i.logical_id WHERE i.binary_id=? AND i.addr=? ORDER BY i.confidence DESC,i.logical_id LIMIT 1', (binary['id'], row['addr'])).fetchone()
                if name and name[0]:
                    row['name'] = name[0]
    finally:
        con.close()
    export_id = uuid.uuid4().hex
    output_root = workspace / 'exports' / 'source-archives'
    if output_root.resolve() != output_root:
        raise ValueError('The source export directory must remain inside this workspace.')
    directory = output_root / export_id
    directory.mkdir(parents=True, exist_ok=False)
    generated = directory / 'generated'
    generated.mkdir()
    generation: dict[str, Any] = {'ok': False, 'requested': True, 'reason': 'No unique project/program binding is available for whole-program source generation.'}
    if export_program and context.get('locator') and context.get('program'):
        _checked(cancel)
        progress('Exporting whole-program C and a header from the selected Ghidra program.')
        try:
            generation = dict(export_program(generated / 'program.c', context))
            generation['requested'] = True
        except InterruptedError:
            raise
        except Exception as exc:
            generation = {'ok': False, 'requested': True, 'error': str(exc)}
    elif not export_program:
        generation['reason'] = 'The native whole-program exporter is unavailable; preserving all recorded source witnesses.'
    _checked(cancel)
    progress('Packaging source witnesses, assembly evidence and the full function inventory.')
    manifest: dict[str, Any] = {'schemaVersion': 1, 'createdAt': time.time(), 'exportId': export_id,
        'binary': {**dict(binary), 'sha256': sha256, 'currentMd5': fingerprint,
                   'inventoryTargetBinding': 'Recorded import fingerprint matches current bytes' if inventory_bound else 'No recorded import fingerprint; inventory freshness is unverified'}, 'context': context,
        'generationTask': generation, 'claim': 'Source snapshot. Compilation and byte verification are not established by this archive.',
        'files': [], 'warnings': [], 'functions': []}
    observation = generation.get('observation') or {}
    native_count = observation.get('functionCount') if isinstance(observation, dict) else None
    if (isinstance(native_count, bool) or not isinstance(native_count, int) or native_count < 0
            or str(observation.get('md5') or '').lower() != fingerprint):
        native_count = None
    inventory_matches = native_count == len(inventory) if native_count is not None else None
    inventory_warning = ''
    if inventory_matches is False:
        inventory_warning = (f'The selected Ghidra program currently reports {native_count} functions, but the saved corpus inventory contains {len(inventory)}. '
                             'The per-function manifest covers the saved records only. Refresh extracted facts before treating it as the current program inventory.')
        manifest['warnings'].append({'stage': 'inventory', 'reason': inventory_warning})
    known = {int(row['addr']): row for row in inventory}
    exported: dict[int, list[dict]] = {address: [] for address in known}
    seen: dict[tuple[int, str, str], str] = {}
    temporary = directory / 'source.zip.partial'
    destination = directory / 'source.zip'
    allowed_roots = [workspace]
    configured = os.environ.get('AGENT_DECOMPILE_RECOVERED_DIR', '').strip()
    if configured:
        allowed_roots.append(Path(configured).expanduser().resolve())
    try:
        with zipfile.ZipFile(temporary, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True) as archive:
            def put(name: str, content: bytes, claim: str, provenance: dict) -> None:
                _checked(cancel)
                archive.writestr(name, content)
                manifest['files'].append({'path': name, 'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest(), 'claim': claim, 'provenance': provenance})

            def witness(address: int, text: str, provenance: dict, assembly: bool = False) -> None:
                if address not in known or not text.strip():
                    return
                kind = _body_kind(text, assembly)
                content = text.encode('utf-8')
                digest = hashlib.sha256(content).hexdigest()
                key = (address, kind, digest)
                if key in seen:
                    for item in exported[address]:
                        if item['path'] == seen[key]:
                            item['provenance'].append(provenance)
                    return
                folder = 'source/functions' if kind == 'advisory-c' else 'assembly/substrate' if kind == 'assembly-substrate' else 'assembly/listings' if assembly else 'context/functions'
                suffix = '.asm' if assembly else '.c'
                name = f'{folder}/0x{address:08x}-{digest[:16]}{suffix}'
                put(name, content, kind, provenance)
                seen[key] = name
                exported[address].append({'path': name, 'claim': kind, 'sha256': digest, 'provenance': [provenance]})

            generated_count = 0
            generated_c = False
            for path in sorted(generated.rglob('*')):
                _checked(cancel)
                safe = _safe_file(path, [generated])
                if safe is None or safe.suffix.lower() not in _SOURCE_SUFFIXES:
                    continue
                content = safe.read_bytes()
                if not content:
                    continue
                shim = is_machine_code_shim(content.decode('utf-8', errors='replace'))
                is_c = safe.suffix.lower() in {'.c', '.cc', '.cpp', '.cxx'}
                generated_c |= is_c
                prefix = 'assembly/generated' if shim else 'source/whole-program'
                put(prefix+'/'+safe.relative_to(generated).as_posix(), content, 'assembly-substrate' if shim else 'advisory-generated-source', {'tool': 'Ghidra whole-program exporter', 'currentExecution': True, 'generationSucceeded': generation.get('ok') is True})
                generated_count += 1
            generation['filesWritten'] = generated_count
            generation['wholeProgramCWritten'] = generated_c
            if generation.get('ok') and not generated_c:
                generation.update(ok=False, error='The exporter reported success but produced no C file in this execution.')
            for index, source_db in enumerate(knowledge, 1):
                _checked(cancel)
                progress(f'Reading complete source text from witness {index} of {len(knowledge)}.')
                try:
                    with sqlite3.connect(Path(source_db['path']).as_uri()+'?mode=ro', uri=True, timeout=10) as kb:
                        kb.execute('BEGIN')
                        rows_read = 0
                        for entry, code, assembly in kb.execute('SELECT entry_hex,decompiled,asm FROM func_knowledge WHERE program=?', (source_db['program'],)):
                            _checked(cancel)
                            rows_read += 1
                            try:
                                address = int(str(entry), 16)
                            except ValueError:
                                continue
                            if code:
                                witness(address, str(code), source_db)
                            if assembly:
                                witness(address, str(assembly), source_db, assembly=True)
                            if rows_read % 200 == 0:
                                progress(f'Read {rows_read} function records from witness {index}; preserved {len(seen)} source and assembly files.')
                except sqlite3.Error as exc:
                    manifest['warnings'].append({'source': source_db['path'], 'reason': str(exc)})
            for row in recovered:
                _checked(cancel)
                path = Path(str(row['path']))
                if not path.is_absolute():
                    path = workspace / path
                safe = _safe_file(path, allowed_roots)
                if safe is None:
                    manifest['warnings'].append({'source': str(path), 'reason': 'Recorded source is missing or outside its allowed source root.'})
                    continue
                witness(int(row['addr']), safe.read_text(encoding='utf-8', errors='replace'), {'kind': 'binary-bound recovered_function row', 'path': str(safe), 'freshness': 'Not independently reverified'})
            # Include project headers/layout only from the same fingerprint-bound
            # workflow directory used to produce a selected source witness.
            for source_db in knowledge:
                if source_db.get('kind') != 'fingerprint-bound workflow knowledge':
                    continue
                work = Path(source_db['path']).parent
                candidates = [work / 'ghidra_types.h']
                source_tree = work / 'source'
                if source_tree.is_dir() and source_tree.resolve() == source_tree:
                    candidates.extend(source_tree.rglob('*'))
                for path in sorted(candidates):
                    _checked(cancel)
                    safe = _safe_file(path, [work])
                    if safe is None or (safe.suffix.lower() not in _SOURCE_SUFFIXES and safe.name not in _BUILD_NAMES):
                        continue
                    content = safe.read_bytes()
                    kind = _body_kind(content.decode('utf-8', errors='replace'), safe.suffix.lower() in {'.s', '.asm'})
                    prefix = 'assembly/projects' if kind in {'assembly-substrate', 'assembly-listing'} else 'source/projects'
                    put(prefix+'/'+source_db['runId']+'/'+safe.relative_to(work).as_posix(), content, kind, source_db)
            # A protected file transformation or external replacement during export
            # invalidates the target identity; never publish under the old hash.
            final_sha, _ = _hashes(source, cancel)
            if final_sha != sha256:
                raise ValueError('The selected binary changed during export; the archive was not published.')
            source_count = substrate_count = assembly_count = 0
            for row in inventory:
                address = int(row['addr'])
                entries = exported[address]
                has_source = any(item['claim'] == 'advisory-c' for item in entries)
                has_substrate = any(item['claim'] == 'assembly-substrate' for item in entries)
                source_count += has_source
                substrate_count += has_substrate
                assembly_count += any(item['claim'] == 'assembly-listing' for item in entries)
                manifest['functions'].append({**row, 'addr': f'0x{address:08x}', 'sourceAvailable': has_source,
                    'files': entries, 'compiles': None, 'byteVerified': None,
                    'missingReason': None if has_source else 'No address-bound C body is available. Whole-program output, if present, has not been enumerated into individual function coverage.'})
            coverage = {'inventoryFunctions': len(inventory), 'sourceFunctions': source_count, 'missingSourceFunctions': len(inventory)-source_count,
                'currentProgramFunctions': native_count, 'inventoryMatchesCurrentProgram': inventory_matches,
                'assemblySubstrateFunctions': substrate_count, 'assemblyListingFunctions': assembly_count,
                'completeRecordedFunctionSource': bool(inventory) and source_count == len(inventory),
                'wholeProgramCWritten': generated_c, 'wholeProgramFunctionCoverage': None, 'compiles': None, 'byteVerified': None}
            manifest['coverage'] = coverage
            manifest['partial'] = not coverage['completeRecordedFunctionSource'] or generation.get('ok') is not True or not inventory_bound or inventory_matches is False
            if not inventory_bound:
                manifest['warnings'].append({'stage': 'inventory', 'reason': 'No recorded import fingerprint is available; the saved inventory has not been bound to the current target bytes.'})
            if not generation.get('ok'):
                manifest['warnings'].append({'stage': 'whole-program-source', 'reason': generation.get('error') or generation.get('reason') or 'Whole-program export did not complete.'})
            readme = f'''# {binary['slug']} source archive

This archive records source for the selected binary with SHA-256 `{sha256}`.
The manifest lists all {len(inventory)} recorded functions, including missing source.
{inventory_warning}

`source/whole-program/` contains C and headers generated during this export when the Ghidra exporter was available. Exporter success does not establish per-function coverage or compilation.
`source/functions/` contains full address-bound C witnesses. These are advisory source, not proven original source.
`assembly/` keeps machine-code substrate and assembly listings separate from C source coverage.
`source/projects/` preserves existing project layout, headers and build files from fingerprint-bound recovery workspaces when available. Existing layouts may contain unfinished stubs.
`context/` contains declarations or other text that does not establish a function body.

Address-bound C witnesses: {source_count} of {len(inventory)}. Missing C witnesses: {len(inventory)-source_count}.
Whole-program C file written in this execution: {generated_c}.
Compilation and byte verification have not been performed by this export. Read `manifest.json` for provenance and exact coverage limitations.
'''
            archive.writestr('README.md', readme)
            archive.writestr('manifest.json', json.dumps(manifest, indent=2, ensure_ascii=False))
        _checked(cancel)
        temporary.replace(destination)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    progress(f'Source ZIP ready: {source_count} address-bound C witnesses, {len(inventory)-source_count} without an address-bound C body. See the manifest for whole-program output.')
    return {'ok': True, 'exportId': export_id, 'path': str(destination),
        'artifactUrl': f'/dashboard/api/workbench/source-archives/{export_id}/download',
        'downloadUrl': f'/dashboard/api/workbench/source-archives/{export_id}/download', 'filename': str(binary['slug'])+'-source.zip',
        'coverage': coverage, 'partial': manifest['partial'], 'generationTask': generation,
        'warnings': manifest['warnings'][:20], 'warningCount': len(manifest['warnings']),
        'bytes': destination.stat().st_size, 'sourceSha256': sha256,
        'claim': manifest['claim']}


def create_source_archive_router() -> APIRouter:
    router = APIRouter()

    @router.get('/dashboard/api/workbench/source-archives/{export_id}/download')
    def download(export_id: str):
        root = live_root()
        if root is None or not re.fullmatch(r'[0-9a-f]{32}', export_id):
            return JSONResponse({'error': 'Source archive not found'}, status_code=404)
        directory = root.resolve() / 'exports' / 'source-archives' / export_id
        path = _safe_file(directory / 'source.zip', [directory])
        if path is None:
            return JSONResponse({'error': 'Source archive not found'}, status_code=404)
        return FileResponse(path, filename='source-'+export_id+'.zip', media_type='application/zip', headers={'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store'})

    return router
