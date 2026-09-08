"""Persist selected-function observations without assigning proof credit."""

from __future__ import annotations

import hashlib
import json
import time
import os
import threading
import uuid
from pathlib import Path
from typing import Any

from .common import live_root, parse_address, query_db

_LOCK = threading.RLock()


def _context(locator: str, program: str) -> tuple[str, str]:
    if locator and not locator.startswith(('ghidra:', 'http:', 'https:')):
        from agentdecompile_recovery.corpus.ghidra_project import classify_locator
        info = classify_locator(locator)
        locator = str(Path(info.get('canonical') or locator).resolve())
    return locator, program.strip('/')


def evidence_path(locator: str, program: str, address: str) -> Path | None:
    root = live_root()
    addr = parse_address(address)
    if root is None or addr is None:
        return None
    locator, program = _context(locator, program)
    key = json.dumps([locator, program, addr])
    return root / "function-evidence" / (hashlib.sha256(key.encode()).hexdigest() + ".json")


def record(params: dict[str, Any], tool: str, payload: dict[str, Any]) -> None:
    address = params.get("functionIdentifier") or params.get("addressOrSymbol") or params.get("addr")
    program = str(params.get("programPath") or params.get("program") or "")
    locator = str(params.get("locator") or "")
    path = evidence_path(locator, program, str(address or ""))
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    receipt = {"tool": tool, "locator": locator, "program": program, "address": address, "observedAt": time.time(), "claim": "advisory", "payload": payload, "revision": params.get('_evidenceRevision'), "instructionLimit": params.get('limit')}
    temp = path.with_name(path.name + f'.{os.getpid()}.{threading.get_ident()}.tmp')
    temp.write_text(json.dumps(receipt), encoding="utf-8")
    temp.replace(path)


def read(locator: str, program: str, address: str) -> dict[str, Any] | None:
    path = evidence_path(locator, program, address)
    if path is None:
        return None
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    payload = receipt.get("payload")
    if not isinstance(payload, dict):
        return None
    views = payload.get('views') or {}
    decompiled = views.get('decompile') or payload
    info = views.get('info') or payload
    calls = views.get('calls') or payload
    code = decompiled.get("decompilation") or decompiled.get("code") or ""
    if isinstance(code, dict):
        code = code.get("code") or code.get("text") or ""
    assembly = views.get('disassemble') or payload.get("disassembly") or {}
    instructions = assembly.get("instructions", []) if isinstance(assembly, dict) else []
    reason = str(decompiled.get('error') or decompiled.get('message') or '')
    state = 'available' if code else 'external' if info.get('isExternal') else 'thunk' if info.get('isThunk') else 'unavailable'
    if not code and not reason:
        reason = 'Imported function: no local source body exists.' if state == 'external' else 'Thunk: Ghidra returned no C body for this forwarding function.' if state == 'thunk' else 'Ghidra returned no C body for this function.'
    return {
        "ok": True,
        "source": "recorded-mcp-evidence",
        "addr": address,
        "function": {**info, "name": payload.get("name") or info.get('name'), "addr": address, "signature": payload.get("signature") or info.get('signature')},
        "decompile": {"text": code, "path": str(path), "truncated": False, "state": state, "reason": reason},
        "assembly": {"text": "\n".join(_instruction(row) for row in instructions), "instructionCount": len(instructions), "truncated": bool(receipt.get('instructionLimit') and len(instructions) >= receipt['instructionLimit'])},
        "graph": {"center": {"name": payload.get("name"), "addr": address}, "callers": [_node(row) for row in calls.get("callers") or []], "callees": [_node(row) for row in calls.get("callees") or []]},
        "comments": payload.get("comments") or [],
        "provenance": {key: value for key, value in receipt.items() if key != "payload"},
        "evidencePath": str(path),
        "byte_exact": None,
        "evidenceRevision": receipt.get('revision'),
        "evidenceComplete": bool(views.get('decompile') and views.get('disassemble')),
    }


def _instruction(row: dict[str, Any]) -> str:
    mnemonic = str(row.get('mnemonic') or '')
    operands = row.get('operands') or ''
    text = ', '.join(operands) if isinstance(operands, list) else str(operands)
    if not text.startswith(mnemonic):
        text = f'{mnemonic} {text}'
    return f"{row.get('address', '')}  {str(row.get('bytes') or ''):20}  {text}"


def _revision(locator: str, program: str, address: str) -> str:
    rows, _ = query_db('SELECT b.md5,f.name,f.signature,f.plate,f.return_type,f.param_types FROM program_binding p JOIN binary b ON b.repo_path=p.source_path JOIN func f ON f.binary_id=b.id WHERE p.locator=? AND ltrim(p.program,\'/\')=? AND f.addr=?', (locator, program, parse_address(address)), ignore_missing=True)
    epoch = evidence_path(locator, program, '0x0')
    try:
        generation = epoch.with_suffix('.revision').read_text() if epoch else ''
    except OSError:
        generation = ''
    return hashlib.sha256(json.dumps([rows, generation], sort_keys=True, default=str).encode()).hexdigest()


def invalidate(params: dict[str, Any]) -> None:
    """Successful explicit program mutations invalidate selected-function reads."""
    locator, program = _context(str(params.get('locator') or ''), str(params.get('programPath') or params.get('program') or ''))
    if not locator or not program:
        return
    path = evidence_path(locator, program, '0x0')
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        revision_path = path.with_suffix('.revision')
        temp = revision_path.with_name(revision_path.name + f'.{os.getpid()}.{threading.get_ident()}.tmp')
        temp.write_text(uuid.uuid4().hex)
        temp.replace(revision_path)


def ensure_observation(locator: str, program: str, address: str) -> dict[str, Any]:
    """Admit one shared read per bound function revision, across browser polls."""
    from .actions import jobs
    from .preparation import _lock_lease
    locator, program = _context(locator, program)
    path = evidence_path(locator, program, address)
    if not locator or not program or path is None:
        return {'status': 'blocked', 'reason': 'Select the exact Ghidra project and program to load function evidence.'}
    revision = _revision(locator, program, address)
    observed = read(locator, program, address)
    if observed and observed.get('evidenceComplete') and observed.get('evidenceRevision') == revision:
        return {'status': 'available', 'reason': (observed.get('decompile') or {}).get('reason', ''), 'revision': revision}
    request_path = path.with_suffix('.request.json')
    path.parent.mkdir(parents=True, exist_ok=True)
    with _LOCK, path.with_suffix('.request.lock').open('a+') as lease:
        try:
            _lock_lease(lease)
        except BlockingIOError:
            return {'status': 'submitting', 'reason': 'Another server is recording this function read.'}
        try:
            request = json.loads(request_path.read_text())
        except (OSError, ValueError):
            request = {}
        job = jobs.get_job(request.get('jobId', '')) if request.get('jobId') else None
        # A metadata change during an accepted read waits for that read to finish.
        # The next poll can then acquire the new revision without overlapping work.
        if request.get('revision') == revision or (job and job.status in {'queued', 'running', 'cancelling'}):
            if job:
                state = job.status
                reason = job.error or ('Ghidra function evidence is queued.' if state == 'queued' else 'Reading source, assembly, and references from Ghidra.' if state in {'running', 'cancelling'} else 'Ghidra returned no complete function witness; inspect the recorded job output.')
                return {**request, 'status': state, 'reason': reason}
            return {**request, 'status': 'interrupted' if request.get('jobId') else request.get('status', 'blocked'), 'reason': request.get('reason') or 'The accepted function read is unavailable; its recorded request is retained to avoid duplicate work.'}
        request = {'status': 'submitting', 'revision': revision, 'requestedAt': time.time(), 'locator': locator, 'program': program, 'address': address}
        _write_request(request_path, request)
        response, status = jobs.start_job('mcp.get-function', {'locator': locator, 'programPath': '/' + program, 'functionIdentifier': address, 'mode': 'all', 'limit': 1000000, 'timeout': 60, '_functionEvidence': True, '_evidenceRevision': revision})
        if status >= 400:
            request.update(status='blocked', reason=response.get('error', 'Function evidence could not be admitted.'))
        else:
            request.update(status=response['job']['status'], jobId=response['job']['id'], reason='Reading the selected function through get-function.')
        _write_request(request_path, request)
        return request


def _write_request(path: Path, value: dict[str, Any]) -> None:
    temp = path.with_name(path.name + f'.{os.getpid()}.{threading.get_ident()}.tmp')
    temp.write_text(json.dumps(value))
    temp.replace(path)


def _node(row: dict[str, Any]) -> dict[str, Any]:
    from .common import format_address

    address = str(row.get("addr") or row.get("address") or "")
    if address and not address.startswith("0x"):
        try:
            address = format_address(int(address, 16))
        except ValueError:
            pass
    return {**row, "addr": address, "name": row.get("name") or row.get("functionName") or address, "kind": "MCP reference"}
