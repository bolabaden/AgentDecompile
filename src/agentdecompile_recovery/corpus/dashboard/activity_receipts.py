"""Expose recorded proof references without promoting them to current proof.

Only a selected binary's fingerprint-bound workflow directories are inspected.
The canonical claim validator decides which records are objdiff receipts; source
existence and timestamps are observations, never freshness or parity proof.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from agentdecompile_recovery.claim_report import _is_objdiff_receipt

_CACHE: dict[tuple[str, ...], tuple[float, list[dict[str, Any]]]] = {}
_FINGERPRINTS: dict[str, tuple[tuple[int, ...], str]] = {}


def _md5(path: Path) -> str:
    try:
        before = path.stat()
        signature = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        cached = _FINGERPRINTS.get(str(path))
        if cached and cached[0] == signature:
            return cached[1]
        with path.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'md5').hexdigest()
        after = path.stat()
        if signature != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            return ''
        if len(_FINGERPRINTS) >= 256:
            _FINGERPRINTS.clear()
        _FINGERPRINTS[str(path)] = (signature, digest)
        return digest
    except OSError:
        return ''


def _address(value: Any) -> str:
    try:
        return f'0x{(value if isinstance(value, int) else int(str(value), 16)):08x}'
    except (TypeError, ValueError):
        return ''


def recorded_receipts(root: Path, binary: dict, runs: list[dict]) -> list[dict]:
    """Read at most 4096 JSON entries and expose at most 1024 validated receipts."""
    digest = str(binary.get('sha256') or '')
    if not re.fullmatch(r'[0-9a-fA-F]{64}', digest):
        return []
    aliases = set(binary.get('aliasSlugs') or [binary.get('slug')])
    ids = {str(value) for value in binary.get('binaryIds') or [binary.get('id')]}
    bindings = {(p.get('locator'), str(p.get('program') or '').lstrip('/')) for p in binary.get('projectBindings') or []}
    locations = []
    for run in runs:
        run_id = str(run.get('id') or '')
        if not re.fullmatch(r'[0-9a-f]{32}', run_id):
            continue
        for program, checkpoint in (run.get('checkpoints') or {}).items():
            binary_id = str(checkpoint.get('binaryId') or '')
            if binary_id not in ids or checkpoint.get('slug') not in aliases or not binary_id.isdigit():
                continue
            if (run.get('locator'), str(program).lstrip('/')) not in bindings:
                continue
            fingerprint = str(checkpoint.get('programFingerprint') or '').lower()
            if not re.fullmatch(r'[0-9a-f]{32}', fingerprint):
                continue
            locations.append((run_id, binary_id, fingerprint))
    if not locations:
        return []
    key = (str(root), digest, json.dumps(sorted(set(locations))))
    cached = _CACHE.get(key)
    if cached and time.monotonic() - cached[0] < 30:
        return cached[1]
    source_binary = Path(str(binary.get('repo') or ''))
    current_fingerprint = _md5(source_binary)
    if not current_fingerprint:
        return []
    workspace = root.resolve()
    output: list[dict] = []
    seen_paths: set[str] = set()
    inspected = 0
    for run_id, binary_id, fingerprint in sorted(set(locations)):
        if fingerprint != current_fingerprint:
            continue
        proof_root = workspace / 'recovery' / run_id / binary_id / 'proof'
        if proof_root.resolve() != proof_root:
            continue
        for directory in (proof_root / 'verified', proof_root / 'recovered-source' / 'functions'):
            if not directory.is_dir():
                continue
            for path in directory.rglob('*.json'):
                inspected += 1
                if inspected > 4096 or len(output) >= 1024:
                    break
                try:
                    resolved = path.resolve()
                    if not resolved.is_relative_to(directory.resolve()) or not resolved.is_relative_to(proof_root):
                        continue
                    if str(resolved) in seen_paths:
                        continue
                    seen_paths.add(str(resolved))
                    stat = resolved.stat()
                    if stat.st_size > 1024 * 1024:
                        continue
                    data = json.loads(resolved.read_text())
                    if not isinstance(data, dict) or not _is_objdiff_receipt(data, path=resolved):
                        continue
                    rows = data.get('functions')[:256] if isinstance(data.get('functions'), list) else [data]
                    addresses = sorted({_address(row.get('entry') or row.get('address')) for row in rows if isinstance(row, dict)} - {''})
                    source = Path(str(data.get('source') or ''))
                    if not source.is_absolute():
                        source = proof_root / source
                    source = source.resolve()
                    source_exists = bool(data.get('source')) and source.is_relative_to(proof_root.resolve()) and source.is_file()
                    modified = source.stat().st_mtime if source_exists else None
                    freshness = 'Source newer than receipt; current proof not established.' if modified is not None and modified > stat.st_mtime else 'Current target and source hashes were not reverified against this receipt.'
                    relative = resolved.relative_to(workspace).as_posix()
                    output.append({'path': relative, 'href': '/dashboard/artifact?' + urlencode({'p': relative}),
                                   'label': 'Recorded objdiff receipt', 'claim': 'recorded-proof', 'verified': False,
                                   'freshness': 'unknown', 'freshnessLabel': freshness,
                                   'sourceExists': source_exists, 'sourceModifiedAt': modified, 'receiptModifiedAt': stat.st_mtime,
                                   'addresses': addresses, 'runId': run_id, 'binaryId': binary_id,
                                   'targetSha256': digest, 'importedFingerprintMatches': True,
                                   'proofTier': data.get('proofTier') or data.get('verificationTier')})
                except (OSError, ValueError):
                    continue
            if inspected > 4096 or len(output) >= 1024:
                break
        if inspected > 4096 or len(output) >= 1024:
            break
    if len(_CACHE) >= 64:
        _CACHE.clear()
    _CACHE[key] = (time.monotonic(), output)
    return output
