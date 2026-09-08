"""Content identity for library presentation; never merges recovery evidence."""
from __future__ import annotations

import hashlib
import threading
from pathlib import Path
from typing import Any

_LOCK = threading.RLock()
_HASHES: dict[str, tuple[tuple[int, ...], str]] = {}
_CONTAINERS: dict[str, list[tuple[str, str, int, int]]] = {}


def binary_sha256(path: str) -> str:
    """Hash stable local bytes, caching only while their filesystem identity holds."""
    try:
        source = Path(path).expanduser()
        if not source.is_file() or source.suffix.lower() == '.gpr':
            return ''
        before = source.stat()
        signature = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        key = str(source.resolve())
        with _LOCK:
            cached = _HASHES.get(key)
            if cached and cached[0] == signature:
                return cached[1]
        digest = hashlib.sha256()
        with source.open('rb') as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b''):
                digest.update(block)
        after = source.stat()
        if signature != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            return ''
        value = digest.hexdigest()
        with _LOCK:
            _HASHES[key] = (signature, value)
        return value
    except (OSError, ValueError):
        return ''


def canonical_library(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Collapse only confirmed identical bytes; keep aliases and all original IDs."""
    from .common import query_db

    identities, identity_error = query_db("SELECT source_path,sha256 FROM binary_content_identity")
    recorded = dict(identities) if not identity_error else {}
    groups: dict[str, list[dict[str, Any]]] = {}
    unresolved = []
    for row in rows:
        digest = binary_sha256(row['repo']) if row['kind'] == 'binary' else ''
        row.update(sha256=digest or None, identityStatus='confirmed' if digest else 'unavailable')
        prior_digest = recorded.get(row['repo'])
        if row['kind'] == 'binary' and (not digest or (prior_digest and prior_digest != digest)):
            row['identityStatus'] = 'changed' if digest else 'unavailable'
            row['recordedSha256'] = prior_digest
            row['identityReason'] = ('Source bytes changed since registration; existing evidence belongs to the recorded hash.'
                                     if digest else 'Original bytes are unavailable; this entry has not been confirmed distinct.')
            unresolved.append(row)
            continue
        groups.setdefault(digest or f"record:{row['id']}", []).append(row)
    result = []
    for key, members in groups.items():
        members.sort(key=lambda r: (-r['funcs'], -int(r['imported']), r['id']))
        row = dict(members[0])
        row['libraryId'] = f'sha256:{key}' if row['sha256'] else key
        row['aliasSlugs'] = [item['slug'] for item in members]
        row['binaryIds'] = [item['id'] for item in members]
        row['sourcePaths'] = list(dict.fromkeys(item['repo'] for item in members))
        row['projectBindings'] = list({(binding['locator'], binding['program']): binding for item in members for binding in item.get('projectBindings', [])}.values())
        result.append(row)
    return sorted(result, key=lambda row: row['slug'].casefold()), unresolved


def annotate_containers(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Bind universal Mach-O slices by measured byte ranges, never by names."""
    import struct

    # The hash cache already verifies the source's filesystem identity. Reuse
    # measured slice hashes only for the same confirmed complete-file digest.
    cache = _CONTAINERS
    by_hash = {row.get('sha256'): row for row in rows if row.get('sha256')}
    architectures = {7: 'i386', 0x01000007: 'x86_64', 12: 'arm', 0x0100000c: 'arm64', 18: 'ppc', 0x01000012: 'ppc64'}
    for digest, parent in by_hash.items():
        if digest not in cache:
            slices = []
            try:
                with Path(parent['repo']).open('rb') as stream:
                    header = stream.read(8)
                    formats = {b'\xca\xfe\xba\xbe': ('>', False), b'\xbe\xba\xfe\xca': ('<', False), b'\xca\xfe\xba\xbf': ('>', True), b'\xbf\xba\xfe\xca': ('<', True)}
                    if header[:4] in formats and len(header) == 8:
                        endian, wide = formats[header[:4]]
                        count = struct.unpack(endian+'I', header[4:])[0]
                        if not 1 <= count <= 128:
                            raise ValueError('Invalid architecture count')
                        width = 32 if wide else 20
                        table = stream.read(count * width)
                        file_size = stream.seek(0, 2)
                        ranges = []
                        for index in range(count):
                            cpu, subtype, offset, size = struct.unpack_from(endian+('IIQQ' if wide else 'IIII'), table, index*width)
                            if size <= 0 or offset < 8+count*width or offset+size > file_size or any(offset < end and start < offset+size for start,end in ranges):
                                raise ValueError('Invalid architecture byte range')
                            ranges.append((offset,offset+size))
                            stream.seek(offset)
                            remaining, hasher = size, hashlib.sha256()
                            while remaining:
                                block = stream.read(min(1024*1024, remaining))
                                if not block:
                                    raise ValueError('Truncated architecture slice')
                                hasher.update(block)
                                remaining -= len(block)
                            slices.append((hasher.hexdigest(), architectures.get(cpu, f'cpu-{cpu}'), offset, size))
                        if binary_sha256(parent['repo']) != digest:
                            slices = []
            except (OSError, ValueError, struct.error):
                slices = []
            cache[digest] = slices
        for child_hash, architecture, offset, size in cache[digest]:
            child = by_hash.get(child_hash)
            if child and child is not parent:
                child.update(containerSha256=digest, architecture=architecture,
                             containerEvidence={'sourcePath':parent['repo'], 'sha256':digest, 'offset':offset, 'size':size, 'sliceSha256':child_hash})
                siblings = parent.setdefault('architectureSlices', [])
                if not any(item['sha256'] == child_hash for item in siblings):
                    siblings.append({'sha256':child_hash, 'architecture':architecture, 'slug':child['slug']})
    return rows
