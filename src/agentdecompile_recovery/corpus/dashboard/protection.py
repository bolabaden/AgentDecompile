"""Byte-backed protection observations and non-executing derived analysis images."""
from __future__ import annotations

from functools import lru_cache
import hashlib
import json
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


def _normalizer_script() -> Path | None:
    from agentdecompile_recovery.tools import resolve_script_asset
    script = resolve_script_asset(Path(__file__).resolve().parents[4], 'normalize-binary.py')
    if script is not None:
        return script
    # Distribution metadata also covers pip --target layouts, where sysconfig's
    # data prefix belongs to the host interpreter rather than the target tree.
    from importlib.metadata import PackageNotFoundError, distribution
    try:
        installed = distribution('agentdecompile')
        suffix = 'share/agentdecompile-recovery/scripts/normalize-binary.py'
        for entry in installed.files or ():
            if str(entry).replace('\\', '/').endswith(suffix):
                candidate = Path(installed.locate_file(entry))
                if candidate.is_file():
                    return candidate.resolve()
    except PackageNotFoundError:
        pass
    return None


def inspect_protection(path: str | Path) -> dict[str, Any]:
    try:
        stat = Path(path).stat()
        return dict(_inspect_cached(str(path), stat.st_size, stat.st_mtime_ns))
    except OSError as exc:
        return {'status': 'unknown', 'encryption': 'unknown', 'drm': 'unknown', 'reason': str(exc), 'sourcePath': str(path)}


@lru_cache(maxsize=512)
def _inspect_cached(path: str, size: int, mtime_ns: int) -> dict[str, Any]:
    result: dict[str, Any] = {'status': 'unknown', 'encryption': 'unknown', 'drm': 'unknown', 'evidence': [], 'sourcePath': str(path)}
    source = Path(path)
    try:
        with source.open('rb') as stream:
            header = stream.read(32)
            if header[:2] == b'MZ':
                # Source checkouts and installed wheels use the same detector.
                # Wheel data lives under the interpreter's configured share path.
                script = _normalizer_script()
                if script is None:
                    raise ValueError('The installed distribution is missing its binary protection detector')
                proc = subprocess.run([sys.executable, str(script), str(source), '--detect-only'], capture_output=True, text=True, timeout=30)
                if proc.returncode:
                    raise ValueError('PE protection inspection failed')
                detection = json.loads(proc.stdout).get('detection')
                if not isinstance(detection, dict):
                    raise ValueError('PE protection inspection returned no evidence')
                result.update(status='detected' if detection['packed'] else 'not-detected', encryption='suspected' if detection.get('encrypted_code_sections') else 'not-detected', drm='detected' if detection.get('protector') in ('SteamStub', 'SecuROM', 'SafeDisc', 'StarForce', 'Denuvo') else 'unknown', evidence=detection.get('evidence', []), detector='normalize-binary', detection=detection)
            elif header[:4] in (b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf'):
                endian = '<' if header[0] in (0xce, 0xcf) else '>'
                is64 = header[:4] in (b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf')
                count, size = struct.unpack_from(endian + 'II', header, 16)
                if count > 65536 or size > 64 * 1024 * 1024:
                    raise ValueError('Invalid Mach-O load command bounds')
                stream.seek(32 if is64 else 28)
                commands = stream.read(size)
                offset = 0
                cryptids = []
                for _ in range(count):
                    if offset + 8 > len(commands):
                        raise ValueError('Truncated Mach-O load commands')
                    command, length = struct.unpack_from(endian + 'II', commands, offset)
                    if length < 8 or offset + length > len(commands):
                        raise ValueError('Invalid Mach-O load command')
                    if command in (0x21, 0x2c):
                        if length < 20:
                            raise ValueError('Truncated Mach-O encryption command')
                        cryptids.append(struct.unpack_from(endian + 'I', commands, offset + 16)[0])
                    offset += length
                encrypted = any(cryptids)
                result.update(status='detected' if encrypted else 'not-detected', encryption='detected' if encrypted else 'not-detected', detector='Mach-O LC_ENCRYPTION_INFO', evidence=[{'cryptids': cryptids}], drm='unknown')
            else:
                result['reason'] = 'Protection detection is unavailable for this format; absence of detection is not proof of absence.'
    except (OSError, ValueError, subprocess.SubprocessError, struct.error) as exc:
        result['reason'] = str(exc)
    return result


def prepare_protected_binary(path: str | Path, output_root: str | Path) -> dict[str, Any]:
    """Unpack supported formats on a copy. Never execute the target binary."""
    source = Path(path)
    result = inspect_protection(source)
    result['analysisPath'] = str(source)
    if result['status'] != 'detected':
        return result
    with source.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    result['sourceSha256'] = digest
    root = Path(output_root) / 'protection' / digest
    root.mkdir(parents=True, exist_ok=True)
    # Isolated attempts never accept stale output left by an earlier failed tool.
    attempt = Path(tempfile.mkdtemp(prefix='attempt-', dir=root))
    copied = attempt / source.name
    shutil.copyfile(source, copied)
    with copied.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != digest:
            raise ValueError('Binary changed while preparing its analysis copy; retry import.')
    protector = (result.get('detection') or {}).get('protector')
    derived = None
    try:
        if protector == 'SteamStub':
            from agentdecompile_recovery.tools import resolve_steamless_cli, run_steamless
            cli = resolve_steamless_cli(Path(__file__).resolve().parents[4])
            if cli is None:
                raise ValueError('Steamless is unavailable')
            proc = run_steamless(cli, copied, timeout=900, keepbind=True)
            result['tool'] = 'Steamless'
            result['toolOutput'] = ((proc.stdout or '') + (proc.stderr or ''))[-4000:]
            if proc.returncode == 0:
                derived = copied.with_name(copied.name + '.unpacked.exe')
        elif protector == 'UPX' and shutil.which('upx'):
            proc = subprocess.run(['upx', '-d', str(copied)], capture_output=True, text=True, timeout=120)
            result['tool'] = 'upx'
            result['toolOutput'] = ((proc.stdout or '') + (proc.stderr or ''))[-4000:]
            if proc.returncode == 0:
                derived = copied
        else:
            raise ValueError('No supported non-executing unpacker is available for this protection')
        if derived is None or not derived.is_file():
            raise ValueError('Unpacker did not produce a successful output')
        check = inspect_protection(derived)
        if check['status'] != 'not-detected':
            raise ValueError('Derived image did not pass protection inspection')
        with derived.open('rb') as stream:
            derived_hash = hashlib.file_digest(stream, 'sha256').hexdigest()
        if derived_hash == digest:
            raise ValueError('Unpacker returned unchanged bytes')
        result.update(analysisPath=str(derived), derivedSha256=derived_hash, handling='unpacked', derivedInspection=check)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        result.update(handling='blocked', blocker='protection-unavailable', reason=str(exc))
    (attempt / 'receipt.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    result['receiptPath'] = str(attempt / 'receipt.json')
    return result
