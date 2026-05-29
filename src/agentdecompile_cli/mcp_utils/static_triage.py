"""Tier 0 static file triage — file(1), SHA-256, strings, optional OS tool probes."""

from __future__ import annotations

import hashlib
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_STRING_LIMIT = 100
_DEFAULT_TIMEOUT_MS = 30_000


def _timeout_seconds(timeout_ms: int) -> float:
    return max(1.0, timeout_ms / 1000.0)


def _run_command(
    args: list[str],
    *,
    timeout_ms: int,
) -> dict[str, Any]:
    """Run a subprocess and return structured stdout/stderr metadata."""
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=_timeout_seconds(timeout_ms),
            check=False,
        )
        return {
            "command": args,
            "exitCode": completed.returncode,
            "stdout": (completed.stdout or "").strip(),
            "stderr": (completed.stderr or "").strip(),
            "available": True,
        }
    except FileNotFoundError:
        return {
            "command": args,
            "exitCode": None,
            "stdout": "",
            "stderr": "",
            "available": False,
            "skipped": "binary not on PATH",
        }
    except subprocess.TimeoutExpired:
        return {
            "command": args,
            "exitCode": None,
            "stdout": "",
            "stderr": "",
            "available": True,
            "error": "timeout",
        }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _extract_strings(
    path: Path,
    *,
    string_limit: int,
    string_filter: str | None,
    timeout_ms: int,
) -> dict[str, Any]:
    result = _run_command(["strings", str(path)], timeout_ms=timeout_ms)
    if not result.get("available"):
        return {**result, "values": [], "count": 0}

    lines = [line for line in result.get("stdout", "").splitlines() if line.strip()]
    if string_filter:
        needle = string_filter.lower()
        lines = [line for line in lines if needle in line.lower()]

    limited = lines[: max(0, string_limit)]
    return {
        **result,
        "values": limited,
        "count": len(limited),
        "totalMatched": len(lines),
        "truncated": len(lines) > len(limited),
    }


def _probe_version(binary_name: str, *, timeout_ms: int) -> dict[str, Any]:
    if shutil.which(binary_name) is None:
        return {
            "tool": binary_name,
            "available": False,
            "skipped": "binary not on PATH",
        }
    probe = _run_command([binary_name, "--version"], timeout_ms=timeout_ms)
    return {
        "tool": binary_name,
        "available": True,
        "exitCode": probe.get("exitCode"),
        "versionLine": (probe.get("stdout") or probe.get("stderr") or "").splitlines()[:1],
    }


def _probe_binwalk_entropy(path: Path, *, timeout_ms: int) -> dict[str, Any]:
    if shutil.which("binwalk") is None:
        return {
            "tool": "binwalk",
            "available": False,
            "skipped": "binary not on PATH",
        }
    probe = _run_command(["binwalk", "-E", str(path)], timeout_ms=timeout_ms)
    lines = [line for line in probe.get("stdout", "").splitlines() if line.strip()]
    return {
        "tool": "binwalk",
        "available": True,
        "exitCode": probe.get("exitCode"),
        "entropyLines": lines[:20],
        "truncated": len(lines) > 20,
    }


def _suggest_tier_escalation(file_output: str) -> dict[str, Any]:
    """Recommend Tier 2+ when the sample looks like a loadable binary."""
    lowered = file_output.lower()
    executable_markers = (
        "executable",
        "shared object",
        "dynamically linked",
        "pe32",
        "pe32+",
        "mach-o",
        "elf",
        "core dump",
    )
    if any(marker in lowered for marker in executable_markers):
        return {
            "recommendedTier": 2,
            "reason": "Sample appears to be an executable or shared library; consider open-project and analyze-program.",
            "nextTools": ["open-project", "analyze-program", "list-functions"],
        }
    if "archive" in lowered or "compressed" in lowered:
        return {
            "recommendedTier": 0,
            "reason": "Archive or compressed payload; expand or unpack before Ghidra import.",
            "nextTools": ["run-file-triage"],
        }
    return {
        "recommendedTier": 2,
        "reason": "Unknown or generic file type; open-project if reverse engineering is still required.",
        "nextTools": ["open-project"],
    }


def build_file_triage_payload(
    binary_path: Path,
    *,
    string_limit: int = _DEFAULT_STRING_LIMIT,
    string_filter: str | None = None,
    try_yara: bool = True,
    try_capa: bool = True,
    try_binwalk: bool = True,
    timeout_ms: int = _DEFAULT_TIMEOUT_MS,
) -> dict[str, Any]:
    """Build unified Tier 0 triage JSON for RE artifact protocol."""
    path = binary_path.expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Binary not found or not a file: {path}")

    file_result = _run_command(["file", "-b", str(path)], timeout_ms=timeout_ms)
    file_output = file_result.get("stdout") or file_result.get("stderr") or ""

    optional_tools: dict[str, Any] = {}
    if try_yara:
        optional_tools["yara"] = _probe_version("yara", timeout_ms=timeout_ms)
    if try_capa:
        optional_tools["capa"] = _probe_version("capa", timeout_ms=timeout_ms)
    if try_binwalk:
        optional_tools["binwalk"] = _probe_binwalk_entropy(path, timeout_ms=timeout_ms)

    strings_result = _extract_strings(
        path,
        string_limit=string_limit,
        string_filter=string_filter,
        timeout_ms=timeout_ms,
    )

    return {
        "action": "run-file-triage",
        "binaryPath": str(path),
        "sha256": _sha256_file(path),
        "file": {
            "description": file_output,
            "probe": file_result,
        },
        "strings": strings_result,
        "optionalTools": optional_tools,
        "suggestedTierEscalation": _suggest_tier_escalation(file_output),
    }
