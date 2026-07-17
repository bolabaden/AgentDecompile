"""Tool and host capability inspection."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sysconfig
from pathlib import Path
from typing import Any


DEFAULT_STEAMLESS = Path("target/steamless-release/extracted/Steamless.CLI.exe")
STEAMLESS_ENV = "AGENTDECOMPILE_STEAMLESS_CLI"
STEAMLESS_API_NAME = "Steamless.API.dll"


class ToolchainError(RuntimeError):
    """Typed host/toolchain failure (maps to blocked:toolchain)."""

    def __init__(self, reason: str, *, detail: str = "") -> None:
        clean = reason.removeprefix("blocked:toolchain:").removeprefix("blocked:toolchain")
        self.reason = clean or reason
        self.detail = detail
        message = f"blocked:toolchain:{self.reason}"
        if detail:
            message = f"{message}: {detail}"
        super().__init__(message)


def inspect_tool(name: str, command: list[str] | None = None) -> dict[str, Any]:
    path = shutil.which(name)
    result: dict[str, Any] = {"name": name, "path": path, "available": path is not None}
    if path and command:
        try:
            proc = subprocess.run(command, text=True, capture_output=True, check=False, timeout=10)
        except subprocess.TimeoutExpired as exc:
            result.update(
                {
                    "available": False,
                    "returnCode": 124,
                    "stdout": ((exc.stdout or b"") if isinstance(exc.stdout, (bytes, bytearray)) else (exc.stdout or ""))[:500],
                    "stderr": "timed out",
                }
            )
            return result
        result.update(
            {
                "returnCode": proc.returncode,
                "stdout": proc.stdout.strip()[:500],
                "stderr": proc.stderr.strip()[:500],
            }
        )
    return result


def inspect_executable(name: str, path: Path, command: list[str] | None = None) -> dict[str, Any]:
    available = path.exists() and os.access(path, os.X_OK)
    result: dict[str, Any] = {"name": name, "path": str(path) if available else None, "available": available}
    if available and command:
        try:
            proc = subprocess.run(command, text=True, capture_output=True, check=False, timeout=10)
        except subprocess.TimeoutExpired:
            result.update({"available": False, "returnCode": 124, "stderr": "timed out"})
            return result
        result.update(
            {
                "returnCode": proc.returncode,
                "stdout": proc.stdout.strip()[:500],
                "stderr": proc.stderr.strip()[:500],
            }
        )
    return result


def inspect_capabilities(repo_root: Path) -> dict[str, Any]:
    steamless = resolve_steamless_cli(repo_root)
    tools = {
        "python": inspect_tool("python3", ["python3", "--version"]),
        "clang": inspect_tool("clang", ["clang", "--version"]),
        "objdiff": inspect_tool("objdiff", ["objdiff", "--version"]),
        "objdump": inspect_tool("objdump", ["objdump", "--version"]),
        "objcopy": inspect_tool("objcopy", ["objcopy", "--version"]),
        "wine": inspect_tool("wine", ["wine", "--version"]),
        "mono": inspect_tool("mono", ["mono", "--version"]),
        "uv": inspect_tool("uv", ["uv", "--version"]),
    }
    local = {
        "oneShotSource": resolve_script_asset(repo_root, "one-shot-source.py") is not None,
        "oneShotSourcePath": str(resolve_script_asset(repo_root, "one-shot-source.py") or ""),
        "sourceParityOneShot": (repo_root / "scripts/source-parity-one-shot.py").exists(),
        "swkotorInventorySlice": (repo_root / "scripts/swkotor-inventory-slice.py").exists(),
        "verifyObjdiff": (repo_root / "scripts/lib/verify-objdiff.sh").exists(),
        "steamlessCli": steamless is not None,
        "steamlessCliPath": str(steamless) if steamless else None,
    }
    return {
        "schema": "agentdecompile.recovery.capabilities.v1",
        "tools": tools,
        "localSurfaces": local,
    }


def resolve_steamless_cli(repo_root: Path, configured: Path | None = None) -> Path | None:
    candidates: list[Path] = []
    if configured is not None:
        candidates.append(configured)
    env_path = os.environ.get(STEAMLESS_ENV)
    if env_path:
        candidates.append(Path(env_path))
    # Prefer pinned repo-managed layout over cwd (cwd-first is an abuse vector).
    candidates.extend(
        [
            repo_root / DEFAULT_STEAMLESS,
            Path.cwd() / DEFAULT_STEAMLESS,
        ]
    )
    for candidate in candidates:
        expanded = candidate.expanduser()
        if not expanded.exists():
            continue
        try:
            return ensure_steamless_layout(expanded.resolve())
        except ToolchainError:
            continue
    return None


def ensure_steamless_layout(cli: Path) -> Path:
    """Ensure Steamless.CLI.exe can load Steamless.API under mono.

    Release zips ship ``Steamless.API.dll`` under ``Plugins/``. Mono does not always
    probe that folder when loading the CLI, so copy the API next to the exe when
    missing. Fail closed when the API cannot be located.
    """

    cli = cli.resolve()
    api = cli.parent / STEAMLESS_API_NAME
    plugin_api = cli.parent / "Plugins" / STEAMLESS_API_NAME
    if not api.exists() and plugin_api.exists():
        shutil.copy2(plugin_api, api)
    if not api.exists():
        raise ToolchainError(
            "steamless-api-missing",
            detail=f"expected {api.name} beside {cli.name} or under Plugins/",
        )
    return cli


def run_steamless(
    cli: Path,
    binary: Path,
    *,
    timeout: int = 900,
    keepbind: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run Steamless with cwd set to the CLI directory so plugins resolve."""

    cli = ensure_steamless_layout(cli)
    binary = binary.resolve()
    args = ["mono", str(cli), "--quiet"]
    if keepbind:
        args.append("--keepbind")
    args.extend(["--dumppayload", "--dumpdrmp", str(binary)])
    return subprocess.run(
        args,
        cwd=str(cli.parent),
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )


def steamless_output_path(binary: Path) -> Path:
    """Steamless writes ``<input>.unpacked.exe`` next to the input."""

    return Path(str(binary.resolve()) + ".unpacked.exe")


def detect_pe_packed(path: Path, repo_root: Path, *, timeout: int = 60) -> bool | None:
    """Return True/False when detection succeeds, None when detection fails."""

    script = repo_root / "scripts" / "normalize-binary.py"
    if not script.exists() or path.suffix.lower() not in {".exe", ".dll"}:
        return False
    try:
        proc = subprocess.run(
            [os.environ.get("PYTHON", "python3"), str(script), str(path), "--detect-only"],
            cwd=str(repo_root),
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return None
    if proc.returncode != 0:
        return None
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    detection = payload.get("detection") if isinstance(payload, dict) else None
    if not isinstance(detection, dict):
        return None
    return bool(detection.get("packed"))


def resolve_script_asset(repo_root: Path, script_name: str) -> Path | None:
    candidates = [
        repo_root / "scripts" / script_name,
        Path(sysconfig.get_path("data")) / "share" / "agentdecompile-recovery" / "scripts" / script_name,
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    return None
