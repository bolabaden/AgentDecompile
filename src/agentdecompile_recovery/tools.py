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

ILSPYCMD_ENV = "AGENTDECOMPILE_ILSPYCMD"
ASSETRIPPER_ENV = "AGENTDECOMPILE_ASSETRIPPER_CLI"
UNITY_EDITOR_ENV = "AGENTDECOMPILE_UNITY_EDITOR"
UNITY_HUB_ROOT_ENV = "AGENTDECOMPILE_UNITY_HUB_ROOT"

DEFAULT_ASSETRIPPER = Path("target/assetripper/AssetRipper.GUI.Free")

# AssetRipper ships as a single self-hosted binary whose name has varied across
# releases/editions; probe every known spelling before giving up.
_ASSETRIPPER_NAMES = (
    "AssetRipper.GUI.Free",
    "AssetRipper.GUI.Free.exe",
    "AssetRipper.CLI",
    "AssetRipper.CLI.exe",
    "AssetRipper",
    "AssetRipper.exe",
)

# Unity Hub install layouts, relative to a hub "Editor" root, per platform.
_UNITY_EDITOR_RELATIVE = (
    Path("Editor/Unity"),  # Linux
    Path("Editor/Unity.exe"),  # Windows
    Path("Unity.app/Contents/MacOS/Unity"),  # macOS
)


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
        "dotnet": inspect_tool("dotnet", ["dotnet", "--version"]),
        "git-lfs": inspect_tool("git-lfs", ["git-lfs", "version"]),
    }
    ilspycmd = resolve_ilspycmd()
    assetripper = resolve_assetripper_cli(repo_root)
    unity_editors = discover_unity_editors()
    tools["ilspycmd"] = (
        inspect_executable("ilspycmd", ilspycmd, [str(ilspycmd), "--version"])
        if ilspycmd
        else {"name": "ilspycmd", "path": None, "available": False}
    )
    tools["assetripper"] = (
        {"name": "assetripper", "path": str(assetripper), "available": True}
        if assetripper
        else {"name": "assetripper", "path": None, "available": False}
    )
    tools["unity-editor"] = {
        "name": "unity-editor",
        "available": bool(unity_editors),
        "versions": {version: str(path) for version, path in sorted(unity_editors.items())},
    }
    local = {
        "oneShotSource": resolve_script_asset(repo_root, "one-shot-source.py") is not None,
        "oneShotSourcePath": str(resolve_script_asset(repo_root, "one-shot-source.py") or ""),
        "sourceParityOneShot": (repo_root / "scripts/source-parity-one-shot.py").exists(),
        "inventorySlice": (repo_root / "scripts/inventory-slice.py").exists(),
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


def resolve_ilspycmd(configured: Path | None = None) -> Path | None:
    """Locate ``ilspycmd`` (dotnet global tool; often installed off-PATH)."""

    candidates: list[Path] = []
    if configured is not None:
        candidates.append(configured)
    env_path = os.environ.get(ILSPYCMD_ENV)
    if env_path:
        candidates.append(Path(env_path))
    on_path = shutil.which("ilspycmd")
    if on_path:
        candidates.append(Path(on_path))
    # `dotnet tool install -g ilspycmd` lands here and is frequently not on PATH.
    candidates.append(Path.home() / ".dotnet" / "tools" / "ilspycmd")
    for candidate in candidates:
        expanded = candidate.expanduser()
        if expanded.exists() and os.access(expanded, os.X_OK):
            return expanded.resolve()
    return None


def resolve_assetripper_cli(repo_root: Path, configured: Path | None = None) -> Path | None:
    """Locate an AssetRipper binary (env override, then repo-managed, then PATH)."""

    candidates: list[Path] = []
    if configured is not None:
        candidates.append(configured)
    env_path = os.environ.get(ASSETRIPPER_ENV)
    if env_path:
        candidates.append(Path(env_path))
    # Prefer pinned repo-managed layout over cwd (cwd-first is an abuse vector).
    candidates.append(repo_root / DEFAULT_ASSETRIPPER)
    for name in _ASSETRIPPER_NAMES:
        candidates.append(repo_root / "target" / "assetripper" / name)
        candidates.append(repo_root / "tools" / "AssetRipper" / "linux" / name)
        on_path = shutil.which(name)
        if on_path:
            candidates.append(Path(on_path))
    for candidate in candidates:
        expanded = candidate.expanduser()
        if expanded.is_file() and os.access(expanded, os.X_OK):
            return expanded.resolve()
    return None


def discover_unity_editors(hub_roots: list[Path] | None = None) -> dict[str, Path]:
    """Map installed Unity Editor version -> executable, via Unity Hub layouts."""

    roots: list[Path] = []
    env_root = os.environ.get(UNITY_HUB_ROOT_ENV)
    if env_root:
        roots.append(Path(env_root))
    if hub_roots:
        roots.extend(hub_roots)
    roots.extend(
        [
            Path.home() / "Unity" / "Hub" / "Editor",
            Path("/opt/unity/editors"),
            Path("/Applications/Unity/Hub/Editor"),
            Path("C:/Program Files/Unity/Hub/Editor"),
        ]
    )
    found: dict[str, Path] = {}
    for root in roots:
        expanded = root.expanduser()
        if not expanded.is_dir():
            continue
        try:
            children = sorted(expanded.iterdir())
        except OSError:
            continue
        for version_dir in children:
            if not version_dir.is_dir() or version_dir.name in found:
                continue
            for relative in _UNITY_EDITOR_RELATIVE:
                executable = version_dir / relative
                if executable.is_file() and os.access(executable, os.X_OK):
                    found[version_dir.name] = executable.resolve()
                    break
    return found


def select_unity_editor(
    requested_version: str | None,
    *,
    installed: dict[str, Path] | None = None,
) -> tuple[str | None, Path | None, str]:
    """Pick an Editor for ``requested_version``.

    Returns ``(version, executable, match)`` where ``match`` is one of
    ``exact`` / ``minor`` / ``fallback`` / ``none``. A non-``exact`` match is a
    real fidelity risk (Unity silently upgrades project assets on open), so the
    caller must record it rather than treat any Editor as interchangeable.
    """

    editors = discover_unity_editors() if installed is None else installed
    if not editors:
        return None, None, "none"
    if requested_version and requested_version in editors:
        return requested_version, editors[requested_version], "exact"
    if requested_version:
        # `2022.3.62f2` -> prefer another `2022.3.*` before anything else.
        parts = requested_version.split(".")
        if len(parts) >= 2:
            prefix = f"{parts[0]}.{parts[1]}."
            same_minor = sorted(v for v in editors if v.startswith(prefix))
            if same_minor:
                chosen = same_minor[-1]
                return chosen, editors[chosen], "minor"
    chosen = sorted(editors)[-1]
    return chosen, editors[chosen], "fallback" if requested_version else "exact"


def run_ilspycmd(
    cli: Path,
    assembly: Path,
    out_dir: Path,
    *,
    reference_dirs: list[Path] | None = None,
    timeout: int = 1800,
) -> subprocess.CompletedProcess[str]:
    """Decompile one assembly into a project tree under ``out_dir``."""

    out_dir.mkdir(parents=True, exist_ok=True)
    args = [str(cli), str(assembly), "-p", "-o", str(out_dir)]
    for reference in reference_dirs or []:
        args.extend(["-r", str(reference)])
    return subprocess.run(args, text=True, capture_output=True, check=False, timeout=timeout)


def run_unity_batchmode(
    editor: Path,
    project_path: Path,
    *,
    execute_method: str | None = None,
    log_file: Path | None = None,
    extra_args: list[str] | None = None,
    timeout: int = 3600,
) -> subprocess.CompletedProcess[str]:
    """Open a project headlessly and quit.

    A cold batchmode open performs a full asset import, which is what makes this
    usable as a verification gate: no Editor window, no focus-dependent
    background scanning, and a deterministic log to parse afterwards.
    """

    args = [
        str(editor),
        "-batchmode",
        "-quit",
        "-nographics",
        "-silent-crashes",
        "-projectPath",
        str(project_path),
    ]
    if execute_method:
        args.extend(["-executeMethod", execute_method])
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        args.extend(["-logFile", str(log_file)])
    args.extend(extra_args or [])
    return subprocess.run(args, text=True, capture_output=True, check=False, timeout=timeout)


def resolve_script_asset(repo_root: Path, script_name: str) -> Path | None:
    candidates = [
        repo_root / "scripts" / script_name,
        Path(sysconfig.get_path("data")) / "share" / "agentdecompile-recovery" / "scripts" / script_name,
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    return None
