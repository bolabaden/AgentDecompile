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
    """Run Steamless with cwd set to the CLI directory so plugins resolve.

    Before invoking Steamless, this function reads and preserves the Rich header
    from *binary*.  Steamless is known to zero bytes 0x40-0xD0 of the output
    (the region where the Rich header lives), silently destroying the compiler
    identification data.  The preserved header is written to
    ``<output>.rich_header.json`` so downstream stages can still identify the
    toolchain even after unpacking.

    A ``rich_header_warning`` key is included in that sidecar when the output's
    Rich region is zeroed but the input's was not.
    """

    cli = ensure_steamless_layout(cli)
    binary = binary.resolve()

    # Capture Rich header before the destructive unpack step.
    pre_rich = _read_rich_header_bytes(binary)

    args = ["mono", str(cli), "--quiet"]
    if keepbind:
        args.append("--keepbind")
    args.extend(["--dumppayload", "--dumpdrmp", str(binary)])
    result = subprocess.run(
        args,
        cwd=str(cli.parent),
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )

    # Write sidecar with pre-unpack Rich header (and warning if it was zeroed).
    output = steamless_output_path(binary)
    _write_rich_header_sidecar(binary, output, pre_rich)

    return result


def _read_rich_header_bytes(binary: Path) -> dict | None:
    """Return the Rich header from *binary* as a dict, or None if not present.

    The dict contains:
      - ``raw_hex``: hex of the raw (XOR-encoded) Rich region bytes
      - ``xor_key``: the 32-bit XOR key (int)
      - ``offset``: byte offset in the file where the DanS block starts
      - ``entries``: decoded list of {comp_id, count}
    """
    import struct as _struct

    try:
        data = binary.read_bytes()
    except OSError:
        return None
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    try:
        pe_offset = _struct.unpack_from("<I", data, 0x3C)[0]
    except _struct.error:
        return None
    stub = data[0x40:pe_offset] if pe_offset > 0x40 else b""
    rich_pos = stub.rfind(b"Rich")
    if rich_pos == -1:
        return None
    rich_abs = 0x40 + rich_pos
    if rich_abs + 8 > len(data):
        return None
    try:
        xor_key = _struct.unpack_from("<I", data, rich_abs + 4)[0]
    except _struct.error:
        return None
    dans_abs: int | None = None
    dans_word = _struct.unpack_from("<I", b"DanS\x00", 0)[0]
    for off in range(rich_abs - 4, 0x3C - 1, -4):
        try:
            candidate = _struct.unpack_from("<I", data, off)[0] ^ xor_key
        except _struct.error:
            break
        if candidate == dans_word:
            dans_abs = off
            break
    if dans_abs is None:
        return None
    raw = data[dans_abs : rich_abs + 8]
    region_len = rich_abs - dans_abs  # bytes from DanS to Rich (exclusive)
    entries = []
    for i in range(4, region_len // 4, 2):
        if i * 4 + 8 > region_len:
            break
        try:
            w0, w1 = _struct.unpack_from("<II", raw, i * 4)
        except _struct.error:
            break
        entries.append({"comp_id": w0 ^ xor_key, "count": w1 ^ xor_key})
    return {"raw_hex": raw.hex(), "xor_key": xor_key, "offset": dans_abs, "entries": entries}


def _rich_region_zeroed(data: bytes) -> bool:
    """Return True when bytes 0x40-0xD0 of *data* are all zeros."""
    if len(data) < 0xD0:
        return False
    return all(b == 0 for b in data[0x40:0xD0])


def _write_rich_header_sidecar(
    packed: Path,
    unpacked: Path,
    pre_rich: dict | None,
) -> None:
    """Write ``<unpacked>.rich_header.json`` with pre-unpack Rich header data.

    If the unpacked output exists and its Rich region is zeroed while the
    input had a Rich header, a warning is included in the sidecar so that
    any reader knows to consult this file rather than the unpacked binary.
    """
    sidecar: dict = {
        "source_binary": str(packed),
        "unpacked_binary": str(unpacked),
        "pre_unpack_rich_header": pre_rich,
    }
    if pre_rich is not None:
        try:
            out_data = unpacked.read_bytes()
            if _rich_region_zeroed(out_data):
                sidecar["rich_header_warning"] = (
                    "Steamless zeroed bytes 0x40-0xD0 of the unpacked output. "
                    "The Rich header (compiler identification data) from the "
                    "packed input has been destroyed in the unpacked binary. "
                    "Use 'pre_unpack_rich_header' in this sidecar for compiler "
                    "identification instead of reading the unpacked file."
                )
        except OSError:
            pass
    sidecar_path = Path(str(unpacked) + ".rich_header.json")
    try:
        sidecar_path.write_text(json.dumps(sidecar, indent=2))
    except OSError:
        pass


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
