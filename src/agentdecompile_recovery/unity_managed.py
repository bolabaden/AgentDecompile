"""Decompile shipped managed assemblies into C# a Unity project can compile.

A Unity Mono player ships its gameplay code as IL in ``*_Data/Managed/*.dll``,
which ILSpy reconstructs into readable C#. Getting *readable* output is the easy
half. The half that breaks reconstructions is that ILSpy's project mode emits
per-assembly scaffolding which is correct for a standalone ``.csproj`` and fatal
the moment the same files land in a Unity ``Assets/`` folder, where Unity
compiles every ``.cs`` under the tree into one assembly:

* ``Properties/AssemblyInfo.cs`` re-declares assembly attributes Unity already
  generates -> ``CS0579: duplicate 'AssemblyVersion' attribute``.
* ``UnitySourceGeneratedAssemblyMonoScriptTypes_v1.cs`` is Unity's own generated
  MonoScript type table, decompiled back out of the shipped DLL and then
  generated *again* at compile time -> ``CS0101: the namespace already contains
  a definition``.

Both fire on the first import and neither points at the real cause, so they are
stripped here rather than left for a repair loop to rediscover. Assemblies also
get one output directory each: ``Assembly-CSharp`` and
``Assembly-CSharp-firstpass`` are separate assemblies that legally contain types
of the same fully-qualified name, and merging their trees turns that legal
overlap into unresolvable CS0101s.

Decompilation is the only thing this module claims. Whether the result compiles
is decided by an Editor import, which is a later stage with its own receipt.
"""

from __future__ import annotations

import subprocess

from pathlib import Path
from typing import Any

from .tools import ToolchainError, resolve_ilspycmd, run_ilspycmd

# ILSpy project-mode scaffolding that breaks a Unity compile. Matched by
# filename anywhere in the tree: ILSpy places AssemblyInfo.cs under Properties/,
# but the namespace layout of the source assembly can move it.
SCAFFOLDING_FILENAMES: tuple[str, ...] = (
    "AssemblyInfo.cs",
    "UnitySourceGeneratedAssemblyMonoScriptTypes_v1.cs",
)

# The assemblies that hold a Unity game's own code. `-firstpass` is compiled
# before the main assembly (Plugins/Standard Assets), so it can never reference
# it -- which is exactly why the two are shipped, and recovered, separately.
DEFAULT_GAME_ASSEMBLIES: tuple[str, ...] = ("Assembly-CSharp", "Assembly-CSharp-firstpass")

_ASSEMBLY_SCHEMA = "agentdecompile.unity-managed-assembly.v1"
_SCHEMA = "agentdecompile.unity-managed.v1"

_CLAIM_BOUNDARY = (
    "decompiled C# is a behavioural reconstruction from IL, not original source: names of locals, "
    "control-flow shape, comments, and compiler-generated constructs differ from what the developers "
    "wrote, and semantic equivalence is unverified. This stage proves only that ILSpy emitted files; "
    "it does not prove they compile -- a later Editor import stage decides that."
)


def _count_cs_files(directory: Path) -> int:
    if not directory.is_dir():
        return 0
    return sum(1 for _ in directory.rglob("*.cs"))


def strip_scaffolding(source_dir: Path) -> list[str]:
    """Delete ILSpy scaffolding under ``source_dir``; return what was removed.

    Paths are returned relative to ``source_dir`` so a receipt stays meaningful
    after the tree is moved into a Unity project. Pure filesystem work, no
    subprocess: this is the piece worth testing directly, because a missed file
    surfaces later as a compiler error with no obvious connection to this stage.
    """

    source_dir = Path(source_dir)
    if not source_dir.is_dir():
        return []

    wanted = set(SCAFFOLDING_FILENAMES)
    removed: list[str] = []
    emptied_parents: set[Path] = set()

    for path in sorted(source_dir.rglob("*.cs")):
        if path.name not in wanted or not path.is_file():
            continue
        try:
            path.unlink()
        except OSError:
            continue
        removed.append(path.relative_to(source_dir).as_posix())
        emptied_parents.add(path.parent)

    # An ILSpy `Properties/` folder holding nothing but AssemblyInfo.cs becomes an
    # empty directory that Unity would import as a stray asset folder.
    for parent in sorted(emptied_parents, reverse=True):
        if parent == source_dir:
            continue
        try:
            if not any(parent.iterdir()):
                parent.rmdir()
        except OSError:
            continue

    return removed


def _resolve_ilspycmd(ilspycmd: Path | None) -> Path:
    resolved = resolve_ilspycmd(ilspycmd) if ilspycmd is None else Path(ilspycmd).expanduser()
    if resolved is None or not Path(resolved).is_file():
        raise ToolchainError(
            "ilspycmd-missing",
            detail=(
                "ilspycmd not found; install with `dotnet tool install -g ilspycmd` "
                "or set AGENTDECOMPILE_ILSPYCMD"
            ),
        )
    return Path(resolved).resolve()


def decompile_assembly(
    assembly: Path,
    out_dir: Path,
    *,
    ilspycmd: Path | None = None,
    reference_dirs: list[Path] | None = None,
    timeout: int = 1800,
) -> dict[str, Any]:
    """Decompile one assembly into ``out_dir`` and strip Unity-hostile scaffolding.

    ``reference_dirs`` should include the shipped ``Managed`` folder: without it
    ILSpy cannot resolve types that live in sibling assemblies and silently emits
    weaker output (unresolved base types become ``object``).
    """

    assembly = Path(assembly).resolve()
    out_dir = Path(out_dir).resolve()
    cli = _resolve_ilspycmd(ilspycmd)

    if not assembly.is_file():
        return {
            "schema": _ASSEMBLY_SCHEMA,
            "status": "skipped",
            "reason": f"assembly not present: {assembly}",
            "assembly": assembly.stem,
            "assemblyPath": str(assembly),
            "outDir": str(out_dir),
            "fileCount": 0,
            "stripped": [],
            "claimBoundary": _CLAIM_BOUNDARY,
        }

    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        proc = run_ilspycmd(
            cli,
            assembly,
            out_dir,
            reference_dirs=list(reference_dirs or []),
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {
            "schema": _ASSEMBLY_SCHEMA,
            "status": "error",
            "reason": f"ilspycmd timed out after {timeout}s",
            "assembly": assembly.stem,
            "assemblyPath": str(assembly),
            "outDir": str(out_dir),
            "fileCount": _count_cs_files(out_dir),
            "stripped": [],
            "claimBoundary": _CLAIM_BOUNDARY,
        }

    stripped = strip_scaffolding(out_dir)
    file_count = _count_cs_files(out_dir)

    # ilspycmd can exit 0 having written nothing when it fails to load the input,
    # so the file count is the real success signal and the return code is context.
    if proc.returncode != 0 or file_count == 0:
        reason = (
            f"ilspycmd exited {proc.returncode}"
            if proc.returncode != 0
            else "ilspycmd exited 0 but wrote no .cs files"
        )
        return {
            "schema": _ASSEMBLY_SCHEMA,
            "status": "error",
            "reason": reason,
            "assembly": assembly.stem,
            "assemblyPath": str(assembly),
            "outDir": str(out_dir),
            "fileCount": file_count,
            "stripped": stripped,
            "returnCode": proc.returncode,
            "stderr": (proc.stderr or "").strip()[-2000:],
            "claimBoundary": _CLAIM_BOUNDARY,
        }

    return {
        "schema": _ASSEMBLY_SCHEMA,
        "status": "complete",
        "reason": None,
        "assembly": assembly.stem,
        "assemblyPath": str(assembly),
        "assemblyBytes": assembly.stat().st_size,
        "outDir": str(out_dir),
        "fileCount": file_count,
        "stripped": stripped,
        "returnCode": proc.returncode,
        "claimBoundary": _CLAIM_BOUNDARY,
    }


def discover_game_assemblies(data_dir: Path, names: list[str] | None = None) -> list[Path]:
    """Resolve assembly names to paths under ``<data_dir>/Managed``. Read-only."""

    managed = Path(data_dir) / "Managed"
    wanted = list(names) if names else list(DEFAULT_GAME_ASSEMBLIES)
    found: list[Path] = []
    for name in wanted:
        stem = name[:-4] if name.lower().endswith(".dll") else name
        candidate = managed / f"{stem}.dll"
        if candidate.is_file():
            found.append(candidate)
    return found


def decompile_game_assemblies(
    data_dir: Path,
    out_dir: Path,
    *,
    ilspycmd: Path | None = None,
    assemblies: list[str] | None = None,
    timeout: int = 1800,
) -> dict[str, Any]:
    """Decompile a game's own assemblies into one output subdirectory each.

    ``<data_dir>/Managed`` is passed to ILSpy as a reference directory so
    cross-assembly types resolve against the exact DLLs that shipped, rather than
    against whatever happens to be installed on the host.
    """

    data_dir = Path(data_dir).resolve()
    out_dir = Path(out_dir).resolve()
    cli = _resolve_ilspycmd(ilspycmd)

    managed = data_dir / "Managed"
    if not managed.is_dir():
        return {
            "schema": _SCHEMA,
            "status": "error",
            "reason": f"no Managed directory under data dir: {managed}",
            "dataDir": str(data_dir),
            "outDir": str(out_dir),
            "assemblies": [],
            "claimBoundary": _CLAIM_BOUNDARY,
        }

    requested = list(assemblies) if assemblies else list(DEFAULT_GAME_ASSEMBLIES)
    targets = discover_game_assemblies(data_dir, requested)
    if not targets:
        return {
            "schema": _SCHEMA,
            "status": "skipped",
            "reason": (
                f"none of the requested assemblies are present under {managed}: "
                f"{', '.join(requested)}"
            ),
            "dataDir": str(data_dir),
            "managedDir": str(managed),
            "outDir": str(out_dir),
            "requested": requested,
            "assemblies": [],
            "claimBoundary": _CLAIM_BOUNDARY,
        }

    out_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    stripped: list[str] = []
    total_files = 0

    for assembly in targets:
        # One directory per assembly: Assembly-CSharp and -firstpass may declare
        # the same type names, and a merged tree makes that a compile error.
        assembly_out = out_dir / assembly.stem
        result = decompile_assembly(
            assembly,
            assembly_out,
            ilspycmd=cli,
            reference_dirs=[managed],
            timeout=timeout,
        )
        results.append(result)
        total_files += int(result.get("fileCount") or 0)
        stripped.extend(f"{assembly.stem}/{path}" for path in result.get("stripped") or [])

    failed = [entry["assembly"] for entry in results if entry["status"] == "error"]
    succeeded = [entry["assembly"] for entry in results if entry["status"] == "complete"]

    if failed:
        status = "error"
        reason = f"decompilation failed for: {', '.join(failed)}"
    elif not succeeded:
        status = "skipped"
        reason = "no assembly produced output"
    else:
        status = "complete"
        reason = None

    return {
        "schema": _SCHEMA,
        "status": status,
        "reason": reason,
        "dataDir": str(data_dir),
        "managedDir": str(managed),
        "outDir": str(out_dir),
        "ilspycmd": str(cli),
        "requested": requested,
        "decompiled": succeeded,
        "failed": failed,
        "assemblies": results,
        "totalFileCount": total_files,
        "strippedCount": len(stripped),
        "stripped": stripped,
        "claimBoundary": _CLAIM_BOUNDARY,
    }
