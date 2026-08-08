"""Probe a shipped Unity player and plan its reconstruction.

Everything a Unity reconstruction needs to decide -- editor version, scripting
backend, scene inventory and build order, which package dependencies to declare,
and whether the asset graph will fit in RAM -- is derivable from the shipped
player layout. This module does that derivation and nothing else: it reads, it
never writes into a game install, and it never invokes an external tool.

Two entry points, matching the two pipeline stages:

* :func:`probe_unity_install` -- what *is* this game (facts only).
* :func:`build_unity_plan` -- what should we *do* about it (decisions only).

Keeping facts and decisions in separate receipts means a plan can be re-derived
with different budgets without re-probing, and a surprising plan can always be
traced back to the fact that produced it.
"""

from __future__ import annotations

import os
import re
import shutil

from pathlib import Path
from typing import Any

from .unity_assets import find_unity_data_dir

# Unity version strings: 2022.3.62f2, 6000.5.6f1, 2019.4.40f1b3 ...
_VERSION_RE = re.compile(rb"(\d+\.\d+\.\d+[abfpx]\d+(?:c\d+)?)")

# `levelN` is the shipped form of build index N -- the scene list and its order
# are recoverable from filenames alone, before any export tool runs.
_LEVEL_RE = re.compile(r"^level(\d+)$")

# Serialized-data containers that hold scene and scene-shared data. Everything
# here must be present for scenes to export with intact references.
_SCENE_CRITICAL_PREFIXES = ("globalgamemanagers", "level", "sharedassets")

# Runtime `Resources.Load` content. Large, and *not* required for scene export --
# which is what makes it the correct first thing to drop under memory pressure.
_RESOURCES_STEMS = ("resources.assets",)

# Shipped managed assembly -> UPM package that provides it in an editable project.
# AssetRipper emits only `com.unity.modules.*` built-ins, so third-party and
# non-module first-party packages have to come from assembly evidence.
_ASSEMBLY_PACKAGE_MAP: dict[str, str] = {
    "Unity.InputSystem": "com.unity.inputsystem",
    "Unity.TextMeshPro": "com.unity.textmeshpro",
    "Unity.Timeline": "com.unity.timeline",
    "Unity.Burst": "com.unity.burst",
    "Unity.Collections": "com.unity.collections",
    "Unity.Mathematics": "com.unity.mathematics",
    "Unity.AI.Navigation": "com.unity.ai.navigation",
    "Unity.Addressables": "com.unity.addressables",
    "Unity.ResourceManager": "com.unity.addressables",
    "Unity.ScriptableBuildPipeline": "com.unity.scriptablebuildpipeline",
    "Unity.XR.Management": "com.unity.xr.management",
    "Unity.XR.OpenVR": "com.unity.xr.openvr.standalone",
    "Unity.XR.Oculus": "com.unity.xr.oculus",
    "Unity.XR.OpenXR": "com.unity.xr.openxr",
    "UnityEngine.UI": "com.unity.ugui",
    "Unity.RenderPipelines.Universal.Runtime": "com.unity.render-pipelines.universal",
    "Unity.RenderPipelines.HighDefinition.Runtime": "com.unity.render-pipelines.high-definition",
    "Unity.RenderPipelines.Core.Runtime": "com.unity.render-pipelines.core",
    "Unity.Postprocessing.Runtime": "com.unity.postprocessing",
    "Cinemachine": "com.unity.cinemachine",
    "Unity.Splines": "com.unity.splines",
    "Unity.VisualScripting.Core": "com.unity.visualscripting",
    "Unity.Services.Core": "com.unity.services.core",
    "Unity.Services.Analytics": "com.unity.services.analytics",
    "Unity.Netcode.Runtime": "com.unity.netcode.gameobjects",
    "Unity.Recorder": "com.unity.recorder",
    "Unity.2D.Animation.Runtime": "com.unity.2d.animation",
    "Unity.ProBuilder": "com.unity.probuilder",
}

# Assemblies that mean "this build shipped XR/VR". Recorded, never auto-stripped:
# whether XR actually breaks an editable project is decided by the repair loop
# from real errors, not guessed here.
_XR_MARKERS = ("Unity.XR.", "UnityEngine.XR", "OpenVR", "SteamVR", "Oculus")

# Assemblies that are Unity's own or the game's -- never third-party plugin DLLs.
_FIRST_PARTY_PREFIXES = ("Unity", "UnityEngine", "UnityEditor", "Assembly-CSharp", "System", "mscorlib", "netstandard", "Mono.")


def _safe_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def detect_unity_version(data_dir: Path) -> str | None:
    """Read the build's Unity version out of its serialized headers.

    ``globalgamemanagers`` carries the version as a NUL-terminated ASCII string
    near the head of the file. Falls back to other containers because a few
    build configurations (notably ``data.unity3d`` single-file players) omit it.
    """

    candidates = [data_dir / "globalgamemanagers", data_dir / "data.unity3d"]
    candidates.extend(sorted(data_dir.glob("level0")))
    for candidate in candidates:
        if not candidate.is_file():
            continue
        try:
            with candidate.open("rb") as handle:
                head = handle.read(4096)
        except OSError:
            continue
        match = _VERSION_RE.search(head)
        if match:
            return match.group(1).decode("ascii", "replace")
    return None


def detect_scripting_backend(install_root: Path, data_dir: Path) -> str:
    """``mono``, ``il2cpp``, or ``unknown``.

    IL2CPP compiles managed code to native and ships no decompilable assemblies,
    so this determines whether managed source recovery is possible at all.
    """

    managed = data_dir / "Managed"
    has_managed_dlls = managed.is_dir() and any(managed.glob("*.dll"))
    il2cpp_markers = [
        data_dir / "il2cpp_data",
        install_root / "GameAssembly.dll",
        install_root / "GameAssembly.so",
    ]
    has_il2cpp = any(marker.exists() for marker in il2cpp_markers)
    if has_managed_dlls and not has_il2cpp:
        return "mono"
    if has_il2cpp:
        return "il2cpp"
    return "unknown"


def discover_scenes(data_dir: Path) -> list[dict[str, Any]]:
    """Recover the scene list and build order from ``levelN`` filenames."""

    scenes: list[dict[str, Any]] = []
    for path in sorted(data_dir.iterdir()):
        if not path.is_file():
            continue
        match = _LEVEL_RE.match(path.name)
        if not match:
            continue
        scenes.append(
            {
                "buildIndex": int(match.group(1)),
                "container": path.name,
                "sizeBytes": _safe_size(path),
                "streamedResourceBytes": _safe_size(data_dir / f"{path.name}.resS"),
            }
        )
    scenes.sort(key=lambda entry: entry["buildIndex"])
    return scenes


def discover_managed_assemblies(data_dir: Path) -> list[dict[str, Any]]:
    """List shipped managed assemblies, classified for downstream routing."""

    managed = data_dir / "Managed"
    if not managed.is_dir():
        return []
    out: list[dict[str, Any]] = []
    for path in sorted(managed.glob("*.dll")):
        stem = path.stem
        out.append(
            {
                "name": stem,
                "sizeBytes": _safe_size(path),
                "isGameAssembly": stem.startswith("Assembly-CSharp"),
                "isThirdParty": not stem.startswith(_FIRST_PARTY_PREFIXES),
                "package": _ASSEMBLY_PACKAGE_MAP.get(stem),
            }
        )
    return out


def map_assemblies_to_packages(assemblies: list[dict[str, Any]]) -> dict[str, str]:
    """Package dependencies implied by the shipped assembly set."""

    packages: dict[str, str] = {}
    for entry in assemblies:
        package = entry.get("package")
        if package:
            packages[str(package)] = "*"
    return packages


def detect_xr(assemblies: list[dict[str, Any]]) -> dict[str, Any]:
    markers = sorted({entry["name"] for entry in assemblies if str(entry["name"]).startswith(_XR_MARKERS)})
    return {"present": bool(markers), "assemblies": markers}


def _available_memory_bytes() -> int | None:
    """Best-effort available (not merely free) RAM, in bytes."""

    try:  # Linux: MemAvailable already accounts for reclaimable cache.
        meminfo = Path("/proc/meminfo").read_text(encoding="utf-8")
    except OSError:
        pass
    else:
        for line in meminfo.splitlines():
            if line.startswith("MemAvailable:"):
                parts = line.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    return int(parts[1]) * 1024
    try:
        return os.sysconf("SC_AVPHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
    except (ValueError, OSError, AttributeError):
        return None


def probe_unity_install(install_root: Path) -> dict[str, Any]:
    """Derive the facts a Unity reconstruction plan needs. Read-only."""

    install_root = install_root.resolve()
    if not install_root.is_dir():
        return {
            "schema": "agentdecompile.unity-probe.v1",
            "status": "error",
            "detected": False,
            "reason": f"install root is not a directory: {install_root}",
            "installRoot": str(install_root),
        }

    data_dir = find_unity_data_dir(install_root)
    if data_dir is None:
        return {
            "schema": "agentdecompile.unity-probe.v1",
            "status": "complete",
            "detected": False,
            "reason": "no *_Data directory found under install root",
            "installRoot": str(install_root),
            "claimBoundary": "absence of a *_Data directory only rules out a standard desktop player layout",
        }

    scenes = discover_scenes(data_dir)
    assemblies = discover_managed_assemblies(data_dir)
    backend = detect_scripting_backend(install_root, data_dir)
    version = detect_unity_version(data_dir)

    containers: list[dict[str, Any]] = []
    for path in sorted(data_dir.iterdir()):
        if not path.is_file():
            continue
        containers.append({"name": path.name, "sizeBytes": _safe_size(path)})
    total_bytes = sum(entry["sizeBytes"] for entry in containers)

    return {
        "schema": "agentdecompile.unity-probe.v1",
        "status": "complete",
        "detected": True,
        "installRoot": str(install_root),
        "dataDir": str(data_dir),
        "gameName": data_dir.name.removesuffix("_Data"),
        "unityVersion": version,
        "scriptingBackend": backend,
        "sceneCount": len(scenes),
        "scenes": scenes,
        "managedAssemblyCount": len(assemblies),
        "gameAssemblies": [entry["name"] for entry in assemblies if entry["isGameAssembly"]],
        "thirdPartyAssemblies": [entry["name"] for entry in assemblies if entry["isThirdParty"]],
        "impliedPackages": map_assemblies_to_packages(assemblies),
        "xr": detect_xr(assemblies),
        "dataBytes": total_bytes,
        "containers": containers,
        "hasStreamingAssets": (install_root / "StreamingAssets").is_dir()
        or (data_dir / "StreamingAssets").is_dir(),
        "claimBoundary": (
            "derived from shipped file layout and headers only; no asset graph was parsed, "
            "so scene contents and reference integrity remain unverified"
        ),
    }


def build_unity_plan(
    probe: dict[str, Any],
    *,
    max_memory_gb: float | None = None,
    include_resources_assets: bool | None = None,
    requested_editor_version: str | None = None,
    installed_editors: dict[str, Path] | None = None,
    memory_safety_factor: float = 0.55,
) -> dict[str, Any]:
    """Decide how to export this game, given a memory budget and host editors.

    The memory decision exists because whole-graph exporters load the asset graph
    before writing anything: on a large title that exceeds RAM and dies partway,
    which is exactly how a previous run of this pipeline lost its scenes. When
    the budget is short, ``resources.assets`` is dropped first -- it is the
    largest container and the only large one that scene export does not need.
    """

    from .tools import select_unity_editor  # local import keeps this module tool-free

    if not probe.get("detected"):
        return {
            "schema": "agentdecompile.unity-plan.v1",
            "status": "skipped",
            "reason": probe.get("reason", "target is not a Unity game"),
        }

    containers: list[dict[str, Any]] = list(probe.get("containers") or [])
    total_bytes = int(probe.get("dataBytes") or 0)

    available = _available_memory_bytes()
    if max_memory_gb is not None:
        budget_bytes: int | None = int(max_memory_gb * 1024**3)
    elif available is not None:
        budget_bytes = int(available * memory_safety_factor)
    else:
        budget_bytes = None

    def _is_resources(name: str) -> bool:
        lowered = name.lower()
        return any(lowered == stem or lowered.startswith(f"{stem}.") for stem in _RESOURCES_STEMS)

    resources_bytes = sum(entry["sizeBytes"] for entry in containers if _is_resources(entry["name"]))
    over_budget = budget_bytes is not None and total_bytes > budget_bytes

    if include_resources_assets is True:
        drop_resources = False
        reason = "explicitly requested via --unity-include-resources-assets"
    elif include_resources_assets is False:
        drop_resources = True
        reason = "explicitly excluded via --no-unity-include-resources-assets"
    elif over_budget and resources_bytes > 0:
        drop_resources = True
        reason = (
            f"data ({total_bytes / 1024**3:.1f} GiB) exceeds memory budget "
            f"({budget_bytes / 1024**3:.1f} GiB); dropping resources.assets frees "
            f"{resources_bytes / 1024**3:.1f} GiB and is not required for scene export"
        )
    else:
        drop_resources = False
        reason = "full export fits the memory budget" if not over_budget else "no resources.assets container to drop"

    included: list[str] = []
    excluded: list[str] = []
    for entry in containers:
        if drop_resources and _is_resources(entry["name"]):
            excluded.append(entry["name"])
        else:
            included.append(entry["name"])

    staged_bytes = sum(entry["sizeBytes"] for entry in containers if entry["name"] in set(included))

    version, executable, match = select_unity_editor(
        requested_editor_version or probe.get("unityVersion"),
        installed=installed_editors,
    )

    backend = probe.get("scriptingBackend")
    blocked: str | None = None
    if backend == "il2cpp":
        blocked = (
            "il2cpp: managed assemblies are compiled to native code in this build, so no "
            "decompilable Assembly-CSharp exists; managed source recovery needs Cpp2IL/Il2CppDumper"
        )
    elif backend == "unknown":
        blocked = "unknown scripting backend: neither Managed/*.dll nor IL2CPP markers were found"

    return {
        "schema": "agentdecompile.unity-plan.v1",
        "status": "blocked" if blocked else "complete",
        "blockedReason": blocked,
        "export": {
            "mode": "staged" if drop_resources else "full",
            "reason": reason,
            "includedContainers": included,
            "excludedContainers": excluded,
            "stagedBytes": staged_bytes,
            "totalBytes": total_bytes,
            "memoryBudgetBytes": budget_bytes,
            "availableMemoryBytes": available,
        },
        "editor": {
            "requestedVersion": requested_editor_version or probe.get("unityVersion"),
            "selectedVersion": version,
            "executable": str(executable) if executable else None,
            "match": match,
            "versionDrift": match not in {"exact", "none"},
        },
        "packages": probe.get("impliedPackages") or {},
        "xr": probe.get("xr") or {"present": False, "assemblies": []},
        "claimBoundary": (
            "a staged export omits containers listed in excludedContainers; assets loaded from them "
            "at runtime will be unresolved references in the reconstructed project"
        ),
    }


def stage_export_tree(
    data_dir: Path,
    staging_dir: Path,
    included_containers: list[str],
    *,
    extra_dirs: tuple[str, ...] = ("Managed",),
) -> dict[str, Any]:
    """Build a symlink tree exposing only ``included_containers`` to an exporter.

    Symlinks (not copies) so staging a 2 GiB subset of a 15 GiB install costs
    kilobytes and seconds; the exporter sees a normal ``*_Data`` directory.
    """

    staging_dir = staging_dir.resolve()
    if staging_dir.exists():
        shutil.rmtree(staging_dir)
    target_data = staging_dir / data_dir.name
    target_data.mkdir(parents=True, exist_ok=True)

    linked: list[str] = []
    wanted = set(included_containers)
    for path in sorted(data_dir.iterdir()):
        if path.is_file() and path.name in wanted:
            (target_data / path.name).symlink_to(path)
            linked.append(path.name)
    for dir_name in extra_dirs:
        source = data_dir / dir_name
        if source.is_dir():
            (target_data / dir_name).symlink_to(source, target_is_directory=True)
            linked.append(f"{dir_name}/")

    return {
        "stagingDir": str(staging_dir),
        "dataDir": str(target_data),
        "linked": linked,
        "linkCount": len(linked),
    }
