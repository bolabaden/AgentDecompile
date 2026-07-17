"""One-call implicit acquisition.

`acquire_context` is the implicit front door: give it a target and any number of
loose context paths (or none) and it sniffs each input, runs the right adapter,
folds everything into a single target-bound acquisition bundle, and registers
that bundle so every downstream consumer can rediscover it from the target
alone.

Mid-run re-acquire merges into the same target fingerprint as a new snapshot
(does not mutate prior snapshot dirs, does not touch verified/ artifacts).
All acquired data is advisory evidence; compile and objdiff gates remain the
acceptance boundary.
"""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import acquisition_registry as registry
from .context_pack import build_context_pack
from .discovery import route_inputs, sniff_path
from .ghidra_context import export_ghidra_context
from .targets import identify_binary


def _target_json(input_path: Path | None, preferred_name: str | None) -> dict[str, Any]:
    if input_path is None:
        return {}
    try:
        identity = identify_binary(input_path, preferred_name)
    except (FileNotFoundError, OSError, ValueError):
        return {}
    return identity.to_json()


def _has_target_identity(target: dict[str, Any]) -> bool:
    return bool(target.get("sha256") or target.get("stableId"))


def _dedupe_paths(paths: list[Path]) -> list[Path]:
    seen: set[str] = set()
    out: list[Path] = []
    for path in paths:
        try:
            key = str(path.resolve())
        except OSError:
            key = str(path)
        if key in seen:
            continue
        seen.add(key)
        out.append(path)
    return out


def prior_context_inputs(prior_bundle: Path) -> list[Path]:
    """Collect durable prior context inputs for mid-run merge.

    Prefers still-existing original source files, and always includes prior
    function-facts / context-items projections so entities survive deleted notes.
    """

    paths: list[Path] = []
    sources_path = prior_bundle / "sources.jsonl"
    if sources_path.is_file():
        for line in sources_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            candidate = Path(str(row.get("path") or ""))
            if candidate.is_file():
                paths.append(candidate)
    for name in ("function-facts.jsonl",):
        candidate = prior_bundle / name
        if candidate.is_file():
            paths.append(candidate)
    pack_parent = prior_bundle.parent
    for name in ("function-facts.jsonl", "context-items.jsonl"):
        candidate = pack_parent / name
        if candidate.is_file():
            paths.append(candidate)
    return _dedupe_paths(paths)


def _write_latest_pointer(out_dir: Path, snapshot_dir: Path, bundle_dir: Path) -> None:
    pointer = {
        "schema": "agentdecompile.acquire-latest.v1",
        "snapshotDir": str(snapshot_dir),
        "bundleDir": str(bundle_dir),
        "updatedAt": datetime.now(timezone.utc).isoformat(),
    }
    (out_dir / "latest.json").write_text(json.dumps(pointer, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    # Compatibility alias for tools that still expect context-pack/ under acquisition/.
    alias = out_dir / "context-pack"
    if alias.is_symlink() or alias.is_file():
        alias.unlink()
    elif not alias.exists():
        try:
            alias.symlink_to(snapshot_dir / "context-pack", target_is_directory=True)
        except OSError:
            pass


def acquire_context(
    *,
    target_input: Path | None,
    context_paths: list[Path] | None = None,
    out_dir: Path,
    preferred_name: str | None = None,
    repo_root: Path | None = None,
    ghidra: Path | None = None,
    project_snapshot: Path | None = None,
    register: bool = True,
    max_files: int = 500,
    merge_prior: bool = True,
) -> dict[str, Any]:
    """Sniff, extract, bundle, and register in one call.

    `target_input` supplies target identity for fingerprinting and can itself be
    sniffed as a binary source for Ghidra extraction.  `context_paths` are extra
    loose artifacts; each is auto-routed.

    When ``merge_prior`` is true (default), a previously registered bundle for the
    same target fingerprint is merged into a new immutable snapshot. This never
    deletes ``verified/`` or other sibling run artifacts under the work directory.
    """

    out_dir.mkdir(parents=True, exist_ok=True)
    # Hard guard: acquisition must never wipe claim-visible verified trees.
    verified_guard = out_dir.parent / "verified" if out_dir.name == "acquisition" else out_dir / "verified"
    verified_before = {
        str(path.relative_to(verified_guard)): path.stat().st_mtime_ns
        for path in verified_guard.rglob("*")
        if path.is_file()
    } if verified_guard.is_dir() else {}

    repo_root = repo_root or Path.cwd()
    target = _target_json(target_input, preferred_name)

    prior_bundle: Path | None = None
    prior_paths: list[Path] = []
    if merge_prior and _has_target_identity(target):
        prior_bundle = registry.find_bundle(target=target, repo_root=repo_root)
        if prior_bundle is not None:
            prior_paths = prior_context_inputs(prior_bundle)

    inputs: list[Path] = list(context_paths or [])
    if target_input is not None:
        try:
            sniffed = sniff_path(target_input)
        except (OSError, ValueError):
            sniffed = None
        if sniffed is not None and sniffed.adapter == "ghidra" and target_input not in inputs:
            inputs.insert(0, target_input)

    merged_inputs = _dedupe_paths([*prior_paths, *inputs])
    routed = route_inputs(merged_inputs)

    snapshot_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    snapshot_dir = out_dir / "snapshots" / snapshot_id
    snapshot_dir.mkdir(parents=True, exist_ok=True)

    ghidra_reports: list[dict[str, Any]] = []
    derived_context: list[Path] = list(routed.context_paths)
    ghidra_errors: list[dict[str, Any]] = []
    for source in routed.ghidra_sources:
        ghidra_out = snapshot_dir / "ghidra" / source.path.stem
        try:
            report = export_ghidra_context(
                source=source.path,
                out_dir=ghidra_out,
                ghidra=ghidra,
                project_snapshot=project_snapshot,
            )
            ghidra_reports.append(report)
            facts_jsonl = Path(str(report.get("factsJsonl") or ""))
            if facts_jsonl.exists():
                derived_context.append(facts_jsonl)
        except (RuntimeError, ValueError, FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
            ghidra_errors.append({"source": str(source.path), "error": str(exc)})

    pack_manifest = build_context_pack(
        contexts=_dedupe_paths(derived_context),
        out_dir=snapshot_dir / "context-pack",
        target=target,
        repo_root=repo_root,
        max_files=max_files,
    )

    bundle_dir = (
        repo_root / str(pack_manifest["bundleDir"])
        if not Path(str(pack_manifest["bundleDir"])).is_absolute()
        else Path(str(pack_manifest["bundleDir"]))
    )
    bundle_manifest_path = bundle_dir / "manifest.json"
    bundle_manifest = json.loads(bundle_manifest_path.read_text(encoding="utf-8")) if bundle_manifest_path.exists() else {}

    registry_entry: dict[str, Any] | None = None
    can_register = register and bool(bundle_manifest) and _has_target_identity(target)
    if can_register:
        try:
            registry_entry = registry.register_bundle(
                bundle_dir=bundle_dir,
                manifest=bundle_manifest,
                repo_root=repo_root,
                label=preferred_name or (Path(str(target.get("binaryPath"))).name if target.get("binaryPath") else None),
            )
        except ValueError:
            registry_entry = None
            can_register = False

    _write_latest_pointer(out_dir, snapshot_dir, bundle_dir)

    if verified_before and verified_guard.is_dir():
        verified_after = {
            str(path.relative_to(verified_guard)): path.stat().st_mtime_ns
            for path in verified_guard.rglob("*")
            if path.is_file()
        }
        missing = sorted(set(verified_before) - set(verified_after))
        if missing:
            raise RuntimeError(f"acquire_context must not delete verified/ artifacts; missing: {missing[:5]}")

    if target_input is not None and not _has_target_identity(target):
        status = "failed"
    elif register and not can_register and not registry_entry:
        status = "partial" if bundle_manifest else "failed"
    else:
        status = "complete"

    return {
        "schema": "agentdecompile.acquire.v1",
        "status": status,
        "target": target,
        "targetFingerprint": bundle_manifest.get("targetFingerprint") if _has_target_identity(target) else None,
        "routing": routed.to_json(),
        "ghidraReports": ghidra_reports,
        "ghidraErrors": ghidra_errors,
        "contextPack": pack_manifest,
        "bundleDir": str(bundle_dir),
        "snapshotDir": str(snapshot_dir),
        "priorBundleDir": str(prior_bundle) if prior_bundle is not None else None,
        "mergedPriorSourceCount": len(prior_paths),
        "mergedInputCount": len(merged_inputs),
        "registered": registry_entry is not None,
        "registryEntry": registry_entry,
        "claimBoundary": "acquired context is advisory evidence only; compile and objdiff gates remain required.",
    }
