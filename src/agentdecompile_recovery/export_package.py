"""Phase 4 multi-format export package for reconstruct work dirs.

Bundles verified C, advisory sketches, asm/hex slices, byte-authority
artifacts, and Ghidra-backed acquisition serialization under one manifest.
Every view carries authorityClass + claimBoundary.
Lint runs on accepted (verified) source only.
"""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path
from typing import Any

from .source_cleanup import format_source_text, lint_source_text
from .state import atomic_write_json, now

SCHEMA = "agentdecompile.export-package.v1"
CLAIM_BOUNDARY = (
    "export package aggregates recovery views with explicit authority classes; "
    "only objdiff-verified-semantic artifacts are accepted source"
)

AUTHORITY_CLASSES = (
    "objdiff-verified-semantic",
    "byte-authoritative",
    "advisory-decompiler",
    "asm-slice",
    "hex-slice",
    "ghidra-acquisition",
    "unverified-candidate",
)

_GHIDRA_ACQUISITION_NAMES = frozenset(
    {
        "ghidra-acquisition.jsonl",
        "ghidra-acquisition-metadata.json",
    }
)


def build_export_package(
    work_dir: Path,
    *,
    out_dir: Path | None = None,
    lint_verified: bool = True,
) -> dict[str, Any]:
    """Write ``export/`` under the reconstruct work directory."""

    work_dir = work_dir.resolve()
    out_dir = (out_dir or (work_dir / "export")).resolve()
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    views: list[dict[str, Any]] = []
    views.extend(_copy_tree_view(work_dir / "verified", out_dir / "verified", authority="objdiff-verified-semantic"))
    views.extend(_copy_tree_view(work_dir / "advisory", out_dir / "advisory", authority="advisory-decompiler"))
    views.extend(_export_asm_and_hex_slices(work_dir, out_dir))
    views.extend(_copy_byte_authority(work_dir, out_dir))
    views.extend(_export_ghidra_serialization(work_dir, out_dir))

    lint_report: dict[str, Any] | None = None
    if lint_verified:
        lint_report = _lint_verified_sources(out_dir / "verified", out_dir / "lint")
        if lint_report is not None:
            views.append(
                {
                    "path": "lint/summary.json",
                    "kind": "lint-summary",
                    "authorityClass": "objdiff-verified-semantic",
                    "claimBoundary": (
                        "lint/format hygiene on accepted verified source only; "
                        "not an additional semantic recovery claim"
                    ),
                    "counts": lint_report.get("counts"),
                }
            )

    by_authority: dict[str, int] = {}
    for view in views:
        key = str(view.get("authorityClass") or "unknown")
        by_authority[key] = by_authority.get(key, 0) + 1

    manifest = {
        "schema": SCHEMA,
        "status": "complete" if views else "empty",
        "writtenAt": now(),
        "workDir": str(work_dir),
        "exportDir": str(out_dir),
        "viewCount": len(views),
        "countsByAuthorityClass": dict(sorted(by_authority.items())),
        "views": views,
        "lint": lint_report,
        "claimBoundary": CLAIM_BOUNDARY,
        "authorityClasses": list(AUTHORITY_CLASSES),
    }
    atomic_write_json(out_dir / "manifest.json", manifest)
    return manifest


def _copy_tree_view(src: Path, dest: Path, *, authority: str) -> list[dict[str, Any]]:
    if not src.is_dir():
        return []
    dest.mkdir(parents=True, exist_ok=True)
    views: list[dict[str, Any]] = []
    for path in sorted(src.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(src)
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        views.append(
            {
                "path": f"{dest.name}/{rel.as_posix()}",
                "kind": _kind_for_suffix(path.suffix),
                "authorityClass": authority,
                "claimBoundary": _claim_for_authority(authority),
                "sha256": _sha256_file(target),
            }
        )
    return views


def _export_asm_and_hex_slices(work_dir: Path, out_dir: Path) -> list[dict[str, Any]]:
    slices_dir = work_dir / "source-generation"
    if not slices_dir.is_dir():
        return []
    asm_out = out_dir / "asm"
    hex_out = out_dir / "hex"
    views: list[dict[str, Any]] = []
    for bin_path in sorted(slices_dir.rglob("*.target.bin")):
        data = bin_path.read_bytes()
        stem = bin_path.name.replace(".target.bin", "")
        asm_out.mkdir(parents=True, exist_ok=True)
        hex_out.mkdir(parents=True, exist_ok=True)
        asm_path = asm_out / f"{stem}.asm"
        hex_path = hex_out / f"{stem}.hex"
        asm_path.write_text(_bytes_to_masm(stem, data), encoding="utf-8")
        hex_path.write_text(data.hex() + "\n", encoding="utf-8")
        views.append(
            {
                "path": f"asm/{asm_path.name}",
                "kind": "asm-slice",
                "authorityClass": "asm-slice",
                "claimBoundary": _claim_for_authority("asm-slice"),
                "sha256": _sha256_file(asm_path),
                "sourceSlice": str(bin_path),
            }
        )
        views.append(
            {
                "path": f"hex/{hex_path.name}",
                "kind": "hex-slice",
                "authorityClass": "hex-slice",
                "claimBoundary": _claim_for_authority("hex-slice"),
                "sha256": _sha256_file(hex_path),
                "sourceSlice": str(bin_path),
            }
        )
    return views


def _copy_byte_authority(work_dir: Path, out_dir: Path) -> list[dict[str, Any]]:
    src = work_dir / "byte-authority"
    if not src.is_dir():
        return []
    dest = out_dir / "byte-authority"
    shutil.copytree(src, dest, dirs_exist_ok=True)
    views: list[dict[str, Any]] = []
    for path in sorted(dest.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(dest)
        views.append(
            {
                "path": f"byte-authority/{rel.as_posix()}",
                "kind": _kind_for_suffix(path.suffix),
                "authorityClass": "byte-authoritative",
                "claimBoundary": _claim_for_authority("byte-authoritative"),
                "sha256": _sha256_file(path),
            }
        )
    return views


def _export_ghidra_serialization(work_dir: Path, out_dir: Path) -> list[dict[str, Any]]:
    """Package existing Ghidra acquisition / .gzf evidence into export/ghidra/.

    Offline packaging only — does not invoke analyzeHeadless. Live Ghidra project
    databases (.rep) are refused; only safe acquisition JSONL/metadata and packed
    .gzf archives are copied.
    """

    candidates: list[Path] = []
    for path in sorted(work_dir.rglob("*")):
        if not path.is_file():
            continue
        # Skip previously built export trees to avoid recursive re-packaging.
        try:
            path.relative_to(out_dir)
            continue
        except ValueError:
            pass
        name = path.name.lower()
        if name in _GHIDRA_ACQUISITION_NAMES or path.suffix.lower() == ".gzf":
            candidates.append(path)

    if not candidates:
        return []

    dest_root = out_dir / "ghidra"
    dest_root.mkdir(parents=True, exist_ok=True)
    views: list[dict[str, Any]] = []
    packaged: list[dict[str, Any]] = []
    used_names: dict[str, int] = {}

    for src in candidates:
        try:
            rel = src.relative_to(work_dir)
            dest_name = rel.as_posix().replace("/", "__")
        except ValueError:
            dest_name = src.name
        stem = Path(dest_name).stem
        suffix = Path(dest_name).suffix
        count = used_names.get(dest_name, 0)
        used_names[dest_name] = count + 1
        if count:
            dest_name = f"{stem}__{count}{suffix}"
        target = dest_root / dest_name
        shutil.copy2(src, target)
        kind = "ghidra-gzf" if src.suffix.lower() == ".gzf" else "ghidra-acquisition"
        view = {
            "path": f"ghidra/{dest_name}",
            "kind": kind,
            "authorityClass": "ghidra-acquisition",
            "claimBoundary": _claim_for_authority("ghidra-acquisition"),
            "sha256": _sha256_file(target),
            "sourcePath": str(src),
        }
        views.append(view)
        packaged.append(
            {
                "exportPath": view["path"],
                "sourcePath": str(src),
                "kind": kind,
                "sha256": view["sha256"],
            }
        )

    receipt = {
        "schema": "agentdecompile.ghidra-export-serialization.v1",
        "status": "complete",
        "writtenAt": now(),
        "artifactCount": len(packaged),
        "artifacts": packaged,
        "claimBoundary": _claim_for_authority("ghidra-acquisition"),
        "mode": "offline-package",
    }
    atomic_write_json(dest_root / "serialization.json", receipt)
    views.append(
        {
            "path": "ghidra/serialization.json",
            "kind": "ghidra-serialization-receipt",
            "authorityClass": "ghidra-acquisition",
            "claimBoundary": _claim_for_authority("ghidra-acquisition"),
            "sha256": _sha256_file(dest_root / "serialization.json"),
            "counts": {"artifacts": len(packaged)},
        }
    )
    return views


def _lint_verified_sources(verified_dir: Path, lint_dir: Path) -> dict[str, Any] | None:
    if not verified_dir.is_dir():
        return None
    lint_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    ok = 0
    skipped = 0
    for path in sorted(verified_dir.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in {".c", ".cpp", ".cc", ".h", ".hpp"}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        formatted, formatting = format_source_text(text, path.suffix)
        lint = lint_source_text(formatted, path.suffix, formatting)
        row = {
            "source": str(path.relative_to(verified_dir)),
            "formatting": formatting,
            "lint": lint,
            "authorityClass": "objdiff-verified-semantic",
            "claimBoundary": "lint on accepted verified source only",
        }
        results.append(row)
        if lint.get("status") in {"ok", "skipped", "unavailable"}:
            ok += 1
        if lint.get("status") in {"skipped", "unavailable"}:
            skipped += 1
        atomic_write_json(lint_dir / f"{path.stem}.lint.json", row)
    summary = {
        "schema": "agentdecompile.export-lint.v1",
        "status": "complete",
        "counts": {"linted": len(results), "okOrSkipped": ok, "toolUnavailable": skipped},
        "results": results,
        "claimBoundary": "lint hygiene only; not semantic recovery proof",
    }
    atomic_write_json(lint_dir / "summary.json", summary)
    return summary


def _bytes_to_masm(name: str, data: bytes) -> str:
    lines = [f"; target slice {name}", f"{name}_bytes:", ""]
    for i in range(0, len(data), 12):
        chunk = ", ".join(f"0{b:02X}h" for b in data[i : i + 12])
        lines.append(f"    db {chunk}")
    lines.append("")
    return "\n".join(lines)


def _kind_for_suffix(suffix: str) -> str:
    lowered = suffix.lower()
    if lowered in {".c", ".cpp", ".cc", ".h", ".hpp"}:
        return "source"
    if lowered in {".asm", ".s"}:
        return "asm"
    if lowered in {".hex"}:
        return "hex"
    if lowered in {".json"}:
        return "receipt"
    if lowered in {".jsonl"}:
        return "ghidra-acquisition"
    if lowered in {".gzf"}:
        return "ghidra-gzf"
    if lowered in {".bin"}:
        return "bytes"
    return "artifact"


def _claim_for_authority(authority: str) -> str:
    return {
        "objdiff-verified-semantic": "objdiff-zero accepted source; not whole-program parity",
        "byte-authoritative": "byte-authority package is not semantic C recovery",
        "advisory-decompiler": "advisory decompiler/LLM sketch until objdiff-verified-semantic",
        "asm-slice": "raw target-slice asm emission; not high-level recovered C",
        "hex-slice": "hex dump of target-slice bytes; acquisition evidence only",
        "ghidra-acquisition": (
            "Ghidra acquisition / packed-project evidence only; "
            "compile and objdiff gates remain required for accepted source"
        ),
        "unverified-candidate": "candidate without objdiff-zero proof",
    }.get(authority, CLAIM_BOUNDARY)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
