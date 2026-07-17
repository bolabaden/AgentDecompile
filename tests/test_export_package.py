"""Unit tests for Phase 4 multi-format export package."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery.export_package import AUTHORITY_CLASSES, build_export_package
from agentdecompile_recovery.state import atomic_write_json

pytestmark = pytest.mark.unit


def test_build_export_package_segregates_authority_classes(tmp_path: Path) -> None:
    work = tmp_path / "run"
    (work / "verified").mkdir(parents=True)
    (work / "advisory").mkdir(parents=True)
    (work / "verified" / "fn_401000.c").write_text("int fn(void){return 0;}\n", encoding="utf-8")
    atomic_write_json(
        work / "verified" / "fn_401000.json",
        {"status": "matched", "differences": 0, "proofTier": "target-object-objdiff-match"},
    )
    (work / "advisory" / "fn_401000.c").write_text("/* advisory */\nint fn(void){return 1;}\n", encoding="utf-8")
    slices = work / "source-generation"
    slices.mkdir(parents=True)
    (slices / "fn_401000.target.bin").write_bytes(b"\x90\xc3")
    (work / "byte-authority").mkdir()
    atomic_write_json(work / "byte-authority" / "result.json", {"status": "complete", "claimBoundary": "byte package"})

    manifest = build_export_package(work)
    assert manifest["schema"] == "agentdecompile.export-package.v1"
    assert manifest["status"] == "complete"
    assert (work / "export" / "manifest.json").is_file()
    assert (work / "export" / "verified" / "fn_401000.c").is_file()
    assert (work / "export" / "advisory" / "fn_401000.c").is_file()
    assert (work / "export" / "asm" / "fn_401000.asm").is_file()
    assert (work / "export" / "hex" / "fn_401000.hex").is_file()
    assert (work / "export" / "byte-authority" / "result.json").is_file()
    assert (work / "export" / "lint" / "summary.json").is_file()

    classes = {view["authorityClass"] for view in manifest["views"]}
    assert "objdiff-verified-semantic" in classes
    assert "advisory-decompiler" in classes
    assert "asm-slice" in classes
    assert "hex-slice" in classes
    assert "byte-authoritative" in classes
    for view in manifest["views"]:
        assert view["authorityClass"] in AUTHORITY_CLASSES or view["kind"] == "lint-summary"
        assert "claimBoundary" in view
    assert all(
        "objdiff" in view["claimBoundary"]
        or "byte" in view["claimBoundary"]
        or "advisory" in view["claimBoundary"]
        or "asm" in view["claimBoundary"]
        or "hex" in view["claimBoundary"]
        or "lint" in view["claimBoundary"]
        or "Ghidra" in view["claimBoundary"]
        for view in manifest["views"]
    )


def test_build_export_package_includes_ghidra_serialization(tmp_path: Path) -> None:
    work = tmp_path / "run"
    ghidra_dir = work / "snapshots" / "20260717T000000Z" / "ghidra" / "target"
    ghidra_dir.mkdir(parents=True)
    (ghidra_dir / "ghidra-acquisition.jsonl").write_text(
        '{"schema":"agentdecompile.function-fact.v1","name":"fn"}\n',
        encoding="utf-8",
    )
    atomic_write_json(
        ghidra_dir / "ghidra-acquisition-metadata.json",
        {"status": "complete", "mode": "ephemeral-import"},
    )
    packed = work / "artifacts"
    packed.mkdir()
    (packed / "target.gzf").write_bytes(b"GZPK")

    manifest = build_export_package(work, lint_verified=False)
    assert (work / "export" / "ghidra" / "serialization.json").is_file()
    classes = {view["authorityClass"] for view in manifest["views"]}
    assert "ghidra-acquisition" in classes
    kinds = {view["kind"] for view in manifest["views"]}
    assert "ghidra-acquisition" in kinds
    assert "ghidra-gzf" in kinds
    assert "ghidra-serialization-receipt" in kinds
    for view in manifest["views"]:
        if view["authorityClass"] == "ghidra-acquisition":
            assert "objdiff" in view["claimBoundary"]
            assert "accepted source" in view["claimBoundary"]


def test_build_export_package_empty_work_dir(tmp_path: Path) -> None:
    work = tmp_path / "empty"
    work.mkdir()
    manifest = build_export_package(work, lint_verified=False)
    assert manifest["status"] == "empty"
    assert manifest["viewCount"] == 0
    assert (work / "export" / "manifest.json").is_file()
