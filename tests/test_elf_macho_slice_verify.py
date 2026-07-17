"""Unit tests for Phase 5c ELF/Mach-O symbolized slice verify."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from agentdecompile_recovery.functions import discover_function_candidates, write_function_candidates
from agentdecompile_recovery.inventory import build_binary_inventory, write_inventory
from agentdecompile_recovery.recovery_status import build_recovery_status
from agentdecompile_recovery.slice_verify import (
    is_symbolized_slice_eligible,
    verify_symbolized_slice,
    write_slice_verify_summary,
)
from agentdecompile_recovery.targets import identify_binary
from tests.helpers import _build_sourcedennis_x64_binary

pytestmark = pytest.mark.unit


def _build_symbolized_elf(tmp_path: Path) -> Path:
    source = tmp_path / "slice_fn.c"
    source.write_text(
        "\n".join(
            [
                "__attribute__((noinline)) int slice_fn(void) {",
                "    return 0x2a;",
                "}",
                "int _start(void) { return slice_fn(); }",
                "",
            ]
        ),
        encoding="utf-8",
    )
    binary = tmp_path / "slice_test.elf"
    proc = subprocess.run(
        [
            "gcc",
            "-nostdlib",
            "-static",
            "-o",
            str(binary),
            str(source),
        ],
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )
    if proc.returncode != 0 or not binary.is_file():
        pytest.skip(f"gcc could not build symbolized ELF fixture: {proc.stderr[-500:]}")
    return binary


@pytest.fixture
def requires_clang_objcopy() -> None:
    if not shutil.which("clang") or not shutil.which("objcopy"):
        pytest.skip("clang and objcopy required for slice verify roundtrip")


def test_is_symbolized_slice_eligible_stripped_elf(tmp_path: Path) -> None:
    binary = tmp_path / "stripped.elf"
    binary.write_bytes(_build_sourcedennis_x64_binary())
    target = identify_binary(binary)
    inventory = build_binary_inventory(target)
    eligible, reason = is_symbolized_slice_eligible(inventory)
    assert eligible is False
    assert reason == "no symbol table"


def test_elf_slice_verify_matched(tmp_path: Path, requires_clang_objcopy: None) -> None:
    binary = _build_symbolized_elf(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    target = identify_binary(binary)
    inventory = build_binary_inventory(target)
    write_inventory(work / "binary-inventory.json", inventory)
    candidates_doc = discover_function_candidates(inventory)
    write_function_candidates(work / "function-candidates.json", candidates_doc)

    summary = write_slice_verify_summary(work, inventory, candidates_doc)
    assert summary["schema"] == "agentdecompile.slice-verify.v1"
    assert summary["status"] == "matched"
    assert summary["verificationTier"] == "code-slice"
    assert "does not count toward the proof ladder numerator" in summary["claimBoundary"]
    assert (work / "slice-verify" / "receipt.json").is_file()

    status = build_recovery_status(work)
    assert status["sliceVerify"]["status"] == "matched"
    assert status["paths"]["sliceVerify"] is not None


def test_elf_slice_verify_unsupported_without_symbols(tmp_path: Path) -> None:
    binary = tmp_path / "stripped.elf"
    binary.write_bytes(_build_sourcedennis_x64_binary())
    work = tmp_path / "work-stripped"
    work.mkdir()
    target = identify_binary(binary)
    inventory = build_binary_inventory(target)
    candidates_doc = discover_function_candidates(inventory)
    summary = verify_symbolized_slice(work, inventory, candidates_doc)
    assert summary["status"] == "unsupported-slice-verify"
    assert summary["format"] == "elf"


@pytest.mark.skipif(sys.platform != "darwin", reason="Mach-O slice verify smoke requires macOS host")
def test_macho_slice_verify_skipped_on_linux() -> None:
    pytest.skip("Mach-O fixture smoke is macOS-only per Phase 5 plan")
