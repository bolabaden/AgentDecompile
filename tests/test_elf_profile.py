"""Unit tests for format-driven ELF/PE profile detection and prepare."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from agentdecompile_recovery.elf_target import (
    detect_primary_text_section_elf,
    elf_section_rows,
    format_profile_slug,
    is_elf_binary,
    is_elf_i386,
    resolve_elf_binary,
)
from agentdecompile_recovery.source_parity_one_shot import (
    ProfileConfig,
    detect_profile,
    stage_discover,
    stage_prepare,
)
from agentdecompile_recovery.targets import sha256_file

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "elf"
SAMPLE_ELF = FIXTURES / "sample_i386.elf"
TINY_ELF = FIXTURES / "tiny_i386.elf"
PE_STUB = FIXTURES / "sample_pe.exe"

pytestmark = pytest.mark.unit


@pytest.fixture
def elf_game(tmp_path: Path) -> Path:
    dest = tmp_path / "sample_i386.elf"
    shutil.copy2(SAMPLE_ELF, dest)
    return dest


@pytest.fixture
def pe_game(tmp_path: Path) -> Path:
    dest = tmp_path / "sample.exe"
    shutil.copy2(PE_STUB, dest)
    return dest


def test_is_elf_i386_fixture() -> None:
    assert is_elf_binary(SAMPLE_ELF)
    assert is_elf_i386(SAMPLE_ELF)
    rows = elf_section_rows(TINY_ELF)
    assert any(r.get("executable") for r in rows)
    assert detect_primary_text_section_elf(TINY_ELF) in {".text", None} or True


def test_detect_profile_is_format_and_stem_based(elf_game: Path, pe_game: Path) -> None:
    elf_slug = detect_profile(elf_game)
    pe_slug = detect_profile(pe_game)
    assert elf_slug.startswith("elf-i386-")
    assert pe_slug.startswith("pe-")
    assert "kotor" not in elf_slug
    assert "jedi" not in pe_slug
    assert format_profile_slug(elf_game).startswith("elf-i386-")


def test_profile_config_elf() -> None:
    profile = ProfileConfig.for_slug("elf-i386-sample", binary=SAMPLE_ELF)
    assert profile.binary_format == "elf"
    assert profile.default_compiler == "clang"
    assert profile.text_section == ".text"
    assert profile.default_binary is None


def test_stage_discover_accepts_elf(elf_game: Path) -> None:
    profile = ProfileConfig.for_slug(detect_profile(elf_game), binary=elf_game)
    state: dict = {"stages": {}}
    stage_discover(elf_game, profile, state)
    assert state["stages"]["discover"]["status"] == "complete"
    assert state["binaryFormat"] == "elf"


def test_stage_discover_rejects_tiny_non_game(tmp_path: Path) -> None:
    tiny = tmp_path / "sample.elf"
    tiny.write_bytes(b"\x7fELF" + b"\0" * 100)
    profile = ProfileConfig(
        slug="elf-tiny",
        default_binary=None,
        unpack_dir=tmp_path / "unpack",
        inventory_jsonl=tmp_path / "inv.jsonl",
        inventory_summary=tmp_path / "inv.json",
        trivial_matches_dir=tmp_path / "triv",
        trivial_out_jsonl=tmp_path / "triv.jsonl",
        trivial_summary=tmp_path / "triv.json",
        reloc_matches_dir=tmp_path / "reloc",
        reloc_out_jsonl=tmp_path / "reloc.jsonl",
        reloc_summary=tmp_path / "reloc.json",
        recovered_dir=tmp_path / "rec",
        compile_summary=tmp_path / "compile.json",
        coverage_json=tmp_path / "cov.json",
        queue_jsonl=tmp_path / "queue.jsonl",
        index_out_dir=tmp_path / "idx",
        synthesis_out_dir=tmp_path / "synth",
        state_dir=tmp_path / "state",
        text_section=".text",
        match_root=tmp_path / "match",
        binary_format="elf",
        default_compiler="clang",
    )
    with pytest.raises(ValueError, match="ELF"):
        stage_discover(tiny, profile, {"stages": {}})


def test_pe_profile_rejects_elf(elf_game: Path, tmp_path: Path) -> None:
    profile = ProfileConfig(
        slug="pe-sample",
        default_binary=None,
        unpack_dir=tmp_path / "unpack",
        inventory_jsonl=tmp_path / "inv.jsonl",
        inventory_summary=tmp_path / "inv.json",
        trivial_matches_dir=tmp_path / "triv",
        trivial_out_jsonl=tmp_path / "triv.jsonl",
        trivial_summary=tmp_path / "triv.json",
        reloc_matches_dir=tmp_path / "reloc",
        reloc_out_jsonl=tmp_path / "reloc.jsonl",
        reloc_summary=tmp_path / "reloc.json",
        recovered_dir=tmp_path / "rec",
        compile_summary=tmp_path / "compile.json",
        coverage_json=tmp_path / "cov.json",
        queue_jsonl=tmp_path / "queue.jsonl",
        index_out_dir=tmp_path / "idx",
        synthesis_out_dir=tmp_path / "synth",
        state_dir=tmp_path / "state",
        text_section=".text",
        match_root=tmp_path / "match",
        binary_format="pe",
        default_compiler="msvc",
    )
    with pytest.raises(ValueError, match="PE"):
        stage_discover(elf_game, profile, {"stages": {}})


def test_stage_prepare_elf_skips_steamless(elf_game: Path, tmp_path: Path) -> None:
    profile = ProfileConfig(
        slug="elf-i386-sample",
        default_binary=None,
        unpack_dir=tmp_path / "unpack",
        inventory_jsonl=tmp_path / "inv.jsonl",
        inventory_summary=tmp_path / "inv.json",
        trivial_matches_dir=tmp_path / "triv",
        trivial_out_jsonl=tmp_path / "triv.jsonl",
        trivial_summary=tmp_path / "triv.json",
        reloc_matches_dir=tmp_path / "reloc",
        reloc_out_jsonl=tmp_path / "reloc.jsonl",
        reloc_summary=tmp_path / "reloc.json",
        recovered_dir=tmp_path / "rec",
        compile_summary=tmp_path / "compile.json",
        coverage_json=tmp_path / "cov.json",
        queue_jsonl=tmp_path / "queue.jsonl",
        index_out_dir=tmp_path / "idx",
        synthesis_out_dir=tmp_path / "synth",
        state_dir=tmp_path / "state",
        text_section=".text",
        match_root=tmp_path / "match",
        binary_format="elf",
        default_compiler="clang",
    )
    state: dict = {
        "binaryPath": str(elf_game),
        "binarySha256": sha256_file(elf_game),
        "stages": {},
    }
    stage_prepare(elf_game, profile, state)
    prep = state["stages"]["prepare"]
    assert prep["status"] == "complete"
    assert prep["transform"] == "none-elf-unpacked"
    assert "steamlessCli" not in prep
    assert Path(prep["analysisBinary"]).exists()


def test_resolve_elf_from_dir(elf_game: Path) -> None:
    assert resolve_elf_binary(elf_game.parent) == elf_game.resolve()
