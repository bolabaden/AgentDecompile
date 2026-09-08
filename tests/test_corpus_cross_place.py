from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery.corpus import asm_seed, cross_place

pytestmark = pytest.mark.unit


def test_rewrite_banner_uses_destination_address() -> None:
    src = "/*\n * Foo\n * address: 0x005ea020\n */\nint f(void) { return 1; }\n"
    out = cross_place.rewrite_for_dest(src, "00600000", "k1_mac_swkotor.app", "005ea020")
    assert "address: 0x00600000" in out
    assert "from 0x005ea020" in out
    assert "int f(void) { return 1; }" in out


def test_place_one_writes_sibling_and_skips_real_c(tmp_path: Path) -> None:
    src = tmp_path / "src.c"
    src.write_text("/*\n * address: 0x005ea020\n */\nint f(void) { return 1; }\n")
    dest_dir = tmp_path / "k1_mac_swkotor.app"
    dest_dir.mkdir()
    existing = dest_dir / "Foo_00600000.c"
    existing.write_text("/* already real C */\nint g(void) { return 2; }\n")
    index = {0x005EA020: [(2, 0x00600000, "k1_mac_swkotor.app", "Foo")]}
    assert cross_place.place_one(src, 0x005EA020, index, tmp_path) == 0
    assert "already real C" in existing.read_text()
    existing.unlink()
    assert cross_place.place_one(src, 0x005EA020, index, tmp_path) == 1
    out = existing.read_text()
    assert "address: 0x00600000" in out
    assert "int f(void) { return 1; }" in out


def test_should_write_does_not_clobber_real_c(tmp_path: Path) -> None:
    dest = tmp_path / "x.c"
    dest.write_text("/* compiled from Ghidra */\nint f(void) { return 0; }\n")
    assert not cross_place.should_write(dest, src_is_asm=True)
    assert not cross_place.should_write(dest, src_is_asm=False)
    asm = tmp_path / "a.c"
    asm.write_text(asm_seed.asm_banner("a", "1") + asm_seed.emit_naked_asm("a", b"\x90"))
    assert cross_place.should_write(asm, src_is_asm=False)
    assert not cross_place.should_write(asm, src_is_asm=True)


def test_resolve_source_dir_uses_dump_source_verified(tmp_path: Path) -> None:
    verified = tmp_path / "dump-source" / "verified"
    verified.mkdir(parents=True)
    (verified / "FUN_00401000.c").write_text("/* address: 0x00401000 */\nint f(void) { return 1; }\n")
    assert cross_place.resolve_source_dir(tmp_path, "k1_win_gog_swkotor.exe") == verified


def test_resolve_source_dir_uses_dump_source_verified(tmp_path: Path) -> None:
    verified = tmp_path / "dump-source" / "verified"
    verified.mkdir(parents=True)
    (verified / "FUN_00401000.c").write_text("/* address: 0x00401000 */\nint f(void) { return 1; }\n")
    assert cross_place.resolve_source_dir(tmp_path, "k1_win_gog_swkotor.exe") == verified
