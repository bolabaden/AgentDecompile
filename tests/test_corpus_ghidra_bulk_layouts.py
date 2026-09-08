"""Ghidra type-layout alignment for compile-complete leftovers."""

from __future__ import annotations

import pytest

from agentdecompile_recovery.corpus import asm_seed, ghidra_bulk as gb

pytestmark = pytest.mark.unit


def test_trailing_underscore_matches_exported_field() -> None:
    gb._TYPE_FIELDS = {"strref", "internal", "string_count", "field_8"}
    body = "if (this->strref_ != p->strref_) return this_00->string_count + this_00->field_8;"
    fixed = gb.fix_trailing_underscore_fields(body)
    assert "strref_" not in fixed
    assert "this->strref" in fixed
    assert "string_count" in fixed
    assert "field_8" in fixed
    gb._TYPE_FIELDS = set()


def test_trailing_underscore_leaves_unknown_suffix() -> None:
    gb._TYPE_FIELDS = {"strref"}
    body = "this->invented_ = 1;"
    assert gb.fix_trailing_underscore_fields(body) == body
    gb._TYPE_FIELDS = set()


def test_vtable_star_call_becomes_ghidra_call() -> None:
    src = "(*this->vtable->OnBlackButtonPressed)();"
    assert "ghidra_call()" in gb.fix_star_calls(src)
    assert "OnBlackButtonPressed" not in gb.fix_star_calls(src)


def test_emit_type_retargets_void_star_internal() -> None:
    types = {
        "CExoLocString": "typedef struct CExoLocString { void * internal; int strref; } CExoLocString;",
        "CExoLocStringInternal": (
            "typedef struct CExoLocStringInternal { int string_count; unsigned int field_8; } "
            "CExoLocStringInternal;"
        ),
    }
    emitted = gb._emit_type("CExoLocString", types)
    assert "struct CExoLocStringInternal * internal" in emitted
    wanted = gb._expand_wanted({"CExoLocString"}, types)
    assert "CExoLocStringInternal" in wanted
    assert gb._emit_order(wanted, types)[0] == "CExoLocStringInternal"


def test_should_skip_llm_only_huge_or_disallowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gb, "LLM_CLEANUP", True)
    monkeypatch.setattr(gb, "_LLM_STOPPED", False)
    monkeypatch.setattr(gb, "_CORPUS_TOTAL", 100)
    monkeypatch.setattr(gb, "_COMPILED_COUNT", 10)
    monkeypatch.setattr(gb, "COMPILE_COMPLETE", 0.95)
    assert gb.should_skip_llm(body="int f(void) { return 0; }\n") is False
    huge = "int f(void) {\n" + ("  x++;\n" * 8000) + "}\n"
    assert gb.should_skip_llm(body=huge) is True
    monkeypatch.setattr(gb, "_LLM_STOPPED", True)
    assert gb.should_skip_llm(body="int f(void) { return 0; }\n") is True


def test_queue_skips_tried_leftovers_not_seed_asm(tmp_path) -> None:
    blob = bytes.fromhex("90")
    seed = tmp_path / "Seed_00000001.c"
    seed.write_text(asm_seed.asm_banner("Seed_00000001", "00000001") + asm_seed.emit_naked_asm("Seed", blob))
    tried = tmp_path / "Tried_00000002.c"
    tried.write_text(
        asm_seed.asm_banner("Tried_00000002", "00000002")
        + " * source: ghidra_bulk.py asm-fallback\n"
        + asm_seed.emit_naked_asm("Tried", blob)
    )
    # Banner closer is before the alias line — stamp via helper for a real tried file.
    asm_seed.mark_c_replace_tried(tried)
    # Files already containing asm-fallback in the first 800 bytes count as tried.
    dirty = tmp_path / "Dirty_00000003.c"
    dirty.write_text(
        "/*\n * compile-only-asm\n * address: 0x00000003\n"
        " * source: ghidra_bulk.py asm-fallback\n */\n"
        + asm_seed.emit_naked_asm("Dirty", blob)
    )
    real = tmp_path / "Real_00000004.c"
    real.write_text("/* address: 0x00000004 */\nint Real(void) { return 0; }\n")

    assert gb.existing_kind(tmp_path, "Seed", "00000001") == "asm-seed"
    assert gb.existing_kind(tmp_path, "Tried", "00000002") == "asm-tried"
    assert gb.existing_kind(tmp_path, "Dirty", "00000003") == "asm-tried"
    assert gb.existing_kind(tmp_path, "Real", "00000004") == "real-c"
    assert gb.existing_kind(tmp_path, "Missing", "00000005") == "missing"

    assert gb.should_queue("asm-seed", "skip-existing")
    assert not gb.should_queue("asm-tried", "skip-existing")
    assert not gb.should_queue("real-c", "skip-existing")
    assert gb.should_queue("missing", "skip-existing")
    assert gb.should_queue("asm-tried", "force-c-replace")
    assert not gb.should_queue("real-c", "force-c-replace")
    assert gb.should_queue("real-c", "force")
    assert gb.resolve_queue_policy(skip_existing=True, force_c_replace=False) == "skip-existing"
    assert gb.resolve_queue_policy(skip_existing=True, force_c_replace=True) == "force-c-replace"
    assert gb.resolve_queue_policy(skip_existing=False, force_c_replace=True) == "force"


def test_mark_c_replace_tried_is_idempotent(tmp_path) -> None:
    dest = tmp_path / "Seed_00000001.c"
    dest.write_text(asm_seed.asm_banner("Seed_00000001", "00000001") + asm_seed.emit_naked_asm("Seed", b"\x90"))
    assert not asm_seed.is_c_replace_tried(dest)
    asm_seed.mark_c_replace_tried(dest)
    assert asm_seed.is_c_replace_tried(dest)
    first = dest.read_text()
    asm_seed.mark_c_replace_tried(dest)
    assert dest.read_text() == first


def test_asm_seed_is_default_substrate_not_real_c(tmp_path) -> None:
    blob = bytes.fromhex("e9ebfeffff")
    body = asm_seed.emit_naked_asm("Compare", blob)
    assert "__declspec(naked)" in body
    assert "_emit 0xE9" in body
    dest = tmp_path / "Compare_005ea020.c"
    dest.write_text(asm_seed.asm_banner("Compare_005ea020", "005ea020") + body)
    assert asm_seed.is_compile_only_asm(dest)
    real = tmp_path / "ok.c"
    real.write_text("/* compiled from Ghidra */\nint f(void) { return 0; }\n")
    assert not asm_seed.is_compile_only_asm(real)
    assert asm_seed.slice_image(b"\x00\x01\x02\x03", 1, 2) == b"\x01\x02"


def test_sibling_of_real_c_logical_id_is_skipped(tmp_path) -> None:
    from agentdecompile_recovery.corpus.ingest_recovered import ensure_recovered_schema
    from agentdecompile_recovery.corpus.store import connect

    con = connect(tmp_path / "store.sqlite")
    ensure_recovered_schema(con)
    con.execute("INSERT INTO binary(id, repo_path, slug) VALUES (1,'/a/win.exe','win')")
    con.execute(
        "INSERT INTO logical_function(id, canon_key, best_name) VALUES (9, 'C::F', 'C::F')"
    )
    con.execute(
        "INSERT INTO identity(logical_id, binary_id, addr, confidence, method) "
        "VALUES (9, 1, 4198400, 1.0, 'name')"
    )
    con.execute(
        "INSERT INTO recovered_function(program, name, real_c, logical_id, path) "
        "VALUES ('/a/win.exe', 'C::F', 1, 9, '/tmp/C_F.c')"
    )
    con.commit()
    assert 9 in gb.logical_ids_with_real_c(con)
    assert gb.addr_to_logical(con, 1).get(4198400) == 9
    assert gb.skip_real_c_sibling(9, {9}, "asm-seed")
    assert gb.skip_real_c_sibling(9, {9}, "missing")
    assert not gb.skip_real_c_sibling(9, {9}, "real-c")
    assert not gb.skip_real_c_sibling(8, {9}, "asm-seed")
    con.close()
