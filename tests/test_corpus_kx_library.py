from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentdecompile_recovery.corpus import (
    corpus_config,
    export_c,
    fix_func_counts,
    ghidra_env,
    ghidra_verify,
    merge,
    realc,
    stabs_report,
    stabs_types,
    store,
)

pytestmark = pytest.mark.unit


def _part_db(path: Path, *, slug: str, repo_path: str, addr: int, name: str) -> Path:
    con = store.connect(path)
    con.execute(
        "INSERT INTO binary(repo_path, slug, game, platform, arch, bits, func_count, role) VALUES (?,?,?,?,?,?,?,?)",
        (repo_path, slug, "demo", "linux", "x86", 32, 1, "donor"),
    )
    bid = con.execute("SELECT id FROM binary WHERE slug=?", (slug,)).fetchone()["id"]
    con.execute(
        "INSERT INTO func(binary_id, addr, name, size, n_instr, canon_key) VALUES (?,?,?,?,?,?)",
        (bid, addr, name, 16, 4, name),
    )
    con.execute("INSERT INTO calledge(binary_id, caller_addr, callee_addr) VALUES (?,?,?)", (bid, addr, addr + 8))
    con.commit()
    con.close()
    return path


def test_remove_binary_drops_per_binary_rows_not_logicals(tmp_path: Path) -> None:
    db = tmp_path / "corpus.sqlite"
    con = store.connect(db)
    con.execute(
        "INSERT INTO binary(repo_path, slug) VALUES (?,?)",
        ("/K1/demo.exe.keep", "demo.exe.keep"),
    )
    con.execute("INSERT INTO binary(repo_path, slug) VALUES (?,?)", ("/K1/demo.exe", "demo.exe"))
    keep = int(con.execute("SELECT id FROM binary WHERE slug=?", ("demo.exe.keep",)).fetchone()["id"])
    live = int(con.execute("SELECT id FROM binary WHERE slug=?", ("demo.exe",)).fetchone()["id"])
    con.execute("INSERT INTO logical_function(id, best_name) VALUES (1,'add')")
    con.execute(
        "INSERT INTO func(binary_id, addr, name) VALUES (?,?,?),(?,?,?)",
        (keep, 0x1000, "add", live, 0x1000, "add"),
    )
    con.execute(
        "INSERT INTO identity(logical_id, binary_id, addr) VALUES (1,?,0x1000),(1,?,0x1000)",
        (keep, live),
    )
    con.execute("INSERT INTO calledge(binary_id, caller_addr, callee_addr) VALUES (?,?,?)", (keep, 0x1000, 0x2000))
    con.commit()
    stats = store.remove_binary(con, repo_path="/K1/demo.exe.keep")
    assert stats["deleted"]["binary"] == 1
    assert stats["deleted"]["func"] == 1
    assert stats["deleted"]["identity"] == 1
    assert con.execute("SELECT COUNT(*) FROM binary").fetchone()[0] == 1
    assert con.execute("SELECT slug FROM binary").fetchone()[0] == "demo.exe"
    assert con.execute("SELECT COUNT(*) FROM identity").fetchone()[0] == 1
    assert con.execute("SELECT COUNT(*) FROM logical_function").fetchone()[0] == 1


def test_merge_two_part_dbs_into_required_dest(tmp_path: Path) -> None:
    a = _part_db(tmp_path / "parts" / "a.sqlite", slug="one", repo_path="bins/one", addr=0x1000, name="add")
    b = _part_db(tmp_path / "parts" / "b.sqlite", slug="two", repo_path="bins/two", addr=0x2000, name="sub")
    dest = tmp_path / "merged.sqlite"
    result = merge.merge_parts([a, b], dest)
    assert dest.is_file()
    assert {row["repo_path"] for row in result["binaries"]} == {"bins/one", "bins/two"}
    con = store.connect(dest)
    assert con.execute("SELECT COUNT(*) FROM binary").fetchone()[0] == 2
    assert con.execute("SELECT COUNT(*) FROM func").fetchone()[0] == 2
    assert con.execute("SELECT COUNT(*) FROM calledge").fetchone()[0] == 2
    slugs = {r["slug"] for r in con.execute("SELECT slug FROM binary")}
    assert slugs == {"one", "two"}


def test_corpus_config_loads_from_temp_json_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CORPUS_CONFIG", raising=False)
    monkeypatch.delenv("CORPUS_PROGRAM", raising=False)
    programs = tmp_path / "programs"
    programs.mkdir()
    (programs / "demo.json").write_text(
        json.dumps({"repo_path": "bins/demo", "donor": "anchor", "ctx_h": "include/ctx.h"}),
        encoding="utf-8",
    )
    (tmp_path / "maps.json").write_text(json.dumps({"leaf_to_repo": {"demo": "bins/demo"}}), encoding="utf-8")
    monkeypatch.setenv("AGENT_DECOMPILE_CORPUS_CONFIG_DIR", str(tmp_path))

    assert corpus_config.ROOT is None
    cfg = corpus_config.load_program_config("demo")
    assert cfg.repo_path == "bins/demo"
    assert cfg.donor == "anchor"
    assert cfg.ctx_h == "include/ctx.h"
    assert "mizuchi" not in cfg.ctx_h.lower()
    assert corpus_config.leaf_to_repo("demo") == "bins/demo"
    empty = corpus_config.load_program_config("missing")
    assert empty.ctx_h == ""
    assert "mizuchi" not in json.dumps(empty.__dict__).lower()


def test_corpus_config_empty_defaults_without_dir(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_DECOMPILE_CORPUS_CONFIG_DIR", raising=False)
    monkeypatch.delenv("CORPUS_CONFIG", raising=False)
    cfg = corpus_config.load_program_config("anything")
    assert cfg.repo_path == ""
    assert cfg.ctx_h == ""
    assert corpus_config.load_maps() == {}
    assert corpus_config.load_match_pairs() == []


def test_realc_export_c_stabs_types_fix_func_counts(tmp_path: Path) -> None:
    assert realc.is_real_c("int add(int x) { return x + 1; }\n")
    assert not realc.is_real_c("void copied(void) { __asm { nop } }\n")
    assert not realc.is_real_c("__declspec(naked) void f(void) {}")
    assert not realc.is_real_c("ASM_NAKED void f(void) {}\n")
    assert not realc.is_real_c("KOTOR_NAKED void f(void) {}\n")
    assert realc.shim_reason("void f(void) { _emit 0x90; }")
    assert realc.is_real_c('extern float *g_fFPS_ptr __asm__("PTR_g_fFPS");\nint f(void) { return 1; }\n')

    dest_c = export_c.export_dest(tmp_path / "cexport", "bins/demo")
    dest_c.parent.mkdir(parents=True)
    dest_c.write_text("/* already exported */\n" + ("int x;\n" * 200), encoding="utf-8")
    skipped = export_c.run("bins/demo", tmp_path / "cexport")
    assert skipped["skipped"] == "already exported"
    assert skipped["size"] > 1024

    fresh = export_c.run("bins/other", tmp_path / "cexport", start=lambda: False)
    assert fresh["skipped"] == "no-program"

    db = tmp_path / "store.sqlite"
    con = store.connect(db)
    con.execute(
        "INSERT INTO binary(repo_path, slug, func_count, role) VALUES (?,?,?,?)",
        ("bins/demo", "demo", 3, "anchor"),
    )
    bid = con.execute("SELECT id FROM binary").fetchone()["id"]
    con.executemany(
        "INSERT INTO func(binary_id, addr, name, size, n_instr) VALUES (?,?,?,?,?)",
        [
            (bid, 0x10, "InitToolbox", 32, 8),
            (bid, 0x20, "FUN_00000020", 1, 0),
            (bid, 0x30, "CreateMenuBar", 1, 0),
        ],
    )
    con.commit()
    persisted = stabs_types.persist_types(
        con,
        bid,
        types=[{"name": "CThing", "kind": "struct", "stab": "CThing:t(0,1)", "source_file": "a.cpp"}],
    )
    assert persisted["parsed"] == 1
    assert con.execute("SELECT COUNT(*) FROM stabs_type").fetchone()[0] == 1

    report = tmp_path / "reports" / "func_count_audit.json"
    audited = fix_func_counts.audit(con, apply_counts=True, report_path=report)
    assert audited["applied"] is True
    row = audited["binaries"][0]
    assert row["code_func_count"] == 1
    assert row["stub_count"] == 2
    assert row["named_stub_count"] == 1
    assert json.loads(report.read_text(encoding="utf-8"))["totals"]["code_func_count"] == 1
    assert con.execute("SELECT code_func_count FROM binary").fetchone()[0] == 1


def test_stabs_report_writes_into_caller_out_dir(tmp_path: Path) -> None:
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"not-a-macho")
    out_dir = tmp_path / "stabs-out"
    result = stabs_report.write_report(binary, out_dir, repo_path="bins/sample")
    assert Path(result["json"]).is_file()
    assert Path(result["json"]).parent == out_dir
    assert Path(result["markdown"]).is_file()
    assert (out_dir / "_index.json").is_file()
    assert "STABS analysis" in Path(result["markdown"]).read_text(encoding="utf-8")
    assert result["index"]["sample.bin"]["repo_path"] == "bins/sample"


def test_ghidra_env_and_verify_argument_plumbing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    monkeypatch.setattr(ghidra_env, "pyghidra_available", lambda: False)
    ghidra_env._STARTED = False  # noqa: SLF001
    assert ghidra_env.resolve_workspace(tmp_path) == tmp_path
    monkeypatch.setenv("AGENT_DECOMPILE_PROJECT_PATH", str(tmp_path / "proj"))
    assert ghidra_env.resolve_workspace() == tmp_path / "proj"
    assert ghidra_env.start(project_path=tmp_path) is False
    with ghidra_env.open_program(None) as program:
        assert program is None
    with ghidra_env.open_program("") as program:
        assert program is None

    skipped = ghidra_verify.verify(program=None)
    assert skipped["skipped"] == "no-program"
    skipped_paths = ghidra_verify.verify(src_dir=tmp_path / "missing", raw_path=None)
    assert skipped_paths["skipped"] == "no-program"
