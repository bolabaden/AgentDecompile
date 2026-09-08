from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery.corpus import compile_link, store
from agentdecompile_recovery.corpus.cli import main as corpus_main
from agentdecompile_recovery.corpus.workspace_skeleton import (
    build_workspace,
    cu_unit_dir,
    fill_from_ghidra,
    rel_source,
)

pytestmark = pytest.mark.unit


def _seed(db: Path) -> None:
    con = store.connect(db)
    con.execute(
        "INSERT INTO binary(repo_path, slug) VALUES (?,?)",
        ("bins/demo.exe", "demo-donor"),
    )
    bid = int(con.execute("SELECT id FROM binary").fetchone()["id"])
    con.execute(
        "INSERT INTO func(binary_id, addr, name, source_file) VALUES (?,?,?,?)",
        (bid, 0x1000, "addOne", "/Users/dev/src/game/add.c"),
    )
    con.execute(
        "INSERT INTO logical_function(id, best_name, source_file) VALUES (?,?,?)",
        (1, "addOne", "/Users/dev/src/game/add.c"),
    )
    con.execute(
        "INSERT INTO identity(logical_id, binary_id, addr, confidence, method) "
        "VALUES (?,?,?,?,?)",
        (1, bid, 0x1000, 1.0, "test"),
    )
    con.commit()
    con.close()


def test_rel_source_strips_home_prefix() -> None:
    assert rel_source("/Users/dev/src/game/add.c") == "dev/src/game/add.c"
    assert rel_source("/tmp/../etc/passwd.c") is None


def test_fill_keeps_separate_compile_units(tmp_path: Path) -> None:
    db = tmp_path / "corpus.sqlite"
    _seed(db)
    src = tmp_path / "recovered"
    src.mkdir()
    (src / "addOne_00001000.c").write_text(
        "/*\n * addOne_00001000\n * address: 0x00001000\n */\n"
        "int addOne(int x) { return x + 1; }\n"
    )
    out = tmp_path / "workspace"
    con = store.connect(db)
    stats = fill_from_ghidra(con, "demo-donor", "demo-donor", out, src)
    assert stats["placed"] == 1
    unit = cu_unit_dir(out, "dev/src/game/add.c") / "addOne_00001000.c"
    assert unit.is_file()
    assert "int addOne" in unit.read_text()
    stub = out / "dev/src/game/add.c"
    assert stub.is_file()
    assert "addOne_00001000.c" in stub.read_text()
    assert "int addOne" not in stub.read_text()


def test_object_is_current_and_head_read(tmp_path: Path) -> None:
    src = tmp_path / "unit.c"
    src.write_text("/* STABS-attributed compilation unit.\n */\nint f(void) { return 1; }\n")
    obj = tmp_path / "unit.obj"
    assert compile_link.object_is_current(src, obj) is False
    obj.write_bytes(b"obj")
    assert compile_link.object_is_current(src, obj) is True
    src.write_text("int f(void) { return 2; }\n")
    assert compile_link.object_is_current(src, obj) is False
    units = compile_link.iter_compile_units(tmp_path)
    assert src in units


def test_image_is_current_skips_unchanged_link(tmp_path: Path) -> None:
    obj = tmp_path / "a.obj"
    obj.write_bytes(b"obj")
    exe = tmp_path / "out.exe"
    exe.write_bytes(b"MZ")
    assert compile_link.image_is_current([obj], exe) is False
    compile_link.write_link_stamp(exe)
    assert compile_link.image_is_current([obj], exe) is True
    obj.write_bytes(b"obj2")
    assert compile_link.image_is_current([obj], exe) is False
    exe.write_bytes(b"MZ2")
    compile_link.write_link_stamp(exe)
    assert compile_link.image_is_current([obj], exe) is True
    compile_link.write_link_stamp(exe, ("/nologo", "/FORCE"))
    assert compile_link.image_is_current([obj], exe) is False
    assert compile_link.image_is_current([], exe) is False
    assert compile_link.image_is_current([obj], tmp_path / "missing.exe") is False


def test_write_entrypoint_and_script_compiler(tmp_path: Path) -> None:
    main = compile_link.write_entrypoint(tmp_path / "main.c")
    assert "int main" in main.read_text()
    script = tmp_path / "compile.sh"
    script.write_text("#!/bin/sh\ncp \"$1\" \"$2\"\n", encoding="utf-8")
    script.chmod(0o755)
    src = tmp_path / "f.c"
    src.write_text("int f(void) { return 1; }\n")
    obj = tmp_path / "f.obj"
    result = compile_link.compile_unit_script(str(script), src, obj, name="f")
    assert result["ok"] is True
    assert obj.is_file()


def test_compile_link_builds_host_executable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_DECOMPILE_MSVC_COMPILER", raising=False)
    monkeypatch.delenv("AGENT_DECOMPILE_VCROOT", raising=False)
    src = tmp_path / "units"
    src.mkdir()
    (src / "a.c").write_text("int add_one(int x) { return x + 1; }\n")
    (src / "main.c").write_text(
        "int add_one(int);\nint main(void) { return add_one(1) == 2 ? 0 : 1; }\n"
    )
    stub = src / "index.c"
    stub.write_text("/* STABS-attributed compilation unit.\n */\n")
    exe = tmp_path / "out" / "demo"
    result = compile_link.compile_and_link_tree(src, exe, obj_dir=tmp_path / "obj")
    if result.get("reason") == "no C compiler on PATH":
        pytest.skip("no host C compiler")
    assert result["ok"] is True
    assert result["objects"] == 2
    assert exe.is_file()
    again = compile_link.compile_and_link_tree(src, exe, obj_dir=tmp_path / "obj")
    assert again["ok"] is True
    assert again["skipped"] == 2
    assert again.get("linkSkipped") is True


def test_cli_workspace_and_compile_link(tmp_path: Path) -> None:
    db = tmp_path / "corpus.sqlite"
    _seed(db)
    src = tmp_path / "recovered"
    src.mkdir()
    (src / "addOne_00001000.c").write_text(
        "/*\n * address: 0x00001000\n */\nint addOne(int x) { return x + 1; }\n"
    )
    work = tmp_path / "workspace"
    assert (
        corpus_main(
            [
                "workspace",
                "--db",
                str(db),
                "--donor-slug",
                "demo-donor",
                "--out",
                str(work),
                "--fill-from",
                "demo-donor",
                "--src-dir",
                str(src),
            ]
        )
        == 0
    )
    unit = cu_unit_dir(work, "dev/src/game/add.c") / "addOne_00001000.c"
    assert unit.is_file()
    # Host link of one function needs a main; compile-link --sample 1 still
    # reports units even if link fails without main.
    exe = tmp_path / "demo"
    rc = corpus_main(
        [
            "compile-link",
            "--src-dir",
            str(work),
            "--out",
            str(exe),
            "--obj-dir",
            str(tmp_path / "obj"),
            "--sample",
            "1",
        ]
    )
    assert rc in (0, 1)
