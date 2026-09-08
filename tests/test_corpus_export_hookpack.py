from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery.corpus.export_hookpack import (
    FORMAT,
    export_hookpack,
    unique_window,
)
from agentdecompile_recovery.corpus.store import connect

pytestmark = pytest.mark.unit


def test_empty_store_writes_empty_sites(tmp_path: Path) -> None:
    db = tmp_path / "c.sqlite"
    out = tmp_path / "pack.json"
    summary = export_hookpack(connect(db), out)
    assert summary["sites"] == 0
    pack = __import__("json").loads(out.read_text(encoding="utf-8"))
    assert pack["format"] == FORMAT
    assert pack["sites"] == {}


def test_one_logical_two_binaries_majority_signature(tmp_path: Path) -> None:
    con = connect(tmp_path / "c.sqlite")
    con.execute("INSERT INTO binary(id, repo_path, slug) VALUES (1, '/a', 'debug'), (2, '/b', 'release')")
    con.execute(
        "INSERT INTO logical_function(id, best_name, best_signature, n_members) VALUES (9, 'RunScript', 'void RunScript()', 2)"
    )
    con.execute("INSERT INTO identity(logical_id, binary_id, addr, confidence, method) VALUES (9, 1, 100, 1.0, 'stabs'), (9, 2, 200, 0.8, 'engine')")
    con.execute(
        "INSERT INTO func(binary_id, addr, name, signature) VALUES (1, 100, 'RunScript', 'void RunScript()'), (2, 200, 'FUN_200', 'void RunScript()')"
    )
    con.commit()
    out = tmp_path / "pack.json"
    export_hookpack(con, out)
    pack = __import__("json").loads(out.read_text(encoding="utf-8"))
    site = pack["sites"]["RunScript"]
    assert site["logical_id"] == 9
    assert site["signature"]["kind"] == "shared"
    assert {i["binary"] for i in site["instances"]} == {"debug", "release"}
    assert {i["addr"] for i in site["instances"]} == {100, 200}


def test_missing_signature_is_kind_none(tmp_path: Path) -> None:
    con = connect(tmp_path / "c.sqlite")
    con.execute("INSERT INTO binary(id, repo_path, slug) VALUES (1, '/a', 'debug')")
    con.execute(
        "INSERT INTO logical_function(id, best_name, best_signature, n_members) VALUES (3, 'Anon', NULL, 1)"
    )
    con.execute("INSERT INTO identity(logical_id, binary_id, addr, confidence, method) VALUES (3, 1, 50, 1.0, 'engine')")
    con.execute("INSERT INTO func(binary_id, addr, name, signature) VALUES (1, 50, 'FUN_50', NULL)")
    con.commit()
    out = tmp_path / "pack.json"
    export_hookpack(con, out)
    pack = __import__("json").loads(out.read_text(encoding="utf-8"))
    assert pack["sites"]["Anon"]["signature"]["kind"] == "none"


def test_shared_members_win_over_stale_best(tmp_path: Path) -> None:
    con = connect(tmp_path / "c.sqlite")
    con.execute("INSERT INTO binary(id, repo_path, slug) VALUES (1, '/a', 'debug'), (2, '/b', 'release')")
    con.execute(
        "INSERT INTO logical_function(id, best_name, best_signature, n_members) "
        "VALUES (4, 'Split', 'void Old()', 2)"
    )
    con.execute(
        "INSERT INTO identity(logical_id, binary_id, addr, confidence, method) "
        "VALUES (4, 1, 10, 1.0, 'stabs'), (4, 2, 20, 0.8, 'engine')"
    )
    con.execute(
        "INSERT INTO func(binary_id, addr, name, signature) "
        "VALUES (1, 10, 'Split', 'void Split()'), (2, 20, 'FUN_20', 'void Split()')"
    )
    con.commit()
    out = tmp_path / "pack.json"
    export_hookpack(con, out)
    pack = __import__("json").loads(out.read_text(encoding="utf-8"))
    sig = pack["sites"]["Split"]["signature"]
    assert sig["kind"] == "shared"
    assert sig["value"] == "void Split()"


def test_unique_window_omits_non_unique() -> None:
    hay = b"\x90" * 64 + bytes.fromhex("535556578B7C2414") + b"\x90" * 64
    assert unique_window(hay, 64, 32) == bytes.fromhex("535556578B7C2414")
    pat = bytes.fromhex("535556578B7C2414") + b"\x90" * 24
    assert unique_window(pat + pat, 0, 32) is None


def test_export_copies_unique_bytes_from_image(tmp_path: Path, monkeypatch) -> None:
    from agentdecompile_recovery.corpus import export_hookpack as hp

    hay = b"\x90" * 64 + bytes.fromhex("535556578B7C2414") + b"\x90" * 64
    monkeypatch.setattr(hp, "_raw_image", lambda repo: hay)
    monkeypatch.setattr(hp, "_file_offset", lambda image, addr: 64)
    con = connect(tmp_path / "c.sqlite")
    con.execute("INSERT INTO binary(id, repo_path, slug) VALUES (1, '/a', 'debug')")
    con.execute(
        "INSERT INTO logical_function(id, best_name, best_signature, n_members) VALUES (3, 'Run', 'void Run()', 1)"
    )
    con.execute("INSERT INTO identity(logical_id, binary_id, addr, confidence, method) VALUES (3, 1, 256, 1.0, 'stabs')")
    con.execute(
        "INSERT INTO func(binary_id, addr, name, signature, size) VALUES (1, 256, 'Run', 'void Run()', 16)"
    )
    con.commit()
    out = tmp_path / "pack.json"
    hp.export_hookpack(con, out)
    pack = __import__("json").loads(out.read_text(encoding="utf-8"))
    site = pack["sites"]["Run"]
    assert site["expected_bytes"] == "535556578B7C2414"
    assert site["instances"][0]["expected_bytes"] == "535556578B7C2414"
