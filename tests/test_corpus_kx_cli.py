from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentdecompile_recovery.corpus import kx_cli, stabs_manifest, store
from agentdecompile_recovery.corpus.cli import build_parser, main as corpus_main

pytestmark = pytest.mark.unit


def test_kx_commands_registered_on_corpus_parser() -> None:
    subs = build_parser()._subparsers._group_actions[0].choices  # type: ignore[attr-defined]
    missing = sorted(kx_cli.KX_COMMANDS - set(subs))
    assert missing == [], f"missing subcommands: {missing}"


def test_stabs_manifest_generate_offline(tmp_path: Path) -> None:
    db = tmp_path / "store.sqlite"
    raw_dir = tmp_path / "raw"
    out_dir = tmp_path / "manifests"
    raw_dir.mkdir()
    binary = raw_dir / "demo"
    binary.write_bytes(b"not-a-macho")
    con = store.connect(db)
    con.execute(
        "INSERT INTO binary(repo_path, slug, arch) VALUES (?,?,?)",
        ("bins/demo", "demo", "i386"),
    )
    bid = con.execute("SELECT id FROM binary").fetchone()[0]
    con.execute(
        "INSERT INTO func(binary_id, addr, name, n_instr) VALUES (?,?,?,?)",
        (bid, 0x1000, "add", 4),
    )
    con.commit()
    manifest, summary_path, summary = stabs_manifest.generate(
        con,
        "bins/demo",
        raw_dir=raw_dir,
        out_dir=out_dir,
    )
    assert manifest.is_file()
    assert summary_path.is_file()
    assert summary["func_address_hits"] >= 0


def test_bind_identities_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = tmp_path / "store.sqlite"
    con = store.connect(db)
    con.executescript(
        """
        INSERT INTO binary(id, repo_path, slug) VALUES (1,'src/a','a'),(2,'dst/b','b');
        INSERT INTO logical_function(id, best_name) VALUES (1,'fn');
        INSERT INTO identity(logical_id, binary_id, addr, confidence, method) VALUES (1,1,0x10,0.9,'seed');
        INSERT INTO func(binary_id, addr, name) VALUES (1,0x10,'fn'),(2,0x20,'FUN_20');
        INSERT INTO match(run, src_binary, src_addr, dst_binary, dst_addr, score, margin, evidence, status)
        VALUES ('v1',1,0x10,2,0x20,0.95,0.4,'{}','auto');
        """
    )
    con.commit()
    con.close()
    assert corpus_main(["bind-identities", "--db", str(db), "--run", "v1"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["bound"] == 1
