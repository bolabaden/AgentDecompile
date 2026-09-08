from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from agentdecompile_recovery.corpus import (
    compile_tally,
    exact_asm,
    extract,
    ghidra_url,
    mkobj,
    store,
    verify_built,
)
from agentdecompile_recovery.corpus.cli import main as corpus_main
from agentdecompile_recovery.corpus.extract import resolve_source

pytestmark = pytest.mark.unit


def _seed_binary(path: Path, *, repo_path: str = "bins/demo", slug: str = "bins__demo") -> None:
    con = store.connect(path)
    con.execute(
        "INSERT INTO binary(repo_path, slug, game, platform, arch, bits, func_count, role) VALUES (?,?,?,?,?,?,?,?)",
        (repo_path, slug, "demo", "linux", "x86", 32, 1, "donor"),
    )
    bid = con.execute("SELECT id FROM binary WHERE slug=?", (slug,)).fetchone()["id"]
    con.execute(
        "INSERT INTO func(binary_id, addr, name, size, n_instr, is_thunk, canon_key) VALUES (?,?,?,?,?,?,?)",
        (bid, 0x1000, "addOne", 16, 4, 0, "addOne"),
    )
    con.commit()
    con.close()


def test_ghidra_url_encodes_spaces_and_uses_configured_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_DECOMPILE_CORPUS_CONFIG_DIR", raising=False)
    monkeypatch.setenv("GHIDRA_SERVER_HOST", "ghidra.test")
    monkeypatch.setenv("GHIDRA_SERVER_PORT", "15500")
    monkeypatch.setenv("GHIDRA_SERVER_REPOSITORY", "Corpus")
    url = ghidra_url.ghidra_url("/Other Engines/Aurora/nwmain.exe")
    assert url.startswith("ghidra://ghidra.test:15500/Corpus/")
    assert "Other%20Engines" in url
    assert "Aurora" in url
    assert "nwmain.exe" in url
    assert " " not in url


def test_resolve_source_returns_repo_path_when_maps_have_no_local_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "maps.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("AGENT_DECOMPILE_CORPUS_CONFIG_DIR", str(tmp_path))
    assert resolve_source("/bins/demo") == "/bins/demo"
    monkeypatch.delenv("AGENT_DECOMPILE_CORPUS_CONFIG_DIR", raising=False)
    assert extract.resolve_source("/bins/demo") == "/bins/demo"


def test_compile_tally_sample_and_empty_cfuncs(tmp_path: Path) -> None:
    db = tmp_path / "corpus.sqlite"
    _seed_binary(db)
    con = store.connect(db)
    rows = compile_tally.sample_random(con, "bins/demo", 10)
    assert len(rows) == 1
    assert rows[0]["name"] == "addOne"
    dest = tmp_path / "tally.json"
    result = compile_tally.tally(db, "bins/demo", dest, n=10, cfuncs={})
    assert dest.is_file()
    assert result["sampled"] == 1
    assert result["with_ghidra_c"] == 0
    assert json.loads(dest.read_text(encoding="utf-8")) == []


def test_exact_asm_emit_offline(tmp_path: Path) -> None:
    src, tier = exact_asm.generate("FooBar", bytes.fromhex("c3"), verify=False)
    assert "FooBar" in src
    assert "_emit 0xc3" in src
    assert tier.startswith("B")
    dest = tmp_path / "foo.c"
    wrote = exact_asm.write_source(dest, "FooBar", b"\xc3", verify=False)
    assert Path(wrote["out"]).is_file()
    assert "_emit 0xc3" in dest.read_text(encoding="utf-8")


def test_mkobj_write_object_offline(tmp_path: Path) -> None:
    raw = tmp_path / "raw.bin"
    raw.write_bytes(b"\x90" * 16 + b"\xc3")
    out = tmp_path / "t.o"
    dest = mkobj.write_object(binary=raw, offset=16, size=1, name="F_00401000", output=out)
    assert dest.is_file()
    data = dest.read_bytes()
    assert data[:2] == struct.pack("<H", mkobj.MACHINE["coff-i386"])
    assert b".text" in data
    built = mkobj.build_object(b"\xc3", "_ret", mkobj.MACHINE["coff-i386"])
    assert built[:2] == struct.pack("<H", 0x014C)
    assert b"_ret" in built


def test_verify_built_empty_manifest_and_funcbytes_truth(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "build_manifest.json").write_text("[]", encoding="utf-8")
    db = tmp_path / "corpus.sqlite"
    _seed_binary(db)
    result = verify_built.verify(proj, db)
    assert result["verified"] == 0
    assert result["total"] == 0

    fb = tmp_path / "funcbytes"
    fb.mkdir()
    (fb / "bins__demo.jsonl").write_text(json.dumps({"a": 0x1000, "b": "90c3"}) + "\n", encoding="utf-8")
    con = store.connect(db)
    truth = verify_built.truth_for("bins/demo", con, funcbytes_dir=fb)
    assert truth[0x1000] == b"\x90\xc3"


def test_cli_help_lists_new_operator_commands(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        corpus_main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for name in (
        "merge-parts",
        "stabs-report",
        "genproject",
        "ingest-recovered",
        "export-run-report",
        "ghidra-url",
        "apply-annotations",
        "work-queue",
        "report",
        "stabs-manifest",
        "fix-func-counts",
        "propagate-corpus",
        "external-bridge",
        "export-atlas-db",
        "collect-source",
        "coverage-report",
        "mkobj",
        "compile-unit",
    ):
        assert name in out


def test_cli_work_queue_and_report_offline(tmp_path: Path) -> None:
    db = tmp_path / "corpus.sqlite"
    _seed_binary(db)
    con = store.connect(db)
    con.execute("INSERT INTO logical_function(id, canon_key, n_members) VALUES (1,'add',1)")
    con.execute(
        "INSERT INTO identity(logical_id, binary_id, addr, confidence, method) VALUES (1,?,?,0.9,'test')",
        (con.execute("SELECT id FROM binary").fetchone()[0], 0x1000),
    )
    con.commit()
    con.close()

    out_dir = tmp_path / "queue"
    assert corpus_main(["work-queue", "--db", str(db), "--out-dir", str(out_dir)]) == 0
    assert (out_dir / "logical_queue.jsonl").is_file()

    report_dir = tmp_path / "reports"
    assert corpus_main(["report", "--db", str(db), "--out-dir", str(report_dir)]) == 0
    assert (report_dir / "_gen_corpus.md").is_file()


def test_cli_fix_func_counts(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = tmp_path / "corpus.sqlite"
    _seed_binary(db)
    report = tmp_path / "audit.json"
    assert corpus_main(["fix-func-counts", "--db", str(db), "--out", str(report), "--apply"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["applied"] is True
    assert report.is_file()


def test_cli_ghidra_url_and_apply_annotations_dry_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("AGENT_DECOMPILE_CORPUS_CONFIG_DIR", raising=False)
    monkeypatch.setenv("GHIDRA_SERVER_HOST", "ghidra.test")
    monkeypatch.setenv("GHIDRA_SERVER_PORT", "15500")
    monkeypatch.setenv("GHIDRA_SERVER_REPOSITORY", "Corpus")
    assert corpus_main(["ghidra-url", "/Other Engines/demo.exe"]) == 0
    printed = capsys.readouterr().out.strip()
    assert printed.startswith("ghidra://ghidra.test:15500/Corpus/")
    assert "Other%20Engines" in printed

    jsonl = tmp_path / "names.jsonl"
    jsonl.write_text(
        json.dumps(
            {
                "address": "00401000",
                "canonical": "addOne",
                "name": "addOne",
                "confidence": 0.99,
                "status": "auto",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    assert corpus_main(["apply-annotations", str(jsonl), "--program", "/folder/demo"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["dry_run"] is True
    assert payload["program"] == "/folder/demo"
    assert payload["candidates"] == 1
