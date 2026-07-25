"""Tests for batch-decompile facts projection, fresh dump, and dump layers."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from agentdecompile_recovery.batch_decompile_facts import (
    entry_and_name_from_decomp_path,
    project_decompiled_files_to_facts,
)
from agentdecompile_recovery.frontdoor import run_dump_source
from agentdecompile_recovery.source_dump import dump_source_tree, parse_dump_layers
from agentdecompile_recovery.stage_timings import empty_timings, record_stage, write_stage_timings


def test_entry_and_name_from_decomp_path() -> None:
    entry, name = entry_and_name_from_decomp_path(Path("FUN_00401000.c"))
    assert entry == "00401000"
    assert name == "FUN_00401000"
    entry, name = entry_and_name_from_decomp_path(Path("main-0x00402000.c"))
    assert entry == "00402000"


def test_project_decompiled_files_to_facts(tmp_path: Path) -> None:
    decomp = tmp_path / "FUN_00401000.c"
    decomp.write_text("int FUN_00401000(void) { return 1; }\n", encoding="utf-8")
    out = tmp_path / "facts.jsonl"
    receipt = project_decompiled_files_to_facts(
        [decomp], out_jsonl=out, target_sha="deadbeef"
    )
    assert receipt["written"] == 1
    row = json.loads(out.read_text(encoding="utf-8").splitlines()[0])
    assert row["entry"] == "00401000"
    assert "return 1" in row["decompiled"]
    assert row["targetSha256"] == "deadbeef"
    assert row["analysisBinarySha256"] == "deadbeef"


def test_parse_dump_layers_defaults() -> None:
    assert parse_dump_layers(None) == {"verified", "port", "advisory"}
    assert parse_dump_layers("verified,port") == {"verified", "port"}


def test_dump_layers_port_only_omits_advisory(tmp_path: Path) -> None:
    summary = tmp_path / "summary.jsonl"
    source = tmp_path / "clean.c"
    source.write_text("int Clean(void) { return 1; }\n", encoding="utf-8")
    summary.write_text(
        json.dumps(
            {
                "name": "Clean",
                "entry": "00401000",
                "status": "matched",
                "differences": 0,
                "source": str(source),
                "sourceQuality": "high-level-c",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    facts = tmp_path / "facts.jsonl"
    facts.write_text(
        json.dumps(
            {
                "name": "FUN_00402000",
                "entry": "00402000",
                "decompiled": "void FUN_00402000(void) {}\n",
                "decompilationStatus": "complete",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    out = tmp_path / "dump"
    manifest = dump_source_tree(
        out_dir=out,
        summaries=[summary],
        ghidra_facts=facts,
        layers="verified,port",
    )
    assert (out / "verified").exists()
    assert (out / "Port" / "CODE").exists()
    assert not list((out / "advisory" / "ghidra").glob("*.c"))
    assert manifest["ghidraCount"] == 0
    assert "advisory" not in manifest["layers"]


def test_fresh_dump_ignores_undeclared_sibling(tmp_path: Path, monkeypatch) -> None:
    work = tmp_path / "work"
    work.mkdir()
    sibling_root = tmp_path / "sample-trivial-matches"
    sibling_root.mkdir()
    (sibling_root / "summary.jsonl").write_text(
        json.dumps(
            {
                "name": "Leftover",
                "entry": "00401000",
                "status": "matched",
                "differences": 0,
                "sourceText": "int Leftover(void){return 0;}\n",
                "sourceQuality": "high-level-c",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    # Make work look like reconstruct layout so sibling would be discovered in leftover mode.
    reconstruct = tmp_path / "agentdecompile-reconstruct" / "run1"
    reconstruct.mkdir(parents=True)
    out = tmp_path / "dump"
    args = SimpleNamespace(
        dump_source=out,
        dump_source_only=False,
        dump_allow_leftovers=False,
        dump_layers="verified,port",
        ghidra_facts=None,
        input=Path("binary.exe"),
        json=True,
    )
    # Point parent chain: reconstruct/run1 -> agentdecompile-reconstruct -> tmp_path
    # Sibling at tmp_path/sample-trivial-matches is what leftover mode would load.
    monkeypatch.chdir(tmp_path)
    rc = run_dump_source(args, reconstruct)
    assert rc == 0
    receipt = json.loads((reconstruct / "dump-source.json").read_text(encoding="utf-8"))
    assert receipt["freshMode"] is True
    assert receipt["summaries"] == []
    assert not list((out / "verified").glob("*.c"))


def test_stage_timings_schema(tmp_path: Path) -> None:
    timings = empty_timings(tmp_path)
    record_stage(timings, "inventory", started=0.0, ended=1.5, status="complete")
    path = write_stage_timings(tmp_path, timings)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["schema"] == "agentdecompile.stage-timings.v1"
    assert data["stages"]["inventory"]["wallSeconds"] == 1.5


def test_fresh_dump_rejects_stale_work_dir_summary(tmp_path: Path) -> None:
    work = tmp_path / "work"
    (work / "source-synthesis").mkdir(parents=True)
    (work / "state.json").write_text(
        json.dumps(
            {
                "binarySha256": "aaa",
                "stages": {
                    "prepare": {"status": "complete", "analysisBinarySha256": "aaa"},
                },
            }
        ),
        encoding="utf-8",
    )
    stale = work / "source-synthesis" / "accepted.jsonl"
    stale.write_text(
        json.dumps(
            {
                "name": "Stale",
                "entry": "00401000",
                "status": "matched",
                "differences": 0,
                "sourceText": "int Stale(void){return 0;}\n",
                "sourceQuality": "high-level-c",
                "targetSha256": "bbb",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    out = tmp_path / "dump"
    args = SimpleNamespace(
        dump_source=out,
        dump_source_only=False,
        dump_allow_leftovers=False,
        dump_layers="verified,port",
        ghidra_facts=None,
        input=Path("binary.exe"),
        json=True,
    )
    rc = run_dump_source(args, work)
    assert rc == 0
    receipt = json.loads((work / "dump-source.json").read_text(encoding="utf-8"))
    assert receipt["freshMode"] is True
    assert receipt["analysisBinarySha256"] == "aaa"
    assert receipt["summaries"] == []
    assert (work / "stage-timings.json").is_file()
    timings = json.loads((work / "stage-timings.json").read_text(encoding="utf-8"))
    assert "dump-source" in timings["stages"]


def test_fresh_dump_keeps_digest_matched_summary(tmp_path: Path) -> None:
    work = tmp_path / "work"
    (work / "source-synthesis").mkdir(parents=True)
    (work / "state.json").write_text(
        json.dumps(
            {
                "binarySha256": "aaa",
                "stages": {
                    "prepare": {"status": "complete", "analysisBinarySha256": "aaa"},
                },
            }
        ),
        encoding="utf-8",
    )
    matched = work / "source-synthesis" / "accepted.jsonl"
    matched.write_text(
        json.dumps(
            {
                "name": "Ok",
                "entry": "00401000",
                "status": "matched",
                "differences": 0,
                "sourceText": "int Ok(void){return 1;}\n",
                "sourceQuality": "high-level-c",
                "targetSha256": "aaa",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    out = tmp_path / "dump"
    args = SimpleNamespace(
        dump_source=out,
        dump_source_only=False,
        dump_allow_leftovers=False,
        dump_layers="verified,port",
        ghidra_facts=None,
        input=Path("binary.exe"),
        json=True,
    )
    rc = run_dump_source(args, work)
    assert rc == 0
    receipt = json.loads((work / "dump-source.json").read_text(encoding="utf-8"))
    assert str(matched) in receipt["summaries"]
    assert list((out / "verified").glob("*.c"))
