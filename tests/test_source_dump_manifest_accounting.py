"""MANIFEST.json must account for every unit the dump actually wrote.

Before this, `functions` / `files` / `functionCount` / `ghidraCount` were
derived only from the Port/CODE bucket map. With the `port` layer off they
measured nothing (12,746 advisory `.c` files on disk, `ghidraCount: 0`), and
even with `port` on they under-counted advisory by exactly the number of units
the readability gate held out of Port/CODE.

Raising the counts raises no claim: authority values are unchanged, and
`matchedCount` still comes only from `authority_label`.
"""

from __future__ import annotations

import json
from pathlib import Path

from agentdecompile_recovery.source_dump import dump_source_tree


def _facts(path: Path, rows: list[dict]) -> Path:
    path.write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n",
        encoding="utf-8",
    )
    return path


def _advisory_row(entry: str, name: str) -> dict:
    return {
        "name": name,
        "entry": entry,
        "entryOffset": entry,
        "decompiled": f"void {name}(void)\n{{\n  return;\n}}\n",
        "decompilationStatus": "complete",
        "entityKind": "function",
        "bodyBytes": 1,
        "prototype": f"void {name}(void)",
        "tool": "ghidra",
    }


def test_advisory_only_dump_counts_the_files_it_wrote(tmp_path: Path) -> None:
    facts = _facts(
        tmp_path / "facts.jsonl",
        [_advisory_row("00401060", "LoadModule"), _advisory_row("00401280", "DestroyServer")],
    )

    out_dir = tmp_path / "dump"
    manifest = dump_source_tree(
        out_dir=out_dir,
        summaries=[],
        ghidra_facts=facts,
        target_name="swkotor.exe",
        layers="advisory",
    )

    on_disk = sorted((out_dir / "advisory" / "ghidra").glob("*.c"))
    assert len(on_disk) == 2

    assert manifest["ghidraCount"] == 2
    assert manifest["functionCount"] == 2
    assert manifest["namedCount"] == 2
    assert len(manifest["functions"]) == 2
    assert manifest["files"], "files[] must not be empty when files were written"

    # Every listed file exists, and every function points at a real file.
    for rel in manifest["files"]:
        assert (out_dir / rel).is_file(), rel
    for fn in manifest["functions"]:
        assert (out_dir / fn["source"]).is_file(), fn["source"]
        assert fn["authority"] == "ghidra-advisory"
        # No Port/CODE layer in this run, so nothing claims a Port home.
        assert fn["portSource"] is None

    # Counting more units must not manufacture proof.
    assert manifest["matchedCount"] == 0
    assert manifest["codeSliceMatchedCount"] == 0


def test_readme_reports_the_advisory_units_it_wrote(tmp_path: Path) -> None:
    facts = _facts(tmp_path / "facts.jsonl", [_advisory_row("00401060", "LoadModule")])
    out_dir = tmp_path / "dump"
    dump_source_tree(
        out_dir=out_dir,
        summaries=[],
        ghidra_facts=facts,
        target_name="swkotor.exe",
        layers="advisory",
    )

    readme = (out_dir / "README.md").read_text(encoding="utf-8")
    assert "- Ghidra advisory: 1" in readme
    assert "- Full-object matched: 0" in readme


def test_gate_excluded_advisory_unit_still_counts_in_ghidra_count(tmp_path: Path) -> None:
    """The latent under-report: with `port` on, gate-excluded units vanished.

    `FUN_`-prefixed names with no module evidence fail
    `passes_readability_gate`, so they never enter a Port/CODE bucket -- but
    their advisory `.c` file is written regardless, and the manifest must say so.
    """

    facts = _facts(
        tmp_path / "facts.jsonl",
        [_advisory_row("00500000", "NamedHelper"), _advisory_row("00600000", "FUN_00600000")],
    )

    out_dir = tmp_path / "dump"
    manifest = dump_source_tree(
        out_dir=out_dir,
        summaries=[],
        ghidra_facts=facts,
        module_hints={
            "00500000": {"module": "game/somemodule", "moduleProvenance": "assert-string"}
        },
    )

    advisory = sorted((out_dir / "advisory" / "ghidra").glob("**/*.c"))
    assert len(advisory) == 2

    assert manifest["readabilityExcludedFromPort"] == 1
    assert manifest["ghidraCount"] == 2, "the gate-excluded unit was written and must be counted"
    assert manifest["functionCount"] == 2

    by_name = {fn["name"]: fn for fn in manifest["functions"]}
    assert by_name["NamedHelper"]["portSource"] is not None
    assert by_name["FUN_00600000"]["portSource"] is None
    for fn in by_name.values():
        assert fn["authority"] == "ghidra-advisory"
        assert (out_dir / fn["source"]).is_file()

    readme = (out_dir / "README.md").read_text(encoding="utf-8")
    assert "held out of Port/CODE by the readability gate: 1" in readme


def test_manifest_paths_are_dump_root_relative(tmp_path: Path) -> None:
    facts = _facts(tmp_path / "facts.jsonl", [_advisory_row("00500000", "NamedHelper")])
    out_dir = tmp_path / "dump"
    manifest = dump_source_tree(
        out_dir=out_dir,
        summaries=[],
        ghidra_facts=facts,
        module_hints={
            "00500000": {"module": "game/somemodule", "moduleProvenance": "assert-string"}
        },
    )

    assert manifest["files"], "expected written files"
    for rel in manifest["files"]:
        assert not Path(rel).is_absolute()
        assert (out_dir / rel).is_file(), rel
    assert any(rel.startswith("Port/CODE/") for rel in manifest["files"])
    assert any(rel.startswith("advisory/ghidra/") for rel in manifest["files"])
