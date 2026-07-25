"""Dump readability gate for Port/CODE (ELF + reconstruct work-dir facts)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentdecompile_recovery.source_dump import dump_source_tree, strip_ghidra_noise, style_c_source

pytestmark = pytest.mark.unit


def test_fun_named_advisory_excluded_from_port(tmp_path: Path) -> None:
    facts = tmp_path / "facts.jsonl"
    facts.write_text(
        json.dumps(
            {
                "name": "FUN_08050000",
                "entry": "08050000",
                "decompiled": "void FUN_08050000(void) { return; }",
                "decompilationStatus": "complete",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    out = tmp_path / "dump"
    manifest = dump_source_tree(
        out_dir=out,
        summaries=[],
        ghidra_facts=facts,
        layers="port,advisory",
        profile="elf-i386-sample",
        target_name="sample.elf",
    )
    assert manifest.get("readabilityExcludedFromPort", 0) >= 1
    adv = list((out / "advisory" / "ghidra").glob("*.c"))
    assert adv
    port_cpps = list((out / "Port" / "CODE").rglob("ghidra_decompiled.cpp"))
    assert not port_cpps


def test_named_module_hint_lands_in_port(tmp_path: Path) -> None:
    facts = tmp_path / "facts.jsonl"
    facts.write_text(
        json.dumps(
            {
                "name": "LoadArea",
                "entry": "00401000",
                "decompiled": "/* WARNING: Globals starting with '_' overlap */\nint LoadArea(void) { return 0; }",
                "decompilationStatus": "complete",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    out = tmp_path / "dump"
    manifest = dump_source_tree(
        out_dir=out,
        summaries=[],
        ghidra_facts=facts,
        layers="port,advisory",
        profile="pe-i386-sample",
        target_name="sample.exe",
        module_hints={
            "00401000": {
                "module": "game/clientcore",
                "moduleProvenance": "assert-string",
                "score": 0.9,
            }
        },
    )
    assert manifest.get("readabilityExcludedFromPort", 0) == 0
    port_files = list((out / "Port" / "CODE" / "game" / "clientcore").rglob("*.cpp"))
    assert port_files
    text = port_files[0].read_text(encoding="utf-8")
    assert "LoadArea" in text
    assert "WARNING:" not in text


def test_strip_ghidra_noise_removes_warning_and_library_banners() -> None:
    noisy = (
        "/* WARNING: Removing unreachable block */\n"
        "/* Library Function - Single Match */\n"
        "int Foo(void) {\n"
        "  return 1;\n"
        "}\n"
    )
    cleaned = strip_ghidra_noise(noisy)
    assert "WARNING:" not in cleaned
    assert "Library Function" not in cleaned
    styled = style_c_source(noisy)
    assert "WARNING:" not in styled
    assert "Library Function" not in styled
