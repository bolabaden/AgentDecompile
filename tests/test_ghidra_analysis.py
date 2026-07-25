"""Unit tests for durable shared Ghidra analysis orchestration (U2)."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from agentdecompile_recovery.ghidra_analysis import (
    RECEIPT_SCHEMA,
    analysis_receipt_path,
    build_analyze_import_command,
    build_inventory_export_command,
    ensure_analyzed_program,
    export_function_inventory,
    resolve_project_name,
    validate_inventory_text_coverage,
)
from agentdecompile_recovery.source_parity_one_shot import (
    ProfileConfig,
    _inventory_section_counts,
    stage_inventory,
)
from agentdecompile_recovery.state import atomic_write_json

pytestmark = pytest.mark.unit


@pytest.fixture
def binary(tmp_path: Path) -> Path:
    path = tmp_path / "sample.exe"
    path.write_bytes(b"MZ" + b"\x00" * 128 + b"ghidra-analysis-u2")
    return path


@pytest.fixture
def analyze_headless(tmp_path: Path) -> Path:
    path = tmp_path / "analyzeHeadless"
    path.write_text("#!/bin/sh\n", encoding="utf-8")
    path.chmod(0o755)
    return path


@pytest.fixture
def script_dir(tmp_path: Path) -> Path:
    path = tmp_path / "scripts" / "ghidra"
    path.mkdir(parents=True)
    (path / "ExportFunctionInventory.java").write_text("// stub", encoding="utf-8")
    return path


def _fake_run_factory(
    *,
    project_path: Path,
    project_name: str,
    inventory_jsonl: Path | None = None,
) -> list[list[str]]:
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: object) -> SimpleNamespace:
        calls.append(list(cmd))
        if "-import" in cmd:
            (project_path / f"{project_name}.gpr").write_text("stub", encoding="utf-8")
        elif "-process" in cmd and inventory_jsonl is not None:
            inventory_jsonl.parent.mkdir(parents=True, exist_ok=True)
            inventory_jsonl.write_text(
                json.dumps({"name": "fn", "section": ".textV"}) + "\n",
                encoding="utf-8",
            )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    fake_run.calls = calls  # type: ignore[attr-defined]
    return fake_run


def test_build_analyze_import_command_has_no_delete_project(
    analyze_headless: Path,
    binary: Path,
    tmp_path: Path,
    script_dir: Path,
) -> None:
    cmd = build_analyze_import_command(
        analyze_headless=analyze_headless,
        project_path=tmp_path / "ghidra-shared",
        project_name="sample.exe-deadbeef",
        binary_path=binary,
        script_dir=script_dir,
    )
    assert "-deleteProject" not in cmd
    assert "-import" in cmd
    assert str(binary) in cmd


def test_build_inventory_export_command_uses_process_noanalysis(
    analyze_headless: Path,
    tmp_path: Path,
    script_dir: Path,
) -> None:
    inventory = tmp_path / "facts" / "function-inventory.jsonl"
    cmd = build_inventory_export_command(
        analyze_headless=analyze_headless,
        project_path=tmp_path / "ghidra-shared",
        project_name="sample.exe-deadbeef",
        program_name="sample.exe",
        script_dir=script_dir,
        inventory_jsonl=inventory,
    )
    assert "-process" in cmd
    assert "-noanalysis" in cmd
    assert "-deleteProject" not in cmd
    assert "-import" not in cmd
    assert "ExportFunctionInventory.java" in cmd
    assert str(inventory) in cmd


def test_ensure_reuses_receipt_when_sha_matches(
    binary: Path,
    analyze_headless: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_path = tmp_path / "ghidra-shared"
    project_name = "sample.exe-abc123"
    project_path.mkdir(parents=True, exist_ok=True)
    (project_path / f"{project_name}.gpr").write_text("stub", encoding="utf-8")
    receipt_path = analysis_receipt_path(project_path, project_name)
    atomic_write_json(
        receipt_path,
        {
            "schema": RECEIPT_SCHEMA,
            "analysisBinarySha256": "abc123",
            "projectPath": str(project_path),
            "projectName": project_name,
            "programName": "sample.exe",
            "analyzedAt": "2026-07-24T00:00:00Z",
        },
    )
    monkeypatch.setattr(
        "agentdecompile_recovery.ghidra_analysis.sha256_file",
        lambda _path: "abc123",
    )
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: object) -> SimpleNamespace:
        calls.append(list(cmd))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    receipt = ensure_analyzed_program(
        binary,
        project_path=project_path,
        project_name=project_name,
        analyze_headless=analyze_headless,
        run=fake_run,
    )
    assert receipt["reused"] is True
    assert calls == []


def test_ensure_reanalyzes_on_sha_mismatch(
    binary: Path,
    analyze_headless: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_path = tmp_path / "ghidra-shared"
    project_name = "sample.exe-abc123"
    project_path.mkdir(parents=True, exist_ok=True)
    (project_path / f"{project_name}.gpr").write_text("old", encoding="utf-8")
    receipt_path = analysis_receipt_path(project_path, project_name)
    atomic_write_json(
        receipt_path,
        {
            "schema": RECEIPT_SCHEMA,
            "analysisBinarySha256": "old-sha",
            "projectPath": str(project_path),
            "projectName": project_name,
            "programName": "sample.exe",
            "analyzedAt": "2026-07-24T00:00:00Z",
        },
    )
    monkeypatch.setattr(
        "agentdecompile_recovery.ghidra_analysis.sha256_file",
        lambda _path: "new-sha",
    )
    fake_run = _fake_run_factory(project_path=project_path, project_name=project_name)

    receipt = ensure_analyzed_program(
        binary,
        project_path=project_path,
        project_name=project_name,
        analyze_headless=analyze_headless,
        run=fake_run,
    )
    assert receipt["reused"] is False
    assert receipt["analysisBinarySha256"] == "new-sha"
    assert len(fake_run.calls) == 1  # type: ignore[attr-defined]
    assert "-import" in fake_run.calls[0]  # type: ignore[attr-defined]
    assert "-deleteProject" not in fake_run.calls[0]  # type: ignore[attr-defined]


def test_export_function_inventory_uses_existing_project(
    analyze_headless: Path,
    tmp_path: Path,
    script_dir: Path,
) -> None:
    project_path = tmp_path / "ghidra-shared"
    project_name = "sample.exe-abc123"
    inventory = tmp_path / "facts" / "function-inventory.jsonl"
    fake_run = _fake_run_factory(
        project_path=project_path,
        project_name=project_name,
        inventory_jsonl=inventory,
    )
    receipt = {
        "projectPath": str(project_path),
        "projectName": project_name,
        "programName": "sample.exe",
        "receiptPath": str(analysis_receipt_path(project_path, project_name)),
    }
    export = export_function_inventory(
        receipt=receipt,
        inventory_jsonl=inventory,
        analyze_headless=analyze_headless,
        script_dir=script_dir,
        run=fake_run,
    )
    assert inventory.exists()
    cmd = export["exportCommand"]
    assert "-process" in cmd
    assert "-noanalysis" in cmd
    assert "-deleteProject" not in cmd


def test_validate_inventory_text_coverage_rejects_empty_text(
    tmp_path: Path,
) -> None:
    jsonl = tmp_path / "function-inventory.jsonl"
    jsonl.write_text(
        "\n".join(
            [
                json.dumps({"name": "stub", "section": ".bind"}),
                json.dumps({"name": "loader", "section": ".text"}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="no functions in \\.textV"):
        validate_inventory_text_coverage(
            jsonl,
            ".textV",
            section_counter=_inventory_section_counts,
        )


def test_resolve_project_name_uses_ghidrecomp_when_available(
    binary: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "agentdecompile_recovery.ghidra_analysis.gen_proj_bin_name_from_path",
        lambda _path: "sample.exe-deadbeef",
    )
    assert resolve_project_name(binary) == "sample.exe-deadbeef"


def test_stage_inventory_wires_shared_project_receipt(
    binary: Path,
    analyze_headless: Path,
    script_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unpack = tmp_path / "unpack"
    unpack.mkdir()
    profile = ProfileConfig(
        slug="swkotor",
        default_binary=binary,
        unpack_dir=unpack,
        inventory_jsonl=unpack / "facts" / "function-inventory.jsonl",
        inventory_summary=unpack / "facts" / "inventory-summary.json",
        trivial_matches_dir=tmp_path / "trivial",
        trivial_out_jsonl=tmp_path / "trivial" / "summary.jsonl",
        trivial_summary=tmp_path / "trivial" / "summary.json",
        reloc_matches_dir=tmp_path / "reloc",
        reloc_out_jsonl=tmp_path / "reloc" / "summary.jsonl",
        reloc_summary=tmp_path / "reloc" / "summary.json",
        recovered_dir=tmp_path / "recovered",
        compile_summary=tmp_path / "recovered" / "compile-summary.json",
        coverage_json=tmp_path / "recovered" / "coverage.json",
        queue_jsonl=tmp_path / "queue" / "queue.jsonl",
        index_out_dir=tmp_path / "index",
        synthesis_out_dir=tmp_path / "synthesis",
        state_dir=tmp_path / "state",
        text_section=".textV",
        match_root=tmp_path / "match",
    )
    state: dict[str, object] = {
        "binaryPath": str(binary),
        "binarySha256": "orig-sha",
        "textSection": ".textV",
        "stages": {},
    }
    monkeypatch.setattr(
        "agentdecompile_recovery.source_parity_one_shot.ROOT",
        script_dir.parents[1],
    )
    monkeypatch.setattr(
        "agentdecompile_recovery.source_parity_one_shot.inventory_binary",
        lambda _profile, _state: binary,
    )
    monkeypatch.setattr(
        "agentdecompile_recovery.source_parity_one_shot.sha256_file",
        lambda path: "analysis-sha" if path == binary else "orig-sha",
    )
    project_name = "sample.exe-deadbeef"
    shared_project = unpack / "ghidra-shared"
    fake_run = _fake_run_factory(
        project_path=shared_project,
        project_name=project_name,
        inventory_jsonl=profile.inventory_jsonl,
    )
    monkeypatch.setattr(
        "agentdecompile_recovery.source_parity_one_shot.ensure_analyzed_program",
        lambda *args, **kwargs: ensure_analyzed_program(
            *args,
            project_name=project_name,
            run=fake_run,
            **kwargs,
        ),
    )
    monkeypatch.setattr(
        "agentdecompile_recovery.source_parity_one_shot.export_function_inventory",
        lambda **kwargs: export_function_inventory(run=fake_run, **kwargs),
    )

    stage_inventory(profile, state, refresh=True, ghidra=analyze_headless)

    inv_stage = (state.get("stages") or {}).get("inventory") or {}
    assert inv_stage.get("status") == "complete"
    assert inv_stage.get("ghidraProjectPath") == str(shared_project)
    assert inv_stage.get("ghidraProjectName") == project_name
    assert inv_stage.get("ghidraProgramName") == "sample.exe"
    export_cmds = [cmd for cmd in fake_run.calls if "-process" in cmd]  # type: ignore[attr-defined]
    assert export_cmds
    assert "-noanalysis" in export_cmds[0]
    assert "-deleteProject" not in export_cmds[0]
