"""Unit tests for the Unity stages' wiring into RecoveryRunner.

The behaviour worth protecting here is not what the Unity modules compute --
that is covered by their own tests -- but that these stages are *inert and
resumable* for every target that is not a Unity game. The existing pipeline is
PE/ELF function-recovery oriented and runs on everything, so a Unity stage that
raised, or that skipped without writing its declared output, would break
unrelated runs (the resume gate requires declared outputs to exist).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentdecompile_recovery.pipeline import RecoveryConfig, RecoveryRunner

pytestmark = pytest.mark.unit


UNITY_STAGE_NAMES = [
    "unity-probe",
    "unity-plan",
    "unity-export-assets",
    "unity-decompile-managed",
    "unity-compose-project",
    "unity-editor-validate",
    "unity-repair",
]


def _runner(tmp_path: Path, input_path: Path | None = None, **overrides: object) -> RecoveryRunner:
    config = RecoveryConfig(
        input_path=input_path or (tmp_path / "game"),
        work_dir=tmp_path / "work",
        **overrides,  # type: ignore[arg-type]
    )
    (config.work_dir).mkdir(parents=True, exist_ok=True)
    return RecoveryRunner(config)


def _stage(runner: RecoveryRunner, name: str):
    return next(stage for stage in runner.stages if stage.name == name)


def _run(runner: RecoveryRunner, name: str) -> dict:
    stage = _stage(runner, name)
    return stage.run(runner, stage)


# --- registration ------------------------------------------------------------


def test_unity_stages_are_registered_in_dependency_order(tmp_path: Path) -> None:
    names = [stage.name for stage in _runner(tmp_path).stages]
    unity = [name for name in names if name.startswith("unity-")]
    assert unity == UNITY_STAGE_NAMES


def test_report_stage_remains_last(tmp_path: Path) -> None:
    names = [stage.name for stage in _runner(tmp_path).stages]
    assert names[-1] == "report"


def test_every_unity_stage_declares_a_single_output(tmp_path: Path) -> None:
    runner = _runner(tmp_path)
    for name in UNITY_STAGE_NAMES:
        outputs = _stage(runner, name).outputs
        assert len(outputs) == 1, name
        assert outputs[0].parent == runner.run_dir / "unity", name


def test_unity_stages_have_distinct_fingerprints_from_each_other(tmp_path: Path) -> None:
    runner = _runner(tmp_path)
    fingerprints = {name: runner.stage_fingerprint(_stage(runner, name)) for name in UNITY_STAGE_NAMES}
    assert len(set(fingerprints.values())) == len(UNITY_STAGE_NAMES)


# --- inertness on non-Unity targets ------------------------------------------


def test_probe_reports_not_detected_for_non_unity_target(tmp_path: Path) -> None:
    game = tmp_path / "game"
    game.mkdir()
    (game / "thing.exe").write_bytes(b"MZ")

    summary = _run(_runner(tmp_path, input_path=game), "unity-probe")

    assert summary["status"] == "complete"
    assert summary["detected"] is False


def test_downstream_unity_stages_skip_when_not_a_unity_game(tmp_path: Path) -> None:
    game = tmp_path / "game"
    game.mkdir()
    runner = _runner(tmp_path, input_path=game)
    _run(runner, "unity-probe")

    for name in UNITY_STAGE_NAMES[1:]:
        summary = _run(runner, name)
        assert summary["status"] == "skipped", name
        # The resume gate keys off declared outputs existing, so a skip must
        # still leave its receipt behind or the stage reruns forever.
        assert _stage(runner, name).outputs[0].exists(), name


def test_skipped_stage_receipt_records_a_reason(tmp_path: Path) -> None:
    game = tmp_path / "game"
    game.mkdir()
    runner = _runner(tmp_path, input_path=game)
    _run(runner, "unity-probe")
    _run(runner, "unity-plan")

    payload = json.loads((runner.run_dir / "unity" / "plan.json").read_text(encoding="utf-8"))
    assert payload["status"] == "skipped"
    assert payload["reason"]


# --- install-root resolution -------------------------------------------------


def test_install_root_uses_directory_input_directly(tmp_path: Path) -> None:
    game = tmp_path / "game"
    game.mkdir()
    assert _runner(tmp_path, input_path=game).unity_install_root() == game.resolve()


def test_install_root_uses_parent_for_executable_input(tmp_path: Path) -> None:
    game = tmp_path / "game"
    game.mkdir()
    exe = game / "Player.exe"
    exe.write_bytes(b"MZ")
    assert _runner(tmp_path, input_path=exe).unity_install_root() == game.resolve()


# --- compose/validate guards -------------------------------------------------


def _unity_game(tmp_path: Path) -> Path:
    game = tmp_path / "game"
    data = game / "Game_Data"
    data.mkdir(parents=True)
    (data / "globalgamemanagers").write_bytes(b"\x00" * 16 + b"2022.3.62f2" + b"\x00" * 16)
    (data / "level0").write_bytes(b"x")
    managed = data / "Managed"
    managed.mkdir()
    (managed / "Assembly-CSharp.dll").write_bytes(b"MZ")
    return game


def test_compose_skips_without_a_target_project(tmp_path: Path) -> None:
    runner = _runner(tmp_path, input_path=_unity_game(tmp_path))
    _run(runner, "unity-probe")

    summary = _run(runner, "unity-compose-project")

    assert summary["status"] == "skipped"
    assert "--unity-project-out" in summary["reason"]


def test_validate_skips_without_a_target_project(tmp_path: Path) -> None:
    runner = _runner(tmp_path, input_path=_unity_game(tmp_path))
    _run(runner, "unity-probe")

    summary = _run(runner, "unity-editor-validate")

    assert summary["status"] == "skipped"


def test_repair_skips_when_validation_was_clean(tmp_path: Path) -> None:
    runner = _runner(
        tmp_path,
        input_path=_unity_game(tmp_path),
        unity_project_out=tmp_path / "project",
    )
    _run(runner, "unity-probe")
    unity_dir = runner.run_dir / "unity"
    unity_dir.mkdir(parents=True, exist_ok=True)
    (unity_dir / "validate.json").write_text(json.dumps({"status": "complete", "clean": True}), encoding="utf-8")

    summary = _run(runner, "unity-repair")

    assert summary["status"] == "skipped"
    assert "clean" in summary["reason"]


def test_managed_decompile_skips_on_il2cpp(tmp_path: Path) -> None:
    game = _unity_game(tmp_path)
    # IL2CPP markers alongside Managed/ flip the backend away from mono.
    (game / "Game_Data" / "il2cpp_data").mkdir()
    (game / "GameAssembly.dll").write_bytes(b"MZ")
    runner = _runner(tmp_path, input_path=game)
    _run(runner, "unity-probe")

    summary = _run(runner, "unity-decompile-managed")

    assert summary["status"] == "skipped"
    assert "il2cpp" in summary["reason"]


def test_export_skips_when_plan_is_blocked(tmp_path: Path) -> None:
    game = _unity_game(tmp_path)
    (game / "Game_Data" / "il2cpp_data").mkdir()
    (game / "GameAssembly.dll").write_bytes(b"MZ")
    runner = _runner(tmp_path, input_path=game)
    _run(runner, "unity-probe")
    _run(runner, "unity-plan")

    summary = _run(runner, "unity-export-assets")

    assert summary["status"] == "skipped"
    assert "il2cpp" in summary["reason"]
