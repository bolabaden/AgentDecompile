"""Unit tests for reconstruct vacuum runner → plugin pipeline bridge."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agentdecompile_recovery.autonomy_budget import AutonomyBudget, reconstruct_vacuum_runner_command
from agentdecompile_recovery.vacuum_runner import already_verified, find_source_task, run_vacuum_prompt

pytestmark = pytest.mark.unit


def _task(name: str, *, complete_slice: bool = True) -> dict[str, Any]:
    task: dict[str, Any] = {
        "name": name,
        "entry": "0x401000",
        "status": "generated-unverified",
        "source": "candidate.c",
        "semanticSource": True,
    }
    if complete_slice:
        task["targetSlice"] = {
            "status": "complete",
            "bytesPath": "slice.bin",
            "bodyBytes": 4,
        }
    return task


def test_find_source_task_and_already_verified(tmp_path: Path) -> None:
    work = tmp_path / "run"
    gen = work / "source-generation"
    gen.mkdir(parents=True)
    (gen / "tasks.jsonl").write_text(json.dumps(_task("FUN_401000")) + "\n", encoding="utf-8")
    assert find_source_task(work, "FUN_401000")["name"] == "FUN_401000"
    assert find_source_task(work, "missing") is None
    (work / "verified").mkdir()
    (work / "verified" / "FUN_401000_401000.c").write_text("int x(void){return 0;}\n", encoding="utf-8")
    assert already_verified(work, "FUN_401000") is True
    (work / "verified" / "DrawFrame_401000.c").write_text("int DrawFrame(void){return 0;}\n", encoding="utf-8")
    assert already_verified(work, "Draw") is False
    assert already_verified(work, "DrawFrame") is True


def test_reconstruct_vacuum_runner_command_quotes_placeholders(tmp_path: Path) -> None:
    spaced = tmp_path / "work dir"
    spaced.mkdir()
    cmd = reconstruct_vacuum_runner_command(spaced, max_attempts=4)
    assert "'{{name}}'" in cmd or "\"{{name}}\"" in cmd
    assert "'{{promptDir}}'" in cmd or "\"{{promptDir}}\"" in cmd
    # Simulate vacuum placeholder substitution with a spaced prompt path.
    rendered = cmd.replace("{{name}}", "fn").replace("{{promptDir}}", str(spaced / "prompts" / "fn"))
    assert "--prompt-dir" in rendered
    assert "work dir" in rendered
    budget = AutonomyBudget(max_functions=1, max_attempts_per_function=4)
    args = budget.vacuum_bridge_args(
        queue=spaced / "state" / "queue.json",
        prompts_dir=spaced / "prompts",
        work_dir=spaced,
        runner_command=cmd,
    )
    assert args is not None
    assert "--runner-command" in args
    assert "--no-sleep" in args
    assert str(spaced / "state" / "scores.json") in args


def test_run_vacuum_prompt_missing_and_unsuitable(tmp_path: Path) -> None:
    work = tmp_path / "run"
    work.mkdir()
    missing = run_vacuum_prompt(work_dir=work, name="gone")
    assert missing["exitCode"] == 2
    assert missing["status"] == "missing-task"

    gen = work / "source-generation"
    gen.mkdir()
    (gen / "tasks.jsonl").write_text(json.dumps(_task("alpha", complete_slice=False)) + "\n", encoding="utf-8")
    bad = run_vacuum_prompt(work_dir=work, name="alpha")
    assert bad["exitCode"] == 2
    assert bad["status"] == "unsuitable-task"


def test_run_vacuum_prompt_uses_plugin_pipeline(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    work = tmp_path / "run"
    gen = work / "source-generation"
    gen.mkdir(parents=True)
    slice_path = gen / "slice.bin"
    slice_path.write_bytes(b"\x90\x90\xc3\x00")
    src = gen / "candidate.c"
    src.write_text("int alpha(void){return 0;}\n", encoding="utf-8")
    task = _task("alpha")
    task["source"] = str(src)
    task["targetSlice"]["bytesPath"] = str(slice_path)
    (gen / "tasks.jsonl").write_text(json.dumps(task) + "\n", encoding="utf-8")

    calls: list[Any] = []

    def fake_pipeline(config: Any) -> dict[str, Any]:
        calls.append(config)
        out = Path(config.out_dir)
        matches = out / "plugin-code-slice-matches.jsonl"
        matches.parent.mkdir(parents=True, exist_ok=True)
        matches.write_text(
            json.dumps(
                {
                    "name": "alpha",
                    "entry": "0x401000",
                    "differences": 0,
                    "status": "matched",
                    "source": str(src),
                }
            )
            + "\n",
            encoding="utf-8",
        )
        return {
            "status": "complete",
            "successfulFunctions": 1,
            "failedFunctions": 0,
            "inspectedFunctions": 1,
            "codeSliceMatchesPath": str(matches),
        }

    monkeypatch.setattr(
        "agentdecompile_recovery.vacuum_runner.run_source_plugin_pipeline",
        fake_pipeline,
    )
    result = run_vacuum_prompt(
        work_dir=work,
        name="alpha",
        max_attempts=2,
        vc_root=Path("/opt/msvc8"),
        wineprefix=Path("/opt/wine-smoke-prefix"),
    )
    assert result["exitCode"] == 0
    assert result["status"] == "matched"
    assert calls and calls[0].max_retries >= 2
    assert calls[0].vc_root == Path("/opt/msvc8")
    assert calls[0].wineprefix == Path("/opt/wine-smoke-prefix")
    assert any(path.name.endswith(".c") for path in (work / "verified").iterdir())


def _vacuum_pipeline_stub(src: Path, rows: list[dict[str, Any]]) -> Any:
    def fake_pipeline(config: Any) -> dict[str, Any]:
        out = Path(config.out_dir)
        matches = out / "plugin-code-slice-matches.jsonl"
        matches.parent.mkdir(parents=True, exist_ok=True)
        matches.write_text(
            "".join(json.dumps({**row, "source": str(src)}) + "\n" for row in rows),
            encoding="utf-8",
        )
        return {
            "status": "complete",
            "successfulFunctions": 1,
            "failedFunctions": 0,
            "inspectedFunctions": 1,
            "codeSliceMatchesPath": str(matches),
        }

    return fake_pipeline


def _seed_vacuum_work_dir(tmp_path: Path) -> tuple[Path, Path]:
    work = tmp_path / "run"
    gen = work / "source-generation"
    gen.mkdir(parents=True)
    slice_path = gen / "slice.bin"
    slice_path.write_bytes(b"\x90\x90\xc3\x00")
    src = gen / "candidate.c"
    src.write_text("int alpha(void){return 0;}\n", encoding="utf-8")
    task = _task("alpha")
    task["source"] = str(src)
    task["targetSlice"]["bytesPath"] = str(slice_path)
    (gen / "tasks.jsonl").write_text(json.dumps(task) + "\n", encoding="utf-8")
    return work, src


def test_run_vacuum_prompt_does_not_publish_rows_without_objdiff_zero(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A non-accept row must not reach verified/ just because the pipeline reported success."""

    work, src = _seed_vacuum_work_dir(tmp_path)
    monkeypatch.setattr(
        "agentdecompile_recovery.vacuum_runner.run_source_plugin_pipeline",
        _vacuum_pipeline_stub(
            src,
            [{"name": "alpha", "entry": "0x401000", "differences": 3, "status": "mismatched"}],
        ),
    )

    run_vacuum_prompt(work_dir=work, name="alpha", max_attempts=1)

    assert not (work / "verified").exists()


def test_run_vacuum_prompt_routes_code_slice_row_to_code_slice_dir(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    work, src = _seed_vacuum_work_dir(tmp_path)
    boundary = "this is code-slice evidence, not full target-object source parity"
    monkeypatch.setattr(
        "agentdecompile_recovery.vacuum_runner.run_source_plugin_pipeline",
        _vacuum_pipeline_stub(
            src,
            [
                {
                    "name": "alpha",
                    "entry": "0x401000",
                    "differences": 0,
                    "status": "code-slice-matched",
                    "verificationTier": "synthetic-target-coff-objdiff",
                    "claimBoundary": boundary,
                }
            ],
        ),
    )

    run_vacuum_prompt(work_dir=work, name="alpha", max_attempts=1)

    slice_dir = work / "verified" / "code-slice"
    assert not list((work / "verified").glob("alpha_*"))
    metadata = json.loads((slice_dir / "alpha_401000.json").read_text(encoding="utf-8"))
    assert metadata["proofTier"] == "synthetic-target-coff-objdiff"
    assert boundary in metadata["claimBoundary"]


def test_reconstruct_vacuum_runner_command_includes_vc_root_and_wineprefix(tmp_path: Path) -> None:
    cmd = reconstruct_vacuum_runner_command(
        tmp_path,
        max_attempts=3,
        vc_root=Path("/opt/msvc8"),
        wineprefix=Path("/opt/wine-smoke-prefix"),
    )
    assert "--vc-root /opt/msvc8" in cmd
    assert "--wineprefix /opt/wine-smoke-prefix" in cmd


def test_reconstruct_vacuum_runner_command_omits_flags_when_unset(tmp_path: Path) -> None:
    cmd = reconstruct_vacuum_runner_command(tmp_path, max_attempts=3)
    assert "--vc-root" not in cmd
    assert "--wineprefix" not in cmd
