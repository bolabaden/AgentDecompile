"""Tests for run_pipeline_command.py, the m2c/compiler/objdiff pipeline orchestrator."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from agentdecompile_recovery.prompt_loader import PromptInfo
from agentdecompile_recovery.run_pipeline_command import RunPipelineConfig, run_prompt, run_prompts_pipeline

pytestmark = pytest.mark.unit

_HAS_TOOLCHAIN = shutil.which("cpp") is not None and (shutil.which("gcc") is not None or shutil.which("cc") is not None)


def _fake_runner(stdout: str = "", stderr: str = "", exit_code: int = 0):
    def runner(command: list[str], *, timeout_ms: int | None = None) -> dict:
        return {"command": command, "exitCode": exit_code, "stdout": stdout, "stderr": stderr}

    return runner


def _compiler_script() -> str:
    cc = shutil.which("gcc") or shutil.which("cc")
    return f'{cc} -c "{{{{cFilePath}}}}" -o "{{{{objFilePath}}}}"\n'


def test_setup_phase_runs_get_context_script_and_populates_context_content(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("agentdecompile_cli.mcp_utils.decomp_match.shutil.which", lambda _name: None)

    prompt = PromptInfo(path="p1", content="", function_name="target", target_object_path="x.o", asm="bx lr")
    config = RunPipelineConfig(
        prompts_dir=tmp_path,
        out_dir=tmp_path / "out",
        compiler_script=_compiler_script(),
        project_root=tmp_path,
        get_context_script="echo 'struct Foo { int x; };'",
    )

    result = run_prompt(prompt, config)

    assert result["setupPhase"]["success"] is True
    assert "struct Foo" in result["setupPhase"]["pluginResults"][0]["data"]["contextContent"]


def test_pipeline_aborts_before_attempts_when_setup_phase_fails(tmp_path: Path):
    prompt = PromptInfo(path="p1", content="", function_name="target", target_object_path="x.o", asm="bx lr")
    config = RunPipelineConfig(
        prompts_dir=tmp_path,
        out_dir=tmp_path / "out",
        compiler_script=_compiler_script(),
        project_root=tmp_path,
        get_context_script="exit 1",
    )

    result = run_prompt(prompt, config)

    assert result["success"] is False
    assert result["setupPhase"]["success"] is False
    assert result["attempts"] == []


def test_m2c_phase_fails_gracefully_when_m2c_binary_is_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("agentdecompile_cli.mcp_utils.decomp_match.shutil.which", lambda _name: None)

    prompt = PromptInfo(path="p1", content="", function_name="target", target_object_path="x.o", asm="bx lr")
    config = RunPipelineConfig(
        prompts_dir=tmp_path, out_dir=tmp_path / "out", compiler_script=_compiler_script(), project_root=tmp_path
    )

    result = run_prompt(prompt, config)

    assert result["success"] is False
    assert result["attempts"][0]["pluginResults"][0]["pluginId"] == "m2c"
    assert result["attempts"][0]["pluginResults"][0]["status"] == "failure"


@pytest.mark.skipif(not _HAS_TOOLCHAIN, reason="requires cpp and gcc/cc on PATH")
def test_full_pipeline_matches_when_objdiff_reports_exit_zero(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("agentdecompile_cli.mcp_utils.decomp_match.shutil.which", lambda name: f"/usr/bin/{name}")

    def runner(command: list[str], *, timeout_ms: int | None = None) -> dict:
        if "m2c" in command[0]:
            return {"command": command, "exitCode": 0, "stdout": "int target(void) { return 1; }", "stderr": ""}
        return {"command": command, "exitCode": 0, "stdout": "{}", "stderr": ""}

    prompt = PromptInfo(path="p1", content="", function_name="target", target_object_path=str(tmp_path / "base.o"), asm="bx lr")
    (tmp_path / "base.o").write_bytes(b"")
    config = RunPipelineConfig(
        prompts_dir=tmp_path, out_dir=tmp_path / "out", compiler_script=_compiler_script(), project_root=tmp_path
    )

    result = run_prompt(prompt, config, command_runner=runner)

    assert result["success"] is True
    assert result["matchSource"] == "main-phase"


@pytest.mark.skipif(not _HAS_TOOLCHAIN, reason="requires cpp and gcc/cc on PATH")
def test_pipeline_fails_when_objdiff_reports_a_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("agentdecompile_cli.mcp_utils.decomp_match.shutil.which", lambda name: f"/usr/bin/{name}")

    def runner(command: list[str], *, timeout_ms: int | None = None) -> dict:
        if "m2c" in command[0]:
            return {"command": command, "exitCode": 0, "stdout": "int target(void) { return 1; }", "stderr": ""}
        return {"command": command, "exitCode": 1, "stdout": "{}", "stderr": "mismatch"}

    prompt = PromptInfo(path="p1", content="", function_name="target", target_object_path=str(tmp_path / "base.o"), asm="bx lr")
    (tmp_path / "base.o").write_bytes(b"")
    config = RunPipelineConfig(
        prompts_dir=tmp_path, out_dir=tmp_path / "out", compiler_script=_compiler_script(), project_root=tmp_path, max_retries=1
    )

    result = run_prompt(prompt, config, command_runner=runner)

    assert result["success"] is False


@pytest.mark.skipif(not _HAS_TOOLCHAIN, reason="requires cpp and gcc/cc on PATH")
def test_run_prompts_pipeline_writes_a_json_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("agentdecompile_cli.mcp_utils.decomp_match.shutil.which", lambda name: f"/usr/bin/{name}")

    cc = shutil.which("gcc") or shutil.which("cc")
    prompts_dir = tmp_path / "prompts"
    prompt_dir = prompts_dir / "case1"
    prompt_dir.mkdir(parents=True)
    obj_path = tmp_path / "target.o"
    c_path = tmp_path / "target.c"
    c_path.write_text("void target(void) { volatile int x = 1; x = x + 1; }\n", encoding="utf-8")
    import subprocess

    subprocess.run([cc, "-c", str(c_path), "-o", str(obj_path)], check=True, capture_output=True)

    (prompt_dir / "prompt.md").write_text("# target\n", encoding="utf-8")
    (prompt_dir / "settings.yaml").write_text(
        f'functionName: "target"\ntargetObjectPath: "{obj_path}"\nasm: |\n  bx lr\n', encoding="utf-8"
    )

    def runner(command: list[str], *, timeout_ms: int | None = None) -> dict:
        if "m2c" in command[0]:
            return {"command": command, "exitCode": 0, "stdout": "void target(void) { volatile int x = 1; x = x + 1; }", "stderr": ""}
        return {"command": command, "exitCode": 1, "stdout": "{}", "stderr": "mismatch"}

    config = RunPipelineConfig(
        prompts_dir=prompts_dir,
        out_dir=tmp_path / "out",
        compiler_script=_compiler_script(),
        project_root=tmp_path,
        max_retries=1,
    )

    receipt = run_prompts_pipeline(config, command_runner=runner)

    assert receipt["status"] == "complete"
    report = json.loads(Path(receipt["reportPath"]).read_text(encoding="utf-8"))
    assert report["summary"]["totalPrompts"] == 1
    assert len(report["results"]) == 1
