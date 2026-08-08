"""Tests for prompt_loader.py, ported from the upstream prompt-loader spec.

Uses the real system `gcc`/`nm` to produce a genuine object file rather than
the upstream's fixture cross-compiler toolchain (not present in this repo) --
what matters for this module is nm-output parsing, not any particular ISA.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from agentdecompile_recovery import prompt_loader
from agentdecompile_recovery.prompt_loader import PromptLoadError, load_prompts

pytestmark = pytest.mark.unit

_HAS_GCC = shutil.which("gcc") is not None or shutil.which("cc") is not None


def _compile(tmp_path: Path, function_name: str) -> Path:
    c_path = tmp_path / f"{function_name}.c"
    obj_path = tmp_path / f"{function_name}.o"
    c_path.write_text(f"void {function_name}(void) {{ volatile int x = 1; x = x + 1; }}\n", encoding="utf-8")
    compiler = shutil.which("gcc") or shutil.which("cc")
    subprocess.run([compiler, "-c", str(c_path), "-o", str(obj_path)], check=True, capture_output=True)
    return obj_path


def _record_nm_calls(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """Record every `nm` argv the loader runs, while still running the real `nm`.

    Rebinds only the `subprocess` name inside prompt_loader -- the stdlib module
    itself is untouched -- so the loader keeps parsing genuine nm output and
    nothing here mocks the subprocess away.
    """
    calls: list[list[str]] = []

    def counting_run(args, **kwargs):
        if list(args)[:1] == ["nm"]:
            calls.append(list(args))
        return subprocess.run(args, **kwargs)

    monkeypatch.setattr(prompt_loader, "subprocess", SimpleNamespace(run=counting_run, TimeoutExpired=subprocess.TimeoutExpired))
    return calls


def _write_prompt_dir(prompts_dir: Path, dir_name: str, *, function_name: str, target_object_path: str, asm: str = "") -> Path:
    prompt_dir = prompts_dir / dir_name
    prompt_dir.mkdir(parents=True)
    (prompt_dir / "prompt.md").write_text(f"# {function_name}\n", encoding="utf-8")
    asm_block = "\n".join(f"  {line}" for line in (asm or f".text\nglabel {function_name}\n    bx lr").split("\n"))
    (prompt_dir / "settings.yaml").write_text(
        f'functionName: "{function_name}"\ntargetObjectPath: "{target_object_path}"\nasm: |\n{asm_block}\n',
        encoding="utf-8",
    )
    return prompt_dir


@pytest.mark.skipif(not _HAS_GCC, reason="requires a system C compiler")
def test_loads_a_valid_prompt_folder(tmp_path: Path):
    obj_path = _compile(tmp_path, "target_func")
    prompts_dir = tmp_path / "prompts"
    _write_prompt_dir(prompts_dir, "case1", function_name="target_func", target_object_path=str(obj_path))

    prompts, errors = load_prompts(prompts_dir)

    assert errors == []
    assert len(prompts) == 1
    assert prompts[0].function_name == "target_func"
    assert prompts[0].target_object_path == str(obj_path)
    assert prompts[0].path == "case1"


def test_reports_missing_prompt_md(tmp_path: Path):
    prompts_dir = tmp_path / "prompts"
    prompt_dir = prompts_dir / "case1"
    prompt_dir.mkdir(parents=True)
    (prompt_dir / "settings.yaml").write_text('functionName: "f"\ntargetObjectPath: "x.o"\n', encoding="utf-8")

    prompts, errors = load_prompts(prompts_dir)

    assert prompts == []
    assert len(errors) == 1
    assert isinstance(errors[0], PromptLoadError)
    assert "Missing prompt.md" in str(errors[0])


def test_reports_missing_settings_yaml(tmp_path: Path):
    prompts_dir = tmp_path / "prompts"
    prompt_dir = prompts_dir / "case1"
    prompt_dir.mkdir(parents=True)
    (prompt_dir / "prompt.md").write_text("hello", encoding="utf-8")

    prompts, errors = load_prompts(prompts_dir)

    assert prompts == []
    assert "Missing settings.yaml" in str(errors[0])


def test_reports_missing_target_object_file(tmp_path: Path):
    prompts_dir = tmp_path / "prompts"
    _write_prompt_dir(prompts_dir, "case1", function_name="f", target_object_path=str(tmp_path / "nope.o"))

    prompts, errors = load_prompts(prompts_dir)

    assert prompts == []
    assert "Target object file not found" in str(errors[0])


@pytest.mark.skipif(not _HAS_GCC, reason="requires a system C compiler")
def test_reports_function_not_found_in_object_file(tmp_path: Path):
    obj_path = _compile(tmp_path, "actual_func")
    prompts_dir = tmp_path / "prompts"
    _write_prompt_dir(prompts_dir, "case1", function_name="wrong_name", target_object_path=str(obj_path))

    prompts, errors = load_prompts(prompts_dir)

    assert prompts == []
    assert "not found in object file" in str(errors[0])


def test_accepts_mach_o_underscore_prefixed_symbol(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    obj_path = tmp_path / "target_func.o"
    obj_path.write_bytes(b"\x00")
    prompts_dir = tmp_path / "prompts"
    _write_prompt_dir(prompts_dir, "case1", function_name="target_func", target_object_path=str(obj_path))

    def fake_run(args, **kwargs):
        if list(args)[:1] == ["nm"]:
            return SimpleNamespace(returncode=0, stdout="00000000 T _target_func\n", stderr="")
        raise AssertionError(f"unexpected subprocess.run: {args}")

    monkeypatch.setattr(prompt_loader, "subprocess", SimpleNamespace(run=fake_run, TimeoutExpired=subprocess.TimeoutExpired))

    prompts, errors = load_prompts(prompts_dir)

    assert errors == []
    assert len(prompts) == 1
    assert prompts[0].function_name == "target_func"


@pytest.mark.skipif(not _HAS_GCC, reason="requires a system C compiler")
def test_loads_multiple_prompts_and_collects_errors_independently(tmp_path: Path):
    obj_path = _compile(tmp_path, "good_func")
    prompts_dir = tmp_path / "prompts"
    _write_prompt_dir(prompts_dir, "good", function_name="good_func", target_object_path=str(obj_path))
    bad_dir = prompts_dir / "bad"
    bad_dir.mkdir()

    prompts, errors = load_prompts(prompts_dir)

    assert len(prompts) == 1
    assert prompts[0].path == "good"
    assert len(errors) == 1
    assert errors[0].prompt_path == "bad"


@pytest.mark.skipif(not _HAS_GCC, reason="requires a system C compiler")
def test_runs_nm_once_for_prompt_folders_sharing_an_object_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    obj_path = _compile(tmp_path, "shared_func")
    prompts_dir = tmp_path / "prompts"
    for dir_name in ("case1", "case2", "case3"):
        _write_prompt_dir(prompts_dir, dir_name, function_name="shared_func", target_object_path=str(obj_path))
    nm_calls = _record_nm_calls(monkeypatch)

    prompts, errors = load_prompts(prompts_dir)

    assert errors == []
    assert len(prompts) == 3
    assert nm_calls == [["nm", str(obj_path)]]


@pytest.mark.skipif(not _HAS_GCC, reason="requires a system C compiler")
def test_runs_nm_once_per_distinct_object_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    first_obj = _compile(tmp_path, "first_func")
    second_obj = _compile(tmp_path, "second_func")
    prompts_dir = tmp_path / "prompts"
    _write_prompt_dir(prompts_dir, "case1", function_name="first_func", target_object_path=str(first_obj))
    _write_prompt_dir(prompts_dir, "case2", function_name="first_func", target_object_path=str(first_obj))
    _write_prompt_dir(prompts_dir, "case3", function_name="second_func", target_object_path=str(second_obj))
    nm_calls = _record_nm_calls(monkeypatch)

    prompts, errors = load_prompts(prompts_dir)

    assert errors == []
    assert len(prompts) == 3
    assert sorted(call[1] for call in nm_calls) == sorted([str(first_obj), str(second_obj)])


@pytest.mark.skipif(not _HAS_GCC, reason="requires a system C compiler")
def test_symbols_are_reread_when_the_object_file_is_rebuilt_between_calls(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Campaigns recompile object files between loads, so no cache may outlive one call."""
    shared_obj = tmp_path / "shared.o"
    _compile(tmp_path, "alpha_func").replace(shared_obj)
    first_dir = tmp_path / "prompts_first"
    _write_prompt_dir(first_dir, "case1", function_name="alpha_func", target_object_path=str(shared_obj))
    second_dir = tmp_path / "prompts_second"
    _write_prompt_dir(second_dir, "case1", function_name="beta_func", target_object_path=str(shared_obj))
    nm_calls = _record_nm_calls(monkeypatch)

    first_prompts, first_errors = load_prompts(first_dir)
    _compile(tmp_path, "beta_func").replace(shared_obj)
    second_prompts, second_errors = load_prompts(second_dir)

    assert first_errors == []
    assert [p.function_name for p in first_prompts] == ["alpha_func"]
    assert second_errors == []
    assert [p.function_name for p in second_prompts] == ["beta_func"]
    assert len(nm_calls) == 2


def test_failure_to_run_nm_is_retried_per_prompt_folder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A failed `nm` is never cached as an empty symbol set -- each folder retries."""
    obj_path = tmp_path / "target.o"
    obj_path.write_bytes(b"\x7fELF")
    prompts_dir = tmp_path / "prompts"
    _write_prompt_dir(prompts_dir, "case1", function_name="f", target_object_path=str(obj_path))
    _write_prompt_dir(prompts_dir, "case2", function_name="f", target_object_path=str(obj_path))
    attempts: list[list[str]] = []

    def failing_run(args, **kwargs):
        attempts.append(list(args))
        raise OSError("nm not found")

    monkeypatch.setattr(prompt_loader, "subprocess", SimpleNamespace(run=failing_run, TimeoutExpired=subprocess.TimeoutExpired))

    prompts, errors = load_prompts(prompts_dir)

    assert prompts == []
    assert len(errors) == 2
    assert all("Failed to run nm on object file" in str(err) for err in errors)
    assert len(attempts) == 2
