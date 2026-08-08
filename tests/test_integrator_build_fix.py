"""Tests for integrator_build_fix.py — real bash builds, injected fixer seam."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery.integrator_build_fix import (
    BuildFixRequest,
    attempt_build_fix,
    build_fix_prompt,
    run_verify_build,
)

pytestmark = pytest.mark.unit


def _request(tmp_path: Path, **overrides) -> BuildFixRequest:
    defaults = dict(
        worktree_path=tmp_path,
        build_error="math.c:3: error: redefinition of 'helper'",
        files_modified=["src/math.c"],
        function_name="target_func",
        generated_code="void target_func(void) {}",
        verify_build_command="true",
    )
    defaults.update(overrides)
    return BuildFixRequest(**defaults)  # type: ignore[arg-type]


class TestRunVerifyBuild:
    def test_passes_when_the_script_exits_zero(self, tmp_path: Path):
        result = run_verify_build(tmp_path, "echo built")

        assert result.passed
        assert "built" in result.output

    def test_fails_and_captures_output_when_the_script_exits_nonzero(self, tmp_path: Path):
        result = run_verify_build(tmp_path, "echo to-stdout\necho to-stderr >&2\nexit 3")

        assert not result.passed
        assert "to-stdout" in result.output
        assert "to-stderr" in result.output

    def test_set_e_aborts_at_the_first_failing_command(self, tmp_path: Path):
        result = run_verify_build(tmp_path, "false\necho should-not-appear")

        assert not result.passed
        assert "should-not-appear" not in result.output

    def test_runs_with_cwd_set_to_the_worktree(self, tmp_path: Path):
        (tmp_path / "marker.txt").write_text("here", encoding="utf-8")

        result = run_verify_build(tmp_path, "cat marker.txt")

        assert result.passed
        assert "here" in result.output

    def test_timeout_is_reported_as_a_failed_build(self, tmp_path: Path):
        result = run_verify_build(tmp_path, "sleep 5", timeout=0.3)

        assert not result.passed
        assert "timed out" in result.output


class TestBuildFixPrompt:
    def test_includes_the_error_the_code_and_the_verify_command(self, tmp_path: Path):
        prompt = build_fix_prompt(_request(tmp_path, verify_build_command="make compare"))

        assert "redefinition of 'helper'" in prompt
        assert "void target_func(void) {}" in prompt
        assert "make compare" in prompt
        assert "- src/math.c" in prompt


class TestAttemptBuildFix:
    def test_is_not_attempted_when_no_fixer_is_injected(self, tmp_path: Path):
        result = attempt_build_fix(_request(tmp_path))

        assert not result.attempted
        assert not result.fixed
        assert result.build_output == "math.c:3: error: redefinition of 'helper'"

    def test_reports_fixed_only_after_the_real_build_passes(self, tmp_path: Path):
        flag = tmp_path / "fixed.flag"
        request = _request(tmp_path, verify_build_command=f"test -f {flag}")

        def fixer(req: BuildFixRequest) -> list[dict[str, str]]:
            flag.write_text("done", encoding="utf-8")
            return [{"role": "assistant", "content": "removed the duplicate declaration"}]

        result = attempt_build_fix(request, fixer=fixer)

        assert result.attempted
        assert result.fixed
        assert result.chat_history[0]["content"] == "removed the duplicate declaration"

    def test_a_fixer_that_changes_nothing_is_not_reported_as_fixed(self, tmp_path: Path):
        request = _request(tmp_path, verify_build_command="exit 1")

        result = attempt_build_fix(request, fixer=lambda req: [{"role": "assistant", "content": "all good"}])

        assert result.attempted
        assert not result.fixed

    def test_a_fixer_claiming_success_cannot_override_a_failing_build(self, tmp_path: Path):
        # The build, not the model, is the acceptance gate.
        request = _request(tmp_path, verify_build_command="exit 1")

        result = attempt_build_fix(request, fixer=lambda req: [{"role": "assistant", "content": "FIXED!"}])

        assert not result.fixed

    def test_a_raising_fixer_degrades_to_no_fix_and_records_the_error(self, tmp_path: Path):
        def fixer(req: BuildFixRequest) -> list[dict[str, str]]:
            raise RuntimeError("provider unavailable")

        result = attempt_build_fix(_request(tmp_path, verify_build_command="exit 1"), fixer=fixer)

        assert result.attempted
        assert not result.fixed
        assert result.chat_history[0]["role"] == "error"
        assert "provider unavailable" in result.chat_history[0]["content"]

    def test_the_fixer_receives_the_worktree_path(self, tmp_path: Path):
        seen: list[Path] = []

        def fixer(req: BuildFixRequest) -> list[dict[str, str]]:
            seen.append(req.worktree_path)
            return []

        attempt_build_fix(_request(tmp_path), fixer=fixer)

        assert seen == [tmp_path]
