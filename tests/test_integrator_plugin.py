"""Tests for integrator_plugin.py — worktree isolation, build gate, auto-action chain.

Runs against real git repositories under tmp_path; this repo does not mock
subprocess. Push/PR are exercised through injected runners in
test_integrator_worktree.py, so the chain tests here stop at `commit`.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from agentdecompile_recovery.integrator_build_fix import BuildFixRequest
from agentdecompile_recovery.integrator_helpers import IntegratorError
from agentdecompile_recovery.integrator_plugin import (
    IntegratorConfig,
    IntegratorPlugin,
    load_integrator_module,
)

pytestmark = pytest.mark.unit


def _write_integrator_module(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=str(repo), capture_output=True, text=True, check=True, timeout=60)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    (root / "src" / "math.c").write_text('INCLUDE_ASM("asm/math", target_func);\n', encoding="utf-8")
    _git(root, "init", "-b", "main")
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "user.name", "Test")
    _git(root, "add", "-A")
    _git(root, "commit", "-m", "initial")
    return root


def _config(repo: Path, tmp_path: Path, module_body: str, **overrides) -> IntegratorConfig:
    module_path = _write_integrator_module(tmp_path / "mod.py", module_body)
    defaults: dict = dict(
        integrator_module=module_path,
        worktree_base_dir=tmp_path / "wt",
        timestamp="2026-01-01T00-00-00",
    )
    defaults.update(overrides)
    return IntegratorConfig(**defaults)


REPLACE_STUB = (
    "def integrate(*, function_name, generated_code, worktree_path, project_root, helpers):\n"
    "    file_path = helpers.find_source_file(function_name)\n"
    "    helpers.replace_include_asm(file_path, function_name, generated_code)\n"
    "    return {'filesModified': [str(file_path)], 'summary': f'Integrated {function_name}'}\n"
)

# A minimal but *realistic* integrator: it changes something, so the commit
# stage has work to do. NO_CHANGES below is the deliberate no-op counterpart.
NOOP = (
    "def integrate(*, worktree_path, generated_code, **kwargs):\n"
    "    (worktree_path / 'landed.c').write_text(generated_code, encoding='utf-8')\n"
    "    return {'filesModified': ['landed.c'], 'summary': 'ok'}\n"
)

NO_CHANGES = "def integrate(**kwargs):\n    return {'filesModified': [], 'summary': 'ok'}\n"

TOUCH = (
    "def integrate(*, function_name, generated_code, worktree_path, project_root, helpers):\n"
    "    (worktree_path / 'landed.c').write_text(generated_code, encoding='utf-8')\n"
    "    return {'filesModified': ['landed.c'], 'summary': 'wrote landed.c'}\n"
)

CONTEXT = {"functionName": "target_func", "generatedCode": "void target_func(void) {}"}


class TestLoadIntegratorModule:
    def test_raises_when_integrate_is_missing(self, tmp_path: Path):
        module_path = _write_integrator_module(tmp_path / "no_integrate.py", "x = 1\n")

        with pytest.raises(IntegratorError, match="does not export"):
            load_integrator_module(module_path)

    def test_returns_a_callable_integrate(self, tmp_path: Path):
        module_path = _write_integrator_module(tmp_path / "mod.py", NOOP)

        assert callable(load_integrator_module(module_path).integrate)


class TestIntegratorConfig:
    def test_rejects_an_unknown_auto_action(self, tmp_path: Path):
        with pytest.raises(ValueError, match="auto_action"):
            IntegratorConfig(integrator_module=tmp_path / "mod.py", auto_action="merge")

    @pytest.mark.parametrize("action", ["commit", "push", "pr"])
    def test_accepts_each_documented_auto_action(self, tmp_path: Path, action: str):
        assert IntegratorConfig(integrator_module=tmp_path / "mod.py", auto_action=action).auto_action == action


class TestPreconditions:
    def test_fails_when_no_generated_code_in_context(self, repo: Path, tmp_path: Path):
        plugin = IntegratorPlugin(_config(repo, tmp_path, NOOP), repo)

        result, _context = plugin.execute({"functionName": "f"})

        assert result.status == "failure"
        assert "No generated code" in result.error

    def test_fails_cleanly_when_the_project_is_not_a_git_repository(self, tmp_path: Path):
        plain = tmp_path / "plain"
        plain.mkdir()
        plugin = IntegratorPlugin(_config(plain, tmp_path, NOOP), plain)

        result, _context = plugin.execute(dict(CONTEXT))

        assert result.status == "failure"
        assert "worktree" in result.error


class TestWorktreeIsolation:
    def test_integration_happens_in_the_worktree_not_the_main_tree(self, repo: Path, tmp_path: Path):
        plugin = IntegratorPlugin(_config(repo, tmp_path, REPLACE_STUB), repo)

        result, _context = plugin.execute(dict(CONTEXT))

        assert result.status == "success"
        # The operator's working tree is untouched...
        assert "INCLUDE_ASM" in (repo / "src" / "math.c").read_text(encoding="utf-8")
        # ...while the worktree carries the landed code.
        worktree = Path(result.data["worktreePath"])
        assert (worktree / "src" / "math.c").read_text(encoding="utf-8") == "void target_func(void) {}\n"

    def test_branch_name_renders_the_function_name_template(self, repo: Path, tmp_path: Path):
        plugin = IntegratorPlugin(_config(repo, tmp_path, NOOP, branch_template="fix/{{functionName}}"), repo)

        result, _context = plugin.execute(dict(CONTEXT))

        assert result.data["branchName"] == "fix/target_func"

    def test_branch_template_can_use_the_timestamp(self, repo: Path, tmp_path: Path):
        config = _config(repo, tmp_path, NOOP, branch_template="run/{{functionName}}-{{timestamp}}")
        plugin = IntegratorPlugin(config, repo)

        result, _context = plugin.execute(dict(CONTEXT))

        assert result.data["branchName"] == "run/target_func-2026-01-01T00-00-00"

    def test_the_module_receives_both_worktree_and_project_root(self, repo: Path, tmp_path: Path):
        module = (
            "def integrate(*, function_name, generated_code, worktree_path, project_root, helpers):\n"
            "    (worktree_path / 'paths.txt').write_text(f'{worktree_path}|{project_root}', encoding='utf-8')\n"
            "    return {'filesModified': ['paths.txt'], 'summary': 'ok'}\n"
        )
        plugin = IntegratorPlugin(_config(repo, tmp_path, module), repo)

        result, _context = plugin.execute(dict(CONTEXT))

        worktree = Path(result.data["worktreePath"])
        recorded = (worktree / "paths.txt").read_text(encoding="utf-8")
        assert recorded == f"{worktree}|{repo}"

    def test_a_module_written_for_the_old_signature_still_works(self, repo: Path, tmp_path: Path):
        legacy = (
            "def integrate(*, function_name, generated_code, project_root, helpers):\n"
            "    (helpers.root / 'legacy.c').write_text(generated_code, encoding='utf-8')\n"
            "    return {'filesModified': ['legacy.c'], 'summary': 'legacy ok'}\n"
        )
        plugin = IntegratorPlugin(_config(repo, tmp_path, legacy), repo)

        result, _context = plugin.execute(dict(CONTEXT))

        assert result.status == "success"
        assert result.data["integrationSummary"] == "legacy ok"
        # Even the legacy signature gets worktree-rooted helpers.
        assert (Path(result.data["worktreePath"]) / "legacy.c").is_file()
        assert not (repo / "legacy.c").exists()

    def test_helpers_are_rooted_at_the_worktree(self, repo: Path, tmp_path: Path):
        module = (
            "def integrate(*, function_name, generated_code, worktree_path, project_root, helpers):\n"
            "    assert helpers.root == worktree_path\n"
            "    (worktree_path / 'ok.c').write_text('x', encoding='utf-8')\n"
            "    return {'filesModified': ['ok.c'], 'summary': 'ok'}\n"
        )
        plugin = IntegratorPlugin(_config(repo, tmp_path, module), repo)

        assert plugin.execute(dict(CONTEXT))[0].status == "success"

    def test_a_module_that_changes_nothing_is_reported_as_a_silent_no_op(self, repo: Path, tmp_path: Path):
        plugin = IntegratorPlugin(_config(repo, tmp_path, NO_CHANGES), repo)

        result, _context = plugin.execute(dict(CONTEXT))

        assert result.status == "failure"
        assert "modified no files" in result.error
        assert "commitHash" not in result.data

    def test_propagates_integration_errors_as_plugin_failure(self, repo: Path, tmp_path: Path):
        module = (
            "from agentdecompile_recovery.integrator_helpers import IntegratorError\n"
            "def integrate(**kwargs):\n"
            "    raise IntegratorError('stub not found')\n"
        )
        plugin = IntegratorPlugin(_config(repo, tmp_path, module), repo)

        result, _context = plugin.execute(dict(CONTEXT))

        assert result.status == "failure"
        assert "stub not found" in result.error
        assert result.data["integrationSuccess"] is False

    def test_the_worktree_is_left_on_disk_after_a_failure(self, repo: Path, tmp_path: Path):
        module = (
            "from agentdecompile_recovery.integrator_helpers import IntegratorError\n"
            "def integrate(**kwargs):\n"
            "    raise IntegratorError('boom')\n"
        )
        plugin = IntegratorPlugin(_config(repo, tmp_path, module), repo)

        result, _context = plugin.execute(dict(CONTEXT))

        assert Path(result.data["worktreePath"]).is_dir()


class TestBuildVerification:
    def test_verify_build_script_runs_inside_the_worktree(self, repo: Path, tmp_path: Path):
        config = _config(repo, tmp_path, TOUCH, verify_build_script="cat landed.c")
        plugin = IntegratorPlugin(config, repo)

        result, _context = plugin.execute(dict(CONTEXT))

        assert result.status == "success"
        assert "void target_func(void) {}" in result.data["buildOutput"]

    def test_worktree_path_template_is_substituted(self, repo: Path, tmp_path: Path):
        config = _config(repo, tmp_path, NOOP, verify_build_script="test -d {{worktreePath}} && echo present")
        plugin = IntegratorPlugin(config, repo)

        result, _context = plugin.execute(dict(CONTEXT))

        assert result.status == "success"
        assert "present" in result.data["buildOutput"]

    def test_a_failing_build_blocks_the_commit(self, repo: Path, tmp_path: Path):
        config = _config(repo, tmp_path, TOUCH, verify_build_script="exit 1")
        plugin = IntegratorPlugin(config, repo)

        result, _context = plugin.execute(dict(CONTEXT))

        assert result.status == "failure"
        assert "Build verification failed" in result.error
        assert result.data["integrationSuccess"] is True
        assert result.data["buildPassed"] is False
        assert "commitHash" not in result.data

    def test_ai_build_fix_is_not_attempted_when_disabled(self, repo: Path, tmp_path: Path):
        config = _config(repo, tmp_path, TOUCH, verify_build_script="exit 1", ai_build_fix_enable=False)
        plugin = IntegratorPlugin(config, repo)

        result, _context = plugin.execute(dict(CONTEXT))

        assert "aiBuildFix" not in result.data

    def test_a_successful_ai_build_fix_unblocks_the_commit(self, repo: Path, tmp_path: Path):
        flag = tmp_path / "fixed.flag"
        config = _config(
            repo,
            tmp_path,
            TOUCH,
            verify_build_script=f"test -f {flag}",
            ai_build_fix_enable=True,
        )

        def fixer(request: BuildFixRequest) -> list[dict[str, str]]:
            flag.write_text("done", encoding="utf-8")
            return [{"role": "assistant", "content": "dropped the duplicate decl"}]

        plugin = IntegratorPlugin(config, repo, build_fixer=fixer)

        result, _context = plugin.execute(dict(CONTEXT))

        assert result.status == "success"
        assert result.data["aiBuildFix"] == {"attempted": True, "fixed": True}
        assert result.data["commitHash"]

    def test_an_unsuccessful_ai_build_fix_still_fails_the_phase(self, repo: Path, tmp_path: Path):
        config = _config(repo, tmp_path, TOUCH, verify_build_script="exit 1", ai_build_fix_enable=True)
        plugin = IntegratorPlugin(config, repo, build_fixer=lambda request: [])

        result, _context = plugin.execute(dict(CONTEXT))

        assert result.status == "failure"
        assert "AI fix attempted but unsuccessful" in result.error
        assert result.data["aiBuildFix"] == {"attempted": True, "fixed": False}


class TestAutoActionChain:
    def test_commit_is_the_default_and_records_a_hash(self, repo: Path, tmp_path: Path):
        plugin = IntegratorPlugin(_config(repo, tmp_path, TOUCH), repo)

        result, _context = plugin.execute(dict(CONTEXT))

        assert result.status == "success"
        assert result.data["commitHash"]
        assert "pushed" not in result.data
        assert "prUrl" not in result.data

    def test_commit_message_template_is_rendered(self, repo: Path, tmp_path: Path):
        config = _config(repo, tmp_path, TOUCH, commit_message_template="land {{functionName}}")
        plugin = IntegratorPlugin(config, repo)

        result, _context = plugin.execute(dict(CONTEXT))

        worktree = Path(result.data["worktreePath"])
        log = subprocess.run(
            ["git", "log", "-1", "--format=%s"],
            cwd=str(worktree),
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        )
        assert log.stdout.strip() == "land target_func"

    def test_the_commit_lands_on_the_integration_branch_only(self, repo: Path, tmp_path: Path):
        plugin = IntegratorPlugin(_config(repo, tmp_path, TOUCH), repo)

        result, _context = plugin.execute(dict(CONTEXT))

        main_log = subprocess.run(
            ["git", "log", "--format=%s", "main"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        )
        assert main_log.stdout.strip() == "initial"
        assert result.data["branchName"] != "main"

    def test_a_push_failure_stops_the_chain_and_reports_it(self, repo: Path, tmp_path: Path):
        # No `origin` remote is configured, so the push must fail.
        config = _config(repo, tmp_path, TOUCH, auto_action="push")
        plugin = IntegratorPlugin(config, repo)

        result, _context = plugin.execute(dict(CONTEXT))

        assert result.status == "failure"
        assert "Failed to push" in result.error
        assert result.data["commitHash"]
        assert "prUrl" not in result.data


class TestReportSections:
    def test_success_emits_a_summary_section(self, repo: Path, tmp_path: Path):
        plugin = IntegratorPlugin(_config(repo, tmp_path, TOUCH), repo)

        result, _context = plugin.execute(dict(CONTEXT))

        titles = [section["title"] for section in result.sections]
        assert "Integration Summary" in titles
        assert "Integration Script Output" in titles
        summary = next(s for s in result.sections if s["title"] == "Integration Summary")
        assert "Integration: Success" in summary["message"]
        assert "landed.c" in summary["message"]

    def test_build_output_becomes_a_code_section(self, repo: Path, tmp_path: Path):
        config = _config(repo, tmp_path, TOUCH, verify_build_script="echo compiled")
        plugin = IntegratorPlugin(config, repo)

        result, _context = plugin.execute(dict(CONTEXT))

        build_section = next(s for s in result.sections if s["title"] == "Build Verification Output")
        assert build_section["type"] == "code"
        assert "compiled" in build_section["code"]

    def test_failure_emits_an_error_section(self, repo: Path, tmp_path: Path):
        config = _config(repo, tmp_path, TOUCH, verify_build_script="exit 1")
        plugin = IntegratorPlugin(config, repo)

        result, _context = plugin.execute(dict(CONTEXT))

        assert any(s["title"] == "Error" for s in result.sections)

    def test_a_build_fix_transcript_becomes_a_chat_section(self, repo: Path, tmp_path: Path):
        flag = tmp_path / "fixed.flag"
        config = _config(
            repo, tmp_path, TOUCH, verify_build_script=f"test -f {flag}", ai_build_fix_enable=True
        )

        def fixer(request: BuildFixRequest) -> list[dict[str, str]]:
            flag.write_text("done", encoding="utf-8")
            return [{"role": "assistant", "content": "removed the dup"}]

        plugin = IntegratorPlugin(config, repo, build_fixer=fixer)

        result, _context = plugin.execute(dict(CONTEXT))

        chat = next(s for s in result.sections if s["title"] == "AI Build Fix")
        assert chat["messages"][0]["content"] == "removed the dup"


class TestBackwardCompatibleConstructor:
    def test_positional_module_and_build_command_still_work(self, repo: Path, tmp_path: Path):
        module_path = _write_integrator_module(tmp_path / "mod.py", NOOP)
        plugin = IntegratorPlugin(module_path, repo, build_command="echo build-succeeded")

        result, _context = plugin.execute(dict(CONTEXT))

        assert result.status == "success"
        assert "build-succeeded" in result.data["buildOutput"]
