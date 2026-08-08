"""Tests for integrator_worktree.py against real git repositories.

This repo does not mock subprocess, so every test here builds a throwaway git
repository under tmp_path and runs the real `git` binary. The `gh` path is
exercised through the injectable runner seam instead, since a PR cannot be
opened against a local repo.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from agentdecompile_recovery.integrator_worktree import (
    CommandResult,
    GitError,
    commit_changes,
    create_worktree,
    open_pull_request,
    push_branch,
    render_template,
    submodule_paths,
    worktree_base_dir,
)

pytestmark = pytest.mark.unit


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=str(repo), capture_output=True, text=True, check=True, timeout=60)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A git repo with one commit, isolated from the developer's git config."""

    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    (root / "src" / "math.c").write_text('INCLUDE_ASM("asm/math", target_func);\n', encoding="utf-8")
    _git(root, "init", "-b", "main")
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "user.name", "Test")
    _git(root, "add", "-A")
    _git(root, "commit", "-m", "initial")
    return root


class TestRenderTemplate:
    def test_substitutes_every_placeholder_occurrence(self):
        rendered = render_template("{{a}}/{{b}}/{{a}}", a="x", b="y")
        assert rendered == "x/y/x"

    def test_leaves_unknown_placeholders_untouched(self):
        assert render_template("{{keep}}", other="v") == "{{keep}}"


class TestCreateWorktree:
    def test_creates_a_worktree_on_the_requested_branch(self, repo: Path, tmp_path: Path):
        worktree = create_worktree(repo, "agentdecompile/target_func", base_dir=tmp_path / "wt")

        assert worktree.branch == "agentdecompile/target_func"
        assert worktree.path.is_dir()
        assert (worktree.path / "src" / "math.c").is_file()

    def test_worktree_is_branched_from_head_not_the_working_tree(self, repo: Path, tmp_path: Path):
        # Uncommitted change in the main tree must not appear in the worktree.
        (repo / "src" / "math.c").write_text("void dirty(void) {}\n", encoding="utf-8")

        worktree = create_worktree(repo, "wt/branch", base_dir=tmp_path / "wt")

        assert "INCLUDE_ASM" in (worktree.path / "src" / "math.c").read_text(encoding="utf-8")

    def test_appends_an_index_when_the_branch_already_exists(self, repo: Path, tmp_path: Path):
        base = tmp_path / "wt"
        first = create_worktree(repo, "agentdecompile/dup", base_dir=base)
        second = create_worktree(repo, "agentdecompile/dup", base_dir=base)

        assert first.branch == "agentdecompile/dup"
        assert second.branch == "agentdecompile/dup-1"
        assert first.path != second.path

    def test_slashes_in_the_branch_become_dashes_in_the_path(self, repo: Path, tmp_path: Path):
        worktree = create_worktree(repo, "a/b/c", base_dir=tmp_path / "wt")

        assert worktree.path.name == "a-b-c"

    def test_recovers_when_a_stale_directory_blocks_the_path(self, repo: Path, tmp_path: Path):
        base = tmp_path / "wt"
        stale = worktree_base_dir(base) / "agentdecompile-stale"
        stale.mkdir(parents=True)
        (stale / "leftover.txt").write_text("from an interrupted run", encoding="utf-8")

        worktree = create_worktree(repo, "agentdecompile/stale", base_dir=base)

        assert worktree.path == stale
        assert not (stale / "leftover.txt").exists()

    def test_raises_git_error_when_the_project_is_not_a_repository(self, tmp_path: Path):
        not_a_repo = tmp_path / "plain"
        not_a_repo.mkdir()

        with pytest.raises(GitError):
            create_worktree(not_a_repo, "branch", base_dir=tmp_path / "wt")

    def test_default_base_dir_is_under_the_temp_directory(self):
        assert worktree_base_dir().name == "agentdecompile-integrator"


class TestCommitChanges:
    def test_commits_worktree_changes_and_returns_a_short_hash(self, repo: Path, tmp_path: Path):
        worktree = create_worktree(repo, "wt/commit", base_dir=tmp_path / "wt")
        (worktree.path / "src" / "math.c").write_text("void target_func(void) {}\n", encoding="utf-8")

        commit_hash = commit_changes(worktree.path, "match target_func")

        assert commit_hash
        log = subprocess.run(
            ["git", "log", "-1", "--format=%s"],
            cwd=str(worktree.path),
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        )
        assert log.stdout.strip() == "match target_func"

    def test_commit_message_with_quotes_survives_verbatim(self, repo: Path, tmp_path: Path):
        # argv, not a shell string -- upstream escapes quotes into a shell
        # command and can mangle them.
        worktree = create_worktree(repo, "wt/quotes", base_dir=tmp_path / "wt")
        (worktree.path / "new.txt").write_text("x", encoding="utf-8")
        message = 'match "target_func" $(whoami)'

        commit_changes(worktree.path, message)

        log = subprocess.run(
            ["git", "log", "-1", "--format=%s"],
            cwd=str(worktree.path),
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        )
        assert log.stdout.strip() == message

    def test_raises_git_error_when_there_is_nothing_to_commit(self, repo: Path, tmp_path: Path):
        worktree = create_worktree(repo, "wt/empty", base_dir=tmp_path / "wt")

        with pytest.raises(GitError):
            commit_changes(worktree.path, "no changes")


class TestSubmodulePaths:
    def test_returns_empty_when_there_is_no_gitmodules(self, tmp_path: Path):
        assert submodule_paths(tmp_path) == []

    def test_parses_every_declared_submodule_path(self, tmp_path: Path):
        (tmp_path / ".gitmodules").write_text(
            '[submodule "tools/compiler"]\n'
            "\tpath = tools/compiler\n"
            "\turl = https://example.invalid/c.git\n"
            '[submodule "vendor/m2c"]\n'
            "\tpath = vendor/m2c\n"
            "\turl = https://example.invalid/m.git\n",
            encoding="utf-8",
        )

        assert submodule_paths(tmp_path) == ["tools/compiler", "vendor/m2c"]


class TestRemoteActions:
    def test_push_uses_the_upstream_tracking_form(self, tmp_path: Path):
        seen: list[list[str]] = []

        def runner(command: list[str], cwd: Path, timeout: float) -> CommandResult:
            seen.append(command)
            return CommandResult(0, "", "")

        push_branch(tmp_path, "agentdecompile/f", runner=runner)

        assert seen == [["git", "push", "-u", "origin", "agentdecompile/f"]]

    def test_push_failure_surfaces_stderr_in_the_git_error(self, tmp_path: Path):
        def runner(command: list[str], cwd: Path, timeout: float) -> CommandResult:
            return CommandResult(1, "", "remote rejected")

        with pytest.raises(GitError, match="remote rejected"):
            push_branch(tmp_path, "b", runner=runner)

    def test_open_pull_request_passes_templates_and_returns_the_url(self, tmp_path: Path):
        seen: list[list[str]] = []

        def runner(command: list[str], cwd: Path, timeout: float) -> CommandResult:
            seen.append(command)
            return CommandResult(0, "https://example.invalid/pr/1\n", "")

        url = open_pull_request(tmp_path, "b", title="Match f", body="Matched `f`.", runner=runner)

        assert url == "https://example.invalid/pr/1"
        assert seen[0] == [
            "gh",
            "pr",
            "create",
            "--head",
            "b",
            "--title",
            "Match f",
            "--body",
            "Matched `f`.",
        ]
