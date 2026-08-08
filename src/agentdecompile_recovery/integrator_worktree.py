"""Git worktree lifecycle for the integrator plugin's post-match handoff.

Ports the git plumbing embedded in the upstream integrator plugin
(`#createWorktree`, `#commitChanges`, `#pushBranch`, `#openPullRequest`).
Integration runs in a worktree branched from HEAD so a matched function can be
landed, built, and reviewed without ever touching the operator's working tree.

Upstream keeps these as private methods on the plugin class. They are a module
here because they are pure git mechanics with no plugin state, they are the
part most worth testing directly against a real repository, and the plugin
stays readable when its `execute` is a phase sequence rather than a mix of
phases and `git` argv construction.

Every function takes an injectable `runner`. The default runs real `git`/`gh`
-- this repo does not mock subprocess -- so tests build throwaway repositories
in `tmp_path` and exercise the real binary.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

#: Worktrees live under one shared parent so `git worktree prune` and manual
#: cleanup have a single predictable place to look.
WORKTREE_DIR_NAME = "agentdecompile-integrator"

DEFAULT_GIT_TIMEOUT_SECONDS = 60.0
DEFAULT_PUSH_TIMEOUT_SECONDS = 60.0
DEFAULT_PR_TIMEOUT_SECONDS = 30.0

#: Upstream tries the requested branch then appends -1..-100 before giving up.
MAX_BRANCH_ATTEMPTS = 100

_SUBMODULE_PATH_RE = re.compile(r"^\s*path\s*=\s*(.+)$", re.MULTILINE)


class GitError(RuntimeError):
    """A git/gh invocation failed, or the requested worktree cannot be made."""


class NothingToCommitError(GitError):
    """The integrator module reported success but left the worktree unchanged.

    Upstream lets git's raw "nothing to commit, working tree clean" surface as a
    generic commit failure, which reads like a git problem. It is not: it means
    the integrator module silently did nothing, which is the more useful thing
    to say.
    """


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


Runner = Callable[[list[str], Path, float], CommandResult]


def _subprocess_runner(command: list[str], cwd: Path, timeout: float) -> CommandResult:
    completed = subprocess.run(
        command,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return CommandResult(completed.returncode, completed.stdout, completed.stderr)


def _run(
    command: list[str],
    cwd: Path,
    *,
    runner: Runner | None,
    timeout: float = DEFAULT_GIT_TIMEOUT_SECONDS,
    check: bool = True,
) -> CommandResult:
    execute = runner or _subprocess_runner
    try:
        result = execute(command, cwd, timeout)
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"{' '.join(command)} timed out after {timeout}s") from exc
    except OSError as exc:
        raise GitError(f"could not run {' '.join(command)}: {exc}") from exc

    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise GitError(f"{' '.join(command)} exited {result.returncode}: {detail}")
    return result


@dataclass(frozen=True)
class Worktree:
    path: Path
    branch: str


def render_template(template: str, **values: str) -> str:
    """Substitute `{{name}}` placeholders, upstream's template syntax."""

    rendered = template
    for key, value in values.items():
        rendered = rendered.replace("{{" + key + "}}", value)
    return rendered


def worktree_base_dir(base_dir: Path | None = None) -> Path:
    return (base_dir or Path(tempfile.gettempdir())) / WORKTREE_DIR_NAME


def create_worktree(
    project_root: Path,
    branch_name: str,
    *,
    base_dir: Path | None = None,
    runner: Runner | None = None,
) -> Worktree:
    """Create a worktree branched from HEAD, indexing the branch on collision.

    Mirrors upstream: try `branch_name`, then `branch_name-1` .. `-100`. A
    leftover directory at the target path is removed first -- an interrupted
    earlier run leaves one behind, and `git worktree add` refuses a non-empty
    path, so without this a single crash would poison that branch name forever.
    """

    base = worktree_base_dir(base_dir)
    base.mkdir(parents=True, exist_ok=True)

    for attempt in range(MAX_BRANCH_ATTEMPTS + 1):
        actual_branch = branch_name if attempt == 0 else f"{branch_name}-{attempt}"
        worktree_path = base / actual_branch.replace("/", "-")

        if worktree_path.exists():
            _remove_stale_worktree(project_root, worktree_path, runner=runner)

        result = _run(
            ["git", "worktree", "add", "-b", actual_branch, str(worktree_path), "HEAD"],
            project_root,
            runner=runner,
            check=False,
        )
        if result.returncode == 0:
            return Worktree(path=worktree_path, branch=actual_branch)

        detail = (result.stderr or result.stdout or "").strip()
        if "already exists" in detail:
            continue
        raise GitError(f"failed to create git worktree: {detail}")

    raise GitError(
        f'failed to create worktree: branch name "{branch_name}" and '
        f"{MAX_BRANCH_ATTEMPTS} alternatives are all taken"
    )


def _remove_stale_worktree(project_root: Path, worktree_path: Path, *, runner: Runner | None) -> None:
    """Best-effort removal; a stale path must never abort the run."""

    result = _run(
        ["git", "worktree", "remove", "--force", str(worktree_path)],
        project_root,
        runner=runner,
        check=False,
    )
    if result.returncode == 0:
        return

    shutil.rmtree(worktree_path, ignore_errors=True)
    _run(["git", "worktree", "prune"], project_root, runner=runner, check=False)


def submodule_paths(worktree_path: Path) -> list[str]:
    gitmodules = worktree_path / ".gitmodules"
    if not gitmodules.is_file():
        return []
    content = gitmodules.read_text(encoding="utf-8", errors="replace")
    return [match.group(1).strip() for match in _SUBMODULE_PATH_RE.finditer(content)]


def commit_changes(
    worktree_path: Path,
    commit_message: str,
    *,
    runner: Runner | None = None,
) -> str:
    """Stage everything, restore submodule gitlinks, commit, return short SHA.

    The gitlink restore is upstream behaviour worth keeping: an integrator
    module that symlinks submodule directories into the worktree (the doc's
    recommended pattern, since worktrees get empty submodule dirs) would
    otherwise have `git add -A` stage those symlinks *as symlinks*, silently
    replacing the submodule reference. Resetting each submodule path back to
    HEAD's gitlink undoes that.
    """

    _run(["git", "add", "-A"], worktree_path, runner=runner)

    for sub_path in submodule_paths(worktree_path):
        # Best-effort: the submodule may not exist in this commit.
        _run(["git", "reset", "HEAD", "--", sub_path], worktree_path, runner=runner, check=False)

    commit = _run(["git", "commit", "-m", commit_message], worktree_path, runner=runner, check=False)
    if commit.returncode != 0:
        detail = (commit.stdout or commit.stderr or "").strip()
        if "nothing to commit" in detail or "nothing added to commit" in detail:
            raise NothingToCommitError(
                "integrator module reported success but modified no files in the worktree"
            )
        raise GitError(f"git commit exited {commit.returncode}: {detail}")

    result = _run(["git", "rev-parse", "--short", "HEAD"], worktree_path, runner=runner)
    return result.stdout.strip()


def push_branch(worktree_path: Path, branch_name: str, *, runner: Runner | None = None) -> None:
    _run(
        ["git", "push", "-u", "origin", branch_name],
        worktree_path,
        runner=runner,
        timeout=DEFAULT_PUSH_TIMEOUT_SECONDS,
    )


def open_pull_request(
    worktree_path: Path,
    branch_name: str,
    *,
    title: str,
    body: str,
    runner: Runner | None = None,
) -> str:
    """Open a PR with `gh` and return the URL it prints."""

    result = _run(
        ["gh", "pr", "create", "--head", branch_name, "--title", title, "--body", body],
        worktree_path,
        runner=runner,
        timeout=DEFAULT_PR_TIMEOUT_SECONDS,
    )
    return result.stdout.strip()
