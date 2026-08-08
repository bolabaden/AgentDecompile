"""Build verification, and the optional AI build-fix seam, for the integrator.

Ports upstream's `build-fixer.ts`: after the integrator module places matched C
code, run the project's verification build; if it fails, optionally hand the
error to a model that can edit the worktree and re-run the build.

**Deliberate deviation from upstream, for a security reason.** Upstream spawns
an Agent SDK session with `allowedTools: ['Read','Edit','Bash','Glob','Grep']`
and `permissionMode: 'dontAsk'` scoped to the worktree. This repo takes the
opposite position on model tool access for binary-derived content -- see
rewrite_provider.py's module docstring: context here embeds decompiler output
and disassembly recovered from an untrusted binary, and that content is not
trusted at face value. Granting `Bash` + `Edit` to a session whose prompt
carries it is exactly the exposure that posture exists to prevent.

So the fix step is an injected `BuildFixer` callable and **defaults to
disabled**. The contract, prompt content, re-verification, and result shape all
match upstream; only the decision to grant an agent write access to the
worktree is moved out of this module and made an explicit operator act.

`run_verify_build` is shared with the plugin: upstream duplicates the same
script-writing logic in both `integrator-plugin.ts` and `build-fixer.ts`.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

DEFAULT_BUILD_TIMEOUT_SECONDS = 300.0
DEFAULT_FIX_TIMEOUT_SECONDS = 300.0


@dataclass(frozen=True)
class BuildResult:
    passed: bool
    output: str


@dataclass
class BuildFixRequest:
    """Everything a fixer needs to diagnose the failure, mirroring BuildFixOptions."""

    worktree_path: Path
    build_error: str
    files_modified: list[str]
    function_name: str
    generated_code: str
    verify_build_command: str
    timeout_seconds: float = DEFAULT_FIX_TIMEOUT_SECONDS
    model: str | None = None


@dataclass
class BuildFixResult:
    attempted: bool
    fixed: bool
    build_output: str
    system_prompt: str = ""
    chat_history: list[dict[str, str]] = field(default_factory=list)


#: A fixer edits the worktree in place and returns a transcript. It does not
#: decide success -- `attempt_build_fix` always re-runs the real build after.
BuildFixer = Callable[[BuildFixRequest], list[dict[str, str]]]


def run_verify_build(
    worktree_path: Path,
    verify_build_script: str,
    *,
    timeout: float = DEFAULT_BUILD_TIMEOUT_SECONDS,
) -> BuildResult:
    """Run the verification script inside the worktree.

    `set -e` is prepended so any failing command aborts the build, matching the
    documented contract. The script is written to a temp file rather than passed
    with `-c` because verification scripts are routinely multi-line.
    """

    tmp_dir = Path(tempfile.mkdtemp(prefix="agentdecompile-verify-"))
    script_path = tmp_dir / "verify-build.sh"
    script_path.write_text("set -e\n" + verify_build_script, encoding="utf-8")
    bash = shutil.which("bash") or "bash"

    try:
        completed = subprocess.run(
            [bash, str(script_path)],
            cwd=str(worktree_path),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return BuildResult(False, f"build verification timed out after {timeout}s")
    except OSError as exc:
        return BuildResult(False, f"could not run build verification: {exc}")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    output = "\n".join(part for part in (completed.stdout, completed.stderr) if part).strip()
    return BuildResult(completed.returncode == 0, output)


def build_fix_prompt(request: BuildFixRequest) -> str:
    """Port of upstream `buildSystemPrompt` -- same sections, same guidance."""

    files_modified_list = "\n".join(f"- {name}" for name in request.files_modified)
    return f"""You are fixing build errors that occurred after integrating decompiled C code into a decompilation project.

## What happened
The function `{request.function_name}` was successfully decompiled and its code was integrated into the project, but the build verification failed.

## Files modified during integration
{files_modified_list}

## The code that was integrated
```c
{request.generated_code}
```

## Build error output
```
{request.build_error}
```

## Common issues
- Duplicate extern/forward declarations (the integrated code added a declaration that already exists in the file, possibly with a different signature)
- Symbol conflicts between the new decompiled function and existing non-matching assembly
- Missing or conflicting type definitions

## Your task
1. Diagnose the build error
2. Fix the source files to resolve the error
3. Run the build to verify:
```
{request.verify_build_command}
```
4. Only modify files that are necessary to fix the build
5. Do not change the logic of the decompiled function itself"""


def attempt_build_fix(request: BuildFixRequest, *, fixer: BuildFixer | None = None) -> BuildFixResult:
    """Run `fixer` over the worktree, then re-verify the build for real.

    Success is decided by re-running the build, never by the fixer's own claim
    -- same as upstream, and the same reason the rest of this pipeline treats a
    model's output as an unverified candidate. A fixer that raises is recorded
    in the transcript and the build is still re-run, so a broken fixer degrades
    to "no fix applied" rather than failing the post-match phase outright.
    """

    system_prompt = build_fix_prompt(request)

    if fixer is None:
        return BuildFixResult(
            attempted=False,
            fixed=False,
            build_output=request.build_error,
            system_prompt=system_prompt,
        )

    chat_history: list[dict[str, str]] = []
    try:
        chat_history = list(fixer(request))
    except Exception as exc:  # noqa: BLE001 - a broken fixer must not abort the phase
        chat_history = [{"role": "error", "content": f"Build fix error: {exc}"}]

    verified = run_verify_build(
        request.worktree_path,
        request.verify_build_command,
        timeout=DEFAULT_BUILD_TIMEOUT_SECONDS,
    )
    return BuildFixResult(
        attempted=True,
        fixed=verified.passed,
        build_output=verified.output,
        system_prompt=system_prompt,
        chat_history=chat_history,
    )
