"""Post-match phase plugin: integrate a matched decompilation into project source.

Ports the upstream integrator plugin. The user supplies a Python module
(`integrator_module`) exporting an `integrate(...)` callable that uses
integrator_helpers.IntegratorHelpers to insert the matched C code into the
project's source tree (however that project's stub convention works --
INCLUDE_ASM, #pragma GLOBAL_ASM, or something else entirely). Upstream makes
the same design choice: decomp source layouts differ enough that a generic
default integrator would not be meaningful.

Lifecycle, matching the documented contract:

  1. create a git worktree branched from HEAD  (integrator_worktree.py)
  2. call the user's integrate() against that worktree
  3. optionally run verify_build_script inside it
  4. on build failure, optionally hand the errors to a build fixer
  5. commit -> push -> open PR, as far as `auto_action` says

All work happens in the worktree; the operator's working tree is never touched.
On failure the worktree is left on disk for debugging, as upstream does --
`git worktree prune` cleans up accumulated ones.

The one upstream behaviour deliberately not copied: upstream catches *any*
exception from the user module. Only IntegratorError is caught here, so a
genuine bug in an integrator module surfaces instead of being reported as a
tidy integration failure.
"""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from .integrator_build_fix import (
    DEFAULT_BUILD_TIMEOUT_SECONDS,
    DEFAULT_FIX_TIMEOUT_SECONDS,
    BuildFixer,
    BuildFixRequest,
    attempt_build_fix,
    run_verify_build,
)
from .integrator_helpers import IntegratorError, IntegratorHelpers
from .integrator_worktree import (
    GitError,
    NothingToCommitError,
    commit_changes,
    create_worktree,
    open_pull_request,
    push_branch,
    render_template,
)
from .plugin_pipeline import PluginResult, now_ms

#: How far automation goes after a successful match. Each step is additive.
AUTO_ACTIONS = ("commit", "push", "pr")


@dataclass
class IntegratorConfig:
    """Mirrors upstream's `integratorConfigSchema`."""

    integrator_module: Path
    enable: bool = True
    verify_build_script: str | None = None
    auto_action: str = "commit"
    commit_message_template: str = "match {{functionName}}"
    branch_template: str = "agentdecompile/{{functionName}}"
    pr_title_template: str = "Match {{functionName}}"
    pr_body_template: str = "Matched `{{functionName}}` via AgentDecompile."
    ai_build_fix_enable: bool = False
    ai_build_fix_timeout_seconds: float = DEFAULT_FIX_TIMEOUT_SECONDS
    ai_build_fix_model: str | None = None
    build_timeout_seconds: float = DEFAULT_BUILD_TIMEOUT_SECONDS
    worktree_base_dir: Path | None = None
    #: Names the worktree branch when `auto_action` runs; also lets tests pin a timestamp.
    timestamp: str | None = None

    def __post_init__(self) -> None:
        if self.auto_action not in AUTO_ACTIONS:
            raise ValueError(f"auto_action must be one of {AUTO_ACTIONS}, got {self.auto_action!r}")


class IntegratorModule(Protocol):
    def integrate(
        self,
        *,
        function_name: str,
        generated_code: str,
        worktree_path: Path,
        project_root: Path,
        helpers: IntegratorHelpers,
    ) -> dict[str, Any]: ...


def load_integrator_module(module_path: Path) -> IntegratorModule:
    spec = importlib.util.spec_from_file_location("agentdecompile_integrator_module", module_path)
    if spec is None or spec.loader is None:
        raise IntegratorError(f"Could not load integrator module at {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not hasattr(module, "integrate") or not callable(module.integrate):
        raise IntegratorError(f'integrator_module at {module_path} does not export an "integrate" function')
    return module


def _call_integrate(
    module: IntegratorModule,
    *,
    function_name: str,
    generated_code: str,
    worktree_path: Path,
    project_root: Path,
    helpers: IntegratorHelpers,
) -> dict[str, Any]:
    """Pass `worktree_path` when the module accepts it, else stay backward compatible.

    The documented signature takes both paths so a module can copy gitignored
    build artifacts out of `project_root` into the sparse worktree. Modules
    written against the pre-worktree signature only accept `project_root`, and
    those must keep working -- so the richer call is tried first and a
    signature-shaped TypeError falls back.
    """

    try:
        return module.integrate(
            function_name=function_name,
            generated_code=generated_code,
            worktree_path=worktree_path,
            project_root=project_root,
            helpers=helpers,
        )
    except TypeError as exc:
        if "worktree_path" not in str(exc):
            raise
        return module.integrate(  # type: ignore[call-arg]
            function_name=function_name,
            generated_code=generated_code,
            project_root=project_root,
            helpers=helpers,
        )


@dataclass
class _Outcome:
    """Accumulates the IntegratorResult payload as the phases succeed."""

    worktree_path: str
    branch_name: str
    integration_success: bool = False
    build_passed: bool = False
    files_modified: list[str] = field(default_factory=list)
    integration_summary: str = ""
    build_output: str | None = None
    commit_hash: str | None = None
    pushed: bool | None = None
    pr_url: str | None = None
    ai_build_fix: dict[str, bool] | None = None

    def to_data(self, logs: list[str]) -> dict[str, Any]:
        data: dict[str, Any] = {
            "integrationSuccess": self.integration_success,
            "buildPassed": self.build_passed,
            "worktreePath": self.worktree_path,
            "branchName": self.branch_name,
            "filesModified": list(self.files_modified),
            "integrationSummary": self.integration_summary,
            "logs": list(logs),
        }
        if self.build_output is not None:
            data["buildOutput"] = self.build_output
        if self.commit_hash is not None:
            data["commitHash"] = self.commit_hash
        if self.pushed is not None:
            data["pushed"] = self.pushed
        if self.pr_url is not None:
            data["prUrl"] = self.pr_url
        if self.ai_build_fix is not None:
            data["aiBuildFix"] = dict(self.ai_build_fix)
        return data


def build_report_sections(data: dict[str, Any], error: str | None, chat: list[dict[str, str]]) -> list[dict[str, Any]]:
    """Port of upstream `getReportSections`."""

    sections: list[dict[str, Any]] = []
    status_lines = [
        f"Integration: {'Success' if data.get('integrationSuccess') else 'Failed'}",
        f"Build verification: {'Passed' if data.get('buildPassed') else 'Failed'}",
        f"Branch: {data.get('branchName')}",
        f"Worktree: {data.get('worktreePath')}",
    ]
    if data.get("commitHash"):
        status_lines.append(f"Commit: {data['commitHash']}")
    if data.get("pushed"):
        status_lines.append("Pushed: Yes")
    if data.get("prUrl"):
        status_lines.append(f"PR: {data['prUrl']}")
    files_modified = data.get("filesModified") or []
    if files_modified:
        status_lines.extend(["", "Files modified:", *(f"  {name}" for name in files_modified)])
    sections.append({"type": "message", "title": "Integration Summary", "message": "\n".join(status_lines)})

    if data.get("integrationSummary"):
        sections.append(
            {"type": "message", "title": "Integration Script Output", "message": data["integrationSummary"]}
        )
    if data.get("buildOutput"):
        sections.append(
            {
                "type": "code",
                "title": "Build Verification Output",
                "language": "text",
                "code": data["buildOutput"],
            }
        )
    if chat:
        sections.append({"type": "chat", "title": "AI Build Fix", "messages": list(chat)})
    if error:
        sections.append({"type": "message", "title": "Error", "message": error})
    return sections


class IntegratorPlugin:
    id = "integrator"
    name = "Integrator"
    description = "Integrates matched C code into the decomp project source tree"

    def __init__(
        self,
        integrator_module: Path | IntegratorConfig,
        project_root: Path,
        *,
        build_command: str | None = None,
        config: IntegratorConfig | None = None,
        build_fixer: BuildFixer | None = None,
    ) -> None:
        if isinstance(integrator_module, IntegratorConfig):
            resolved = integrator_module
        elif config is not None:
            resolved = config
        else:
            # Back-compatible positional form; `build_command` was the old
            # spelling of `verify_build_script`.
            resolved = IntegratorConfig(integrator_module=integrator_module, verify_build_script=build_command)
        self._config = resolved
        self._project_root = project_root
        self._build_fixer = build_fixer

    # -- phases -----------------------------------------------------------

    def execute(self, context: dict[str, Any]) -> tuple[PluginResult, dict[str, Any]]:
        start = now_ms()
        config = self._config
        generated_code = context.get("generatedCode")
        if not generated_code:
            return (
                self._failure(start, "No generated code available in pipeline context"),
                context,
            )

        function_name = str(context.get("functionName") or "")
        timestamp = config.timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")
        requested_branch = render_template(
            config.branch_template, functionName=function_name, timestamp=timestamp
        )

        try:
            worktree = create_worktree(
                self._project_root, requested_branch, base_dir=config.worktree_base_dir
            )
        except GitError as exc:
            return self._failure(start, f"Failed to create git worktree: {exc}"), context

        outcome = _Outcome(worktree_path=str(worktree.path), branch_name=worktree.branch)
        helpers = IntegratorHelpers(worktree.path)

        # 1. user integrator module
        try:
            module = load_integrator_module(config.integrator_module)
            result = _call_integrate(
                module,
                function_name=function_name,
                generated_code=generated_code,
                worktree_path=worktree.path,
                project_root=self._project_root,
                helpers=helpers,
            )
        except IntegratorError as exc:
            return self._failure(start, f"Integration script failed: {exc}", outcome, helpers.logs), context

        outcome.integration_success = True
        outcome.files_modified = list(result.get("filesModified", []))
        outcome.integration_summary = str(result.get("summary") or "")

        # 2. build verification (+ optional fix)
        chat: list[dict[str, str]] = []
        if config.verify_build_script:
            verify_script = render_template(config.verify_build_script, worktreePath=str(worktree.path))
            build = run_verify_build(worktree.path, verify_script, timeout=config.build_timeout_seconds)
            outcome.build_output = build.output

            if not build.passed and config.ai_build_fix_enable:
                fix = attempt_build_fix(
                    BuildFixRequest(
                        worktree_path=worktree.path,
                        build_error=build.output,
                        files_modified=outcome.files_modified,
                        function_name=function_name,
                        generated_code=generated_code,
                        verify_build_command=verify_script,
                        timeout_seconds=config.ai_build_fix_timeout_seconds,
                        model=config.ai_build_fix_model,
                    ),
                    fixer=self._build_fixer,
                )
                chat = fix.chat_history
                outcome.build_output = fix.build_output
                outcome.ai_build_fix = {"attempted": fix.attempted, "fixed": fix.fixed}
                build_passed = fix.fixed
            else:
                build_passed = build.passed

            if not build_passed:
                suffix = " (AI fix attempted but unsuccessful)" if outcome.ai_build_fix else ""
                return (
                    self._failure(
                        start,
                        f"Build verification failed after integration{suffix}",
                        outcome,
                        helpers.logs,
                        chat,
                    ),
                    context,
                )

        outcome.build_passed = True

        # 3. commit -> push -> PR, stopping at the first failure
        try:
            outcome.commit_hash = commit_changes(
                worktree.path,
                render_template(config.commit_message_template, functionName=function_name),
            )
            if config.auto_action in ("push", "pr"):
                push_branch(worktree.path, worktree.branch)
                outcome.pushed = True
            if config.auto_action == "pr":
                outcome.pr_url = open_pull_request(
                    worktree.path,
                    worktree.branch,
                    title=render_template(config.pr_title_template, functionName=function_name),
                    body=render_template(config.pr_body_template, functionName=function_name),
                )
        except NothingToCommitError as exc:
            return self._failure(start, str(exc), outcome, helpers.logs, chat), context
        except GitError as exc:
            stage = "commit" if outcome.commit_hash is None else ("push" if outcome.pushed is None else "open PR")
            return self._failure(start, f"Failed to {stage}: {exc}", outcome, helpers.logs, chat), context

        data = outcome.to_data(helpers.logs)
        return (
            PluginResult(
                self.id,
                self.name,
                "success",
                now_ms() - start,
                output=outcome.integration_summary,
                data=data,
                sections=build_report_sections(data, None, chat),
            ),
            dict(context),
        )

    # -- helpers ----------------------------------------------------------

    def _failure(
        self,
        start: int,
        message: str,
        outcome: _Outcome | None = None,
        logs: list[str] | None = None,
        chat: list[dict[str, str]] | None = None,
    ) -> PluginResult:
        data = outcome.to_data(logs or []) if outcome is not None else {}
        return PluginResult(
            self.id,
            self.name,
            "failure",
            now_ms() - start,
            error=message,
            data=data,
            sections=build_report_sections(data, message, chat or []) if data else [],
        )
