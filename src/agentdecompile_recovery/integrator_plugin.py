"""Post-match phase plugin: integrate a matched decompilation into project source.

Ports the upstream integrator plugin's core shape: the user supplies a Python
module (`integrator_module`) exporting an `integrate(function_name,
generated_code, project_root, helpers)` callable that uses
integrator_helpers.IntegratorHelpers to insert the matched C code into the
project's real source tree (however that project's stub convention works --
INCLUDE_ASM, #pragma GLOBAL_ASM, or something else entirely). That's a
deliberate design choice upstream makes too: every decomp project's source
layout differs enough that a generic default integrator isn't meaningful.

Simplified vs. upstream: no git worktree isolation (upstream creates one so
integration can be reviewed/discarded before merging; here integration runs
directly against `project_root` -- add worktree isolation at the call site
if needed) and no AI build-fix loop (upstream retries failed builds through
an LLM; this project already has its own subagent-dispatch mechanism for
that via rewrite_queue.py, which is a separate concern from this plugin).
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any, Protocol

from .integrator_helpers import IntegratorError, IntegratorHelpers
from .plugin_pipeline import PluginResult, now_ms


class IntegratorModule(Protocol):
    def integrate(
        self,
        *,
        function_name: str,
        generated_code: str,
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


class IntegratorPlugin:
    id = "integrator"
    name = "Integrator"
    description = "Integrates matched C code into the decomp project source tree"

    def __init__(self, integrator_module: Path, project_root: Path, *, build_command: str | None = None) -> None:
        self._integrator_module = integrator_module
        self._project_root = project_root
        self._build_command = build_command

    def execute(self, context: dict[str, Any]) -> tuple[PluginResult, dict[str, Any]]:
        start = now_ms()
        generated_code = context.get("generatedCode")
        if not generated_code:
            return (
                PluginResult(self.id, self.name, "failure", now_ms() - start, error="No generated code available in pipeline context"),
                context,
            )

        helpers = IntegratorHelpers(self._project_root)

        try:
            module = load_integrator_module(self._integrator_module)
            result = module.integrate(
                function_name=context["functionName"],
                generated_code=generated_code,
                project_root=self._project_root,
                helpers=helpers,
            )
        except IntegratorError as exc:
            return (
                PluginResult(
                    self.id, self.name, "failure", now_ms() - start, error=str(exc), data={"logs": helpers.logs}
                ),
                context,
            )

        build_output = None
        if self._build_command:
            try:
                build_output = helpers.exec_command(self._build_command)
            except IntegratorError as exc:
                return (
                    PluginResult(
                        self.id,
                        self.name,
                        "failure",
                        now_ms() - start,
                        error=f"Build failed after integration: {exc}",
                        data={"logs": helpers.logs, "filesModified": result.get("filesModified", [])},
                    ),
                    context,
                )

        updated = dict(context)
        return (
            PluginResult(
                self.id,
                self.name,
                "success",
                now_ms() - start,
                output=result.get("summary"),
                data={
                    "filesModified": result.get("filesModified", []),
                    "integrationSummary": result.get("summary"),
                    "buildOutput": build_output,
                    "logs": helpers.logs,
                },
            ),
            updated,
        )
