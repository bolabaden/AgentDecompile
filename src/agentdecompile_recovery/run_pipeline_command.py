"""Wire prompt_loader + m2c/compiler/objdiff + background permuter into one CLI run.

Ports the orchestration logic of the upstream top-level `run` command (its
React/Ink terminal rendering is UI chrome around this same logic -- see this
module's docstring history for why that chrome isn't duplicated here; this
is the actual pipeline it drives). For each loaded prompt: m2c generates a
first-pass C candidate from the target assembly, the compiler builds it, and
objdiff checks it against the target object's function. A background
decomp-permuter task runs concurrently once there's a candidate to mutate
(see background_task_coordinator.py / permuter_background.py). Matches and
failures alike are written to a run_report.py JSON report.
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .get_context_plugin import GetContextPlugin
from .gnu_c_compiler import GnuCCompiler
from .integrator_plugin import IntegratorConfig, IntegratorPlugin
from .permuter_background import BackgroundPermuterPlugin
from .plugin_pipeline import PluginPipeline, PluginResult, now_ms
from .prompt_loader import PromptInfo, load_prompts
from .run_report import generate_html_report_atomic, save_json_report_atomic, transform_to_report

CommandRunner = Callable[..., dict[str, Any]]


@dataclass
class RunPipelineConfig:
    prompts_dir: Path
    out_dir: Path
    compiler_script: str
    project_root: Path
    permuter_dir: Path | None = None
    permuter_jobs: int | None = None
    max_retries: int = 3
    m2c_target: str | None = None
    get_context_script: str = ""
    integrator_module: Path | None = None
    integrator_build_command: str | None = None
    #: How far the post-match phase automates: "commit", "push", or "pr".
    integrator_auto_action: str = "commit"


class M2cPhasePlugin:
    id = "m2c"
    name = "m2c"
    description = "Generate an initial C candidate from the target assembly via m2c."

    def __init__(self, *, target: str | None, command_runner: CommandRunner | None = None) -> None:
        self._target = target
        self._command_runner = command_runner

    def execute(self, context: dict[str, Any]) -> tuple[PluginResult, dict[str, Any]]:
        from agentdecompile_cli.mcp_utils.decomp_match import build_decomp_match_payload

        start = now_ms()
        with tempfile.NamedTemporaryFile("w", suffix=".s", delete=False) as fh:
            fh.write(context["asm"])
            asm_path = Path(fh.name)
        try:
            result = build_decomp_match_payload(
                tool="m2c",
                assembly_path=asm_path,
                function_name=context["functionName"],
                target=self._target,
                command_runner=self._command_runner,
            )
        finally:
            asm_path.unlink(missing_ok=True)

        decompiled_c = result.get("decompiledC")
        if not decompiled_c:
            reason = (result.get("scan") or {}).get("skipped") or "m2c produced no output"
            return _failure(self, start, reason), context

        updated = dict(context)
        updated["generatedCode"] = decompiled_c
        return _success(self, start, {}), updated


class CompilerPhasePlugin:
    id = "compiler"
    name = "compiler"
    description = "Compile the current C candidate to an object file."

    def __init__(self, compiler_script: str, project_root: Path) -> None:
        self._compiler = GnuCCompiler(compiler_script, project_root)

    def execute(self, context: dict[str, Any]) -> tuple[PluginResult, dict[str, Any]]:
        start = now_ms()
        code = context.get("generatedCode")
        if not code:
            return _failure(self, start, "no generated C code to compile"), context

        result = self._compiler.compile(context["functionName"], code, context.get("contextContent", ""))
        if not result.success:
            return _failure(self, start, result.error_message or "compilation failed"), context

        updated = dict(context)
        updated["compiledObjPath"] = str(result.obj_path)
        return _success(self, start, {}), updated


class ObjdiffPhasePlugin:
    id = "objdiff"
    name = "objdiff"
    description = "Diff the compiled candidate object against the target object's function."

    def __init__(self, command_runner: CommandRunner | None = None) -> None:
        self._command_runner = command_runner

    def execute(self, context: dict[str, Any]) -> tuple[PluginResult, dict[str, Any]]:
        from agentdecompile_cli.mcp_utils.decomp_match import build_decomp_match_payload

        start = now_ms()
        obj_path = context.get("compiledObjPath")
        if not obj_path:
            return _failure(self, start, "no compiled object to diff"), context

        result = build_decomp_match_payload(
            tool="objdiff",
            objdiff_mode="diff",
            target_object_path=obj_path,
            base_object_path=context["targetObjectPath"],
            symbol=context["functionName"],
            command_runner=self._command_runner,
        )
        scan = result.get("scan") or {}
        matched = scan.get("exitCode") == 0
        difference_count = 0 if matched else 1
        data = {"differenceCount": difference_count, "matched": matched, "raw": result}
        if matched:
            return _success(self, start, data), context
        return _failure(self, start, "objdiff reports a mismatch", data), context


def _success(plugin: Any, start: int, data: dict[str, Any]) -> PluginResult:
    return PluginResult(plugin.id, plugin.name, "success", now_ms() - start, data=data)


def _failure(plugin: Any, start: int, message: str, data: dict[str, Any] | None = None) -> PluginResult:
    return PluginResult(plugin.id, plugin.name, "failure", now_ms() - start, error=message, data=data or {})


def _build_pipeline(config: RunPipelineConfig, *, command_runner: CommandRunner | None = None) -> PluginPipeline:
    background_plugins = [BackgroundPermuterPlugin()] if config.permuter_dir else None
    pipeline = PluginPipeline(max_retries=config.max_retries, background_plugins=background_plugins)
    pipeline.register_setup_phase(GetContextPlugin(config.get_context_script, config.project_root))
    pipeline.register(
        M2cPhasePlugin(target=config.m2c_target, command_runner=command_runner),
        CompilerPhasePlugin(config.compiler_script, config.project_root),
        ObjdiffPhasePlugin(command_runner=command_runner),
    )
    if config.integrator_module is not None:
        pipeline.register_post_match_phase(
            IntegratorPlugin(
                IntegratorConfig(
                    integrator_module=config.integrator_module,
                    verify_build_script=config.integrator_build_command,
                    auto_action=config.integrator_auto_action,
                ),
                config.project_root,
            )
        )
    return pipeline


def run_prompt(
    prompt: PromptInfo,
    config: RunPipelineConfig,
    *,
    command_runner: CommandRunner | None = None,
) -> dict[str, Any]:
    pipeline = _build_pipeline(config, command_runner=command_runner)
    initial_context: dict[str, Any] = {
        "permuterDir": str(config.permuter_dir) if config.permuter_dir else None,
        "permuterJobs": config.permuter_jobs,
    }
    result = pipeline.run_pipeline(
        prompt_path=prompt.path,
        prompt_content=prompt.content,
        function_name=prompt.function_name,
        target_object_path=prompt.target_object_path,
        asm=prompt.asm,
        initial_context=initial_context,
    )
    return result.to_json()


def run_prompts_pipeline(
    config: RunPipelineConfig,
    *,
    command_runner: CommandRunner | None = None,
) -> dict[str, Any]:
    """Load every prompt under config.prompts_dir and run the pipeline over each."""
    import datetime

    prompts, load_errors = load_prompts(config.prompts_dir)
    results = [run_prompt(prompt, config, command_runner=command_runner) for prompt in prompts]

    successful = sum(1 for r in results if r.get("success"))
    total = len(results)
    pipeline_results = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "config": {
            "projectRoot": str(config.project_root),
            "promptsDir": str(config.prompts_dir),
            "maxRetries": config.max_retries,
        },
        "results": results,
        "summary": {
            "totalPrompts": total,
            "successfulPrompts": successful,
            "successRate": (successful / total * 100) if total else 0.0,
            "avgAttempts": (
                sum(len(r.get("attempts") or []) for r in results) / total if total else 0.0
            ),
            "totalDurationMs": sum(r.get("totalDurationMs") or 0 for r in results),
        },
    }

    report = transform_to_report(
        pipeline_results,
        {"claudeRunner": {"stallThreshold": 0, "ttftTimeoutMs": 0, "model": "n/a"}, "compiler": {"compilerScript": config.compiler_script}},
    )
    config.out_dir.mkdir(parents=True, exist_ok=True)
    report_path = config.out_dir / "run-report.json"
    html_report_path = config.out_dir / "run-report.html"
    save_json_report_atomic(report, report_path)
    generate_html_report_atomic(report, html_report_path)

    return {
        "schema": "agentdecompile.run-pipeline.v1",
        "status": "complete",
        "reportPath": str(report_path),
        "htmlReportPath": str(html_report_path),
        "loadErrors": [str(err) for err in load_errors],
        "summary": pipeline_results["summary"],
    }
