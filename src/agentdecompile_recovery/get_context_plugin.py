"""Setup-phase plugin: run a user-provided script to generate context content.

Ports the upstream get-context plugin: executes `get_context_script` (e.g. a
script that pulls type definitions relevant to the target function) once per
prompt, before both the programmatic and AI-powered phases, and makes the
result available to later plugins as `context["contextContent"]` /
`context["contextFilePath"]`.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .plugin_pipeline import PluginResult, now_ms


class GetContextPlugin:
    id = "get-context"
    name = "Get Context"
    description = "Executes get_context_script to generate context content"

    def __init__(self, get_context_script: str, project_root: Path) -> None:
        self._get_context_script = get_context_script
        self._project_root = project_root
        self._tmp_dir: Path | None = None

    def execute(self, context: dict[str, Any]) -> tuple[PluginResult, dict[str, Any]]:
        start = now_ms()

        if not self._get_context_script.strip():
            updated = dict(context)
            updated["contextContent"] = ""
            updated["contextFilePath"] = ""
            return (
                PluginResult(
                    self.id,
                    self.name,
                    "success",
                    now_ms() - start,
                    output="No get_context_script configured, using empty context",
                    data={"contextContent": "", "contextFilePath": ""},
                ),
                updated,
            )

        self.cleanup()
        tmp_dir = Path(tempfile.mkdtemp(prefix="agentdecompile-context-"))
        self._tmp_dir = tmp_dir
        script_path = tmp_dir / "get-context.sh"
        context_file_path = tmp_dir / "context.h"

        rendered_script = self._get_context_script.replace(
            "{{functionName}}", str(context.get("functionName") or "")
        ).replace("{{targetObjectPath}}", str(context.get("targetObjectPath") or ""))
        script_path.write_text("set -e\n" + rendered_script, encoding="utf-8")

        bash = shutil.which("bash") or "bash"
        result = subprocess.run(
            [bash, str(script_path)],
            cwd=str(self._project_root),
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            error_message = result.stderr.strip() or result.stdout.strip() or f"exit code {result.returncode}"
            self.cleanup()
            return (
                PluginResult(
                    self.id, self.name, "failure", now_ms() - start, error=f"get_context_script failed: {error_message}"
                ),
                context,
            )

        context_content = result.stdout
        context_file_path.write_text(context_content, encoding="utf-8")

        line_count = len(context_content.split("\n"))
        output = (
            f"Generated {line_count} lines of context"
            if context_content
            else (
                "Warning: get_context_script succeeded but produced no stdout output. If your script writes to a "
                'file, add "cat <file>" at the end of your script to pipe the content to stdout.'
            )
        )

        updated = dict(context)
        updated["contextContent"] = context_content
        updated["contextFilePath"] = str(context_file_path)
        return (
            PluginResult(
                self.id,
                self.name,
                "success",
                now_ms() - start,
                output=output,
                data={"contextContent": context_content, "contextFilePath": str(context_file_path)},
            ),
            updated,
        )

    def cleanup(self) -> None:
        if self._tmp_dir is not None:
            shutil.rmtree(self._tmp_dir, ignore_errors=True)
            self._tmp_dir = None
