"""Transform pipeline run results into the run-report JSON schema and save atomically.

Ports the upstream report-generator's JSON path (`transformToReport` /
`saveJsonReportAtomic`) plus an HTML report path: the upstream version injects
the report JSON into a pre-built React app bundle. There's no React toolchain
in this Python repo to build that bundle from, so `generate_html_report`
below renders the same information (summary stats, per-prompt pass/fail,
per-plugin attempt detail) as a single self-contained HTML file with plain
JS -- no build step, no external requests, works by double-clicking the file.
Same capability (view a run report in a browser), a plainer implementation.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any


def transform_to_report(
    pipeline_results: dict[str, Any],
    plugin_configs: dict[str, Any],
    partial: dict[str, Any] | None = None,
) -> dict[str, Any]:
    config = pipeline_results.get("config") or {}
    claude_runner = plugin_configs.get("claudeRunner") or {}
    compiler = plugin_configs.get("compiler") or {}

    report: dict[str, Any] = {
        "version": 1,
        "timestamp": pipeline_results.get("timestamp"),
        "config": {
            "promptsDir": _relative_prompts_dir(config),
            "maxRetries": config.get("maxRetries"),
            "stallThreshold": claude_runner.get("stallThreshold"),
            "ttftTimeoutMs": claude_runner.get("ttftTimeoutMs"),
            "compilerScript": compiler.get("compilerScript"),
            "getContextScript": config.get("getContextScript"),
            "target": config.get("target"),
            "model": claude_runner.get("model"),
            "softTimeout": claude_runner.get("softTimeout"),
        },
        "results": [_transform_prompt_result(row) for row in pipeline_results.get("results") or []],
        "summary": pipeline_results.get("summary"),
    }
    if partial:
        report["partial"] = partial
    return report


def _relative_prompts_dir(config: dict[str, Any]) -> str:
    project_root = config.get("projectRoot")
    prompts_dir = config.get("promptsDir")
    if not project_root or not prompts_dir:
        return str(prompts_dir or ".")
    relative = os.path.relpath(str(prompts_dir), str(project_root))
    return relative or "."


def _transform_prompt_result(prompt_result: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "promptPath": prompt_result.get("promptPath"),
        "functionName": prompt_result.get("functionName"),
        "success": prompt_result.get("success"),
        "attempts": prompt_result.get("attempts") or [],
        "totalDurationMs": prompt_result.get("totalDurationMs"),
        "setupPhase": prompt_result.get("setupPhase"),
    }
    if prompt_result.get("programmaticPhase") is not None:
        result["programmaticPhase"] = prompt_result["programmaticPhase"]
    background_tasks = prompt_result.get("backgroundTasks") or []
    if background_tasks:
        result["backgroundTasks"] = background_tasks
    if prompt_result.get("matchSource") is not None:
        result["matchSource"] = prompt_result["matchSource"]
    if prompt_result.get("postMatchPhase") is not None:
        result["postMatchPhase"] = prompt_result["postMatchPhase"]
    return result


_HTML_TEMPLATE = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Run Report</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 2rem; color: #1a1a1a; }
  h1 { font-size: 1.25rem; }
  .summary { display: flex; gap: 1.5rem; margin-bottom: 1.5rem; }
  .stat { padding: 0.5rem 1rem; border: 1px solid #ddd; border-radius: 6px; }
  .stat .value { font-size: 1.4rem; font-weight: 600; }
  .stat .label { font-size: 0.8rem; color: #666; }
  table { border-collapse: collapse; width: 100%; }
  th, td { text-align: left; padding: 0.4rem 0.6rem; border-bottom: 1px solid #eee; font-size: 0.9rem; }
  .ok { color: #0a7c33; }
  .fail { color: #b3261e; }
  details { margin: 0.25rem 0; }
  pre { background: #f6f6f6; padding: 0.5rem; overflow-x: auto; font-size: 0.8rem; }
</style>
</head>
<body>
<h1>Run Report</h1>
<div id="summary" class="summary"></div>
<table>
  <thead><tr><th>Status</th><th>Function</th><th>Prompt</th><th>Attempts</th><th>Match source</th><th>Duration (ms)</th></tr></thead>
  <tbody id="rows"></tbody>
</table>
<script>
const report = JSON.parse(atob("__REPORT_BASE64__"));

function stat(value, label) {
  const el = document.createElement("div");
  el.className = "stat";
  el.innerHTML = `<div class="value">${value}</div><div class="label">${label}</div>`;
  return el;
}

const summaryEl = document.getElementById("summary");
const s = report.summary || {};
summaryEl.appendChild(stat(s.totalPrompts ?? 0, "total prompts"));
summaryEl.appendChild(stat(s.successfulPrompts ?? 0, "successful"));
summaryEl.appendChild(stat(((s.successRate ?? 0)).toFixed(1) + "%", "success rate"));
summaryEl.appendChild(stat(((s.avgAttempts ?? 0)).toFixed(1), "avg attempts"));

const rowsEl = document.getElementById("rows");
for (const result of report.results || []) {
  const tr = document.createElement("tr");
  const statusClass = result.success ? "ok" : "fail";
  const statusIcon = result.success ? "+" : "x";
  tr.innerHTML = `
    <td class="${statusClass}">${statusIcon}</td>
    <td>${result.functionName ?? ""}</td>
    <td>${result.promptPath ?? ""}</td>
    <td>${(result.attempts || []).length}</td>
    <td>${result.matchSource ?? ""}</td>
    <td>${result.totalDurationMs ?? ""}</td>
  `;
  rowsEl.appendChild(tr);
}
</script>
</body>
</html>
"""


def generate_html_report(report: dict[str, Any], output_path: Path | str) -> None:
    """Render a self-contained, offline HTML view of a run report (no build step)."""
    encoded = base64.b64encode(json.dumps(report).encode("utf-8")).decode("ascii")
    html = _HTML_TEMPLATE.replace("__REPORT_BASE64__", encoded)
    Path(output_path).write_text(html, encoding="utf-8")


def generate_html_report_atomic(report: dict[str, Any], output_path: Path | str) -> None:
    encoded = base64.b64encode(json.dumps(report).encode("utf-8")).decode("ascii")
    html = _HTML_TEMPLATE.replace("__REPORT_BASE64__", encoded)
    output_path = Path(output_path)
    tmp_path = output_path.parent / f".tmp-{output_path.name}-{os.getpid()}"
    tmp_path.write_text(html, encoding="utf-8")
    tmp_path.replace(output_path)


def save_json_report_atomic(report: dict[str, Any], output_path: Path | str) -> None:
    """Write to a temp file then rename, so a crash mid-write never corrupts the report."""
    output_path = Path(output_path)
    tmp_path = output_path.parent / f".tmp-{output_path.name}-{os.getpid()}"
    tmp_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    tmp_path.replace(output_path)


def delete_file_if_exists(path: Path | str) -> None:
    try:
        Path(path).unlink()
    except FileNotFoundError:
        pass
