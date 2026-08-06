"""Tests for run_report.py, ported from the upstream report-generator spec.

Also covers generate_html_report/_atomic: a self-contained, offline HTML
render of the report (no React build step -- see run_report.py's docstring).
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from agentdecompile_recovery.run_report import (
    generate_html_report,
    generate_html_report_atomic,
    save_json_report_atomic,
    transform_to_report,
)

pytestmark = pytest.mark.unit

_PLUGIN_CONFIGS = {
    "claudeRunner": {"stallThreshold": 3, "ttftTimeoutMs": 180_000, "model": "test-model"},
    "compiler": {"compilerScript": "echo test"},
}


def _make_pipeline_results(result_count: int) -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    results = []
    for i in range(result_count):
        success = i % 2 == 0
        results.append(
            {
                "promptPath": f"prompt-{i}.md",
                "functionName": f"func_{i}",
                "success": success,
                "totalDurationMs": 1000 * (i + 1),
                "setupPhase": {
                    "attemptNumber": 0,
                    "pluginResults": [],
                    "success": True,
                    "durationMs": 100,
                    "startTimestamp": now,
                },
                "attempts": [
                    {
                        "attemptNumber": 1,
                        "pluginResults": [],
                        "success": success,
                        "durationMs": 900,
                        "startTimestamp": now,
                    }
                ],
            }
        )
    successful = sum(1 for row in results if row["success"])
    return {
        "timestamp": now,
        "config": {"projectRoot": "/repo", "promptsDir": "/repo/prompts", "maxRetries": 3, "target": "msvc"},
        "results": results,
        "summary": {
            "totalPrompts": result_count,
            "successfulPrompts": successful,
            "successRate": (successful / result_count * 100) if result_count else 0,
            "avgAttempts": 1,
            "totalDurationMs": sum(row["totalDurationMs"] for row in results),
        },
    }


def test_produces_a_report_without_partial_field_when_no_partial_info_is_provided():
    pipeline_results = _make_pipeline_results(3)
    report = transform_to_report(pipeline_results, _PLUGIN_CONFIGS)

    assert "partial" not in report
    assert len(report["results"]) == 3


def test_includes_partial_metadata_when_provided():
    pipeline_results = _make_pipeline_results(2)
    report = transform_to_report(pipeline_results, _PLUGIN_CONFIGS, {"completedPrompts": 2, "totalPrompts": 10})

    assert report["partial"] == {"completedPrompts": 2, "totalPrompts": 10}
    assert len(report["results"]) == 2


def test_handles_a_single_completed_function_in_a_partial_report():
    pipeline_results = _make_pipeline_results(1)
    report = transform_to_report(pipeline_results, _PLUGIN_CONFIGS, {"completedPrompts": 1, "totalPrompts": 30})

    assert report["partial"] == {"completedPrompts": 1, "totalPrompts": 30}
    assert len(report["results"]) == 1
    assert report["summary"]["totalPrompts"] == 1


def test_relative_prompts_dir_computed_from_project_root():
    pipeline_results = _make_pipeline_results(1)
    report = transform_to_report(pipeline_results, _PLUGIN_CONFIGS)

    assert report["config"]["promptsDir"] == "prompts"
    assert report["config"]["model"] == "test-model"
    assert report["config"]["compilerScript"] == "echo test"


def test_save_json_report_atomic_writes_a_valid_json_file(tmp_path: Path):
    report = transform_to_report(_make_pipeline_results(2), _PLUGIN_CONFIGS)
    output_path = tmp_path / "test-report.json"

    save_json_report_atomic(report, output_path)

    parsed = json.loads(output_path.read_text(encoding="utf-8"))
    assert len(parsed["results"]) == 2
    assert parsed["version"] == 1


def test_save_json_report_atomic_does_not_leave_temp_files_on_success(tmp_path: Path):
    report = transform_to_report(_make_pipeline_results(1), _PLUGIN_CONFIGS)
    output_path = tmp_path / "test-report.json"

    save_json_report_atomic(report, output_path)

    assert [p.name for p in tmp_path.iterdir()] == ["test-report.json"]


def test_save_json_report_atomic_overwrites_an_existing_file(tmp_path: Path):
    output_path = tmp_path / "test-report.json"

    save_json_report_atomic(transform_to_report(_make_pipeline_results(1), _PLUGIN_CONFIGS), output_path)
    save_json_report_atomic(transform_to_report(_make_pipeline_results(3), _PLUGIN_CONFIGS), output_path)

    parsed = json.loads(output_path.read_text(encoding="utf-8"))
    assert len(parsed["results"]) == 3


def test_generate_html_report_embeds_the_report_json_and_is_self_contained(tmp_path: Path):
    report = transform_to_report(_make_pipeline_results(2), _PLUGIN_CONFIGS)
    output_path = tmp_path / "test-report.html"

    generate_html_report(report, output_path)

    html = output_path.read_text(encoding="utf-8")
    assert "<html>" in html
    assert "http://" not in html and "https://" not in html  # no external requests
    decoded = json.loads(base64.b64decode(html.split('atob("')[1].split('")')[0]))
    assert len(decoded["results"]) == 2


def test_generate_html_report_atomic_does_not_leave_temp_files_on_success(tmp_path: Path):
    report = transform_to_report(_make_pipeline_results(1), _PLUGIN_CONFIGS)
    output_path = tmp_path / "test-report.html"

    generate_html_report_atomic(report, output_path)

    assert [p.name for p in tmp_path.iterdir()] == ["test-report.html"]


def test_generate_html_report_atomic_overwrites_an_existing_file(tmp_path: Path):
    output_path = tmp_path / "test-report.html"

    generate_html_report_atomic(transform_to_report(_make_pipeline_results(1), _PLUGIN_CONFIGS), output_path)
    generate_html_report_atomic(transform_to_report(_make_pipeline_results(3), _PLUGIN_CONFIGS), output_path)

    html = output_path.read_text(encoding="utf-8")
    decoded = json.loads(base64.b64decode(html.split('atob("')[1].split('")')[0]))
    assert len(decoded["results"]) == 3
