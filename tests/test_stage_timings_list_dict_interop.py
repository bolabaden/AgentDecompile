"""Regression test: frontdoor's dict-shaped stage-timings API must survive
reading a file already written by pipeline.py's list-shaped writer.

Found while investigating why the live swkotor.exe autonomous campaign
crashed with `TypeError: list indices must be integers or slices, not str`
in stage_timings.record_stage(). Root cause: two independent writers share
the same file (<work_dir>/stage-timings.json) and the same schema tag
(agentdecompile.stage-timings.v1), but disagree on the shape of "stages" --
pipeline.py's ReconstructPipeline._write_stage_timings() writes a *list* of
per-stage row dicts (each with a "stage" key), while stage_timings.py's
record_stage()/load_stage_timings() treat "stages" as a *dict* keyed by
stage name. frontdoor.run_dump_source() calls record_stage() against a file
the main 15-stage pipeline already wrote in list form, and
`stages[name] = {...}` on a list raises TypeError instead of KeyError.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentdecompile_recovery.stage_timings import load_stage_timings, record_stage

pytestmark = pytest.mark.unit


def test_load_stage_timings_converts_list_shaped_stages_from_pipeline_writer(tmp_path: Path) -> None:
    payload = {
        "schema": "agentdecompile.stage-timings.v1",
        "workDir": str(tmp_path),
        "stages": [
            {"stage": "discover", "status": "complete", "durationSeconds": 1.5},
            {"stage": "inspect-capabilities", "status": "skipped-resume", "durationSeconds": 0},
        ],
        "totalSeconds": 1.5,
    }
    (tmp_path / "stage-timings.json").write_text(json.dumps(payload), encoding="utf-8")

    timings = load_stage_timings(tmp_path)

    assert isinstance(timings["stages"], dict)
    assert timings["stages"]["discover"]["status"] == "complete"
    assert timings["stages"]["inspect-capabilities"]["status"] == "skipped-resume"


def test_record_stage_succeeds_after_loading_list_shaped_file(tmp_path: Path) -> None:
    payload = {
        "schema": "agentdecompile.stage-timings.v1",
        "workDir": str(tmp_path),
        "stages": [{"stage": "discover", "status": "complete", "durationSeconds": 1.5}],
        "totalSeconds": 1.5,
    }
    (tmp_path / "stage-timings.json").write_text(json.dumps(payload), encoding="utf-8")

    timings = load_stage_timings(tmp_path)
    record_stage(timings, "dump-source", started=0.0, ended=2.0, status="complete")

    assert timings["stages"]["dump-source"]["status"] == "complete"
    assert timings["stages"]["discover"]["status"] == "complete"


def test_load_stage_timings_still_handles_dict_shaped_stages(tmp_path: Path) -> None:
    payload = {
        "schema": "agentdecompile.stage-timings.v1",
        "workDir": str(tmp_path),
        "stages": {"discover": {"status": "complete", "wallSeconds": 1.5}},
    }
    (tmp_path / "stage-timings.json").write_text(json.dumps(payload), encoding="utf-8")

    timings = load_stage_timings(tmp_path)

    assert timings["stages"] == {"discover": {"status": "complete", "wallSeconds": 1.5}}
