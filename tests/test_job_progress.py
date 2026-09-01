"""Job progress is a percent on the job payload, not only queued/running/ok."""

from __future__ import annotations

from agentdecompile_recovery.corpus.dashboard.actions.jobs import (
    JobRecord,
    infer_job_progress,
)


def test_infer_queued_is_small() -> None:
    assert infer_job_progress("queued", "") == 4


def test_infer_ok_is_complete() -> None:
    assert infer_job_progress("ok", "done\n") == 100


def test_infer_parses_percent_from_log() -> None:
    assert infer_job_progress("running", "Auto analysis 41%\n") == 41


def test_job_to_dict_includes_progress() -> None:
    job = JobRecord(
        id="abc",
        action_id="mcp.analyze-program",
        title="analyze program",
        argv=["true"],
        status="running",
        log="analyze-program 22%\n",
    )
    payload = job.to_dict()
    assert payload["progress"] == 22
    assert payload["actionId"] == "mcp.analyze-program"
