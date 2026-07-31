"""Tests for the `--project` CLI flag and the ghidra_db-backed project reader (U10).

`open_project_names_context` (ghidra_context.py) replaces the old
`analyzeHeadless`/`--project-snapshot` path for real `.gpr`/`.rep` projects:
it opens the project read-only through `ghidra_db` and returns curated
function names, no JVM involved.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from agentdecompile_recovery import cli
from agentdecompile_recovery.acquire import acquire_context
from agentdecompile_recovery.ghidra_context import (
    export_ghidra_context,
    open_project_names_context,
    project_input_error,
)

pytestmark = pytest.mark.unit

ODYSSEY_REP = Path("/home/brunner56/Odyssey.rep")
GHIDRA_REP = Path("/home/brunner56/Downloads/biodecompwarehouse/projects/agentdecompile.rep")

_needs_odyssey = pytest.mark.skipif(not ODYSSEY_REP.is_dir(), reason="Odyssey project fixture unavailable")
_needs_ghidra_project = pytest.mark.skipif(not GHIDRA_REP.is_dir(), reason="Ghidra project fixture unavailable")


def _first_available_project() -> Path | None:
    if ODYSSEY_REP.is_dir():
        return ODYSSEY_REP
    if GHIDRA_REP.is_dir():
        return GHIDRA_REP
    return None


_needs_any_project = pytest.mark.skipif(
    _first_available_project() is None, reason="no Ghidra project fixture available"
)


# -- valid --project path opens and yields a non-empty names map ------------


@_needs_any_project
def test_open_project_names_context_valid_project_returns_nonempty_names(tmp_path: Path) -> None:
    project = _first_available_project()
    assert project is not None

    report = open_project_names_context(source=project, out_dir=tmp_path / "ghidra")

    assert report["status"] == "complete"
    assert report["mode"] == "project-db-read-only"
    assert report["curatedOnly"] is True
    assert report["factCount"] > 0
    assert report["namesByEntry"], "expected at least one curated name"

    facts_path = Path(report["factsJsonl"])
    assert facts_path.is_file()
    assert facts_path.stat().st_size > 0


@_needs_any_project
def test_export_ghidra_context_routes_project_dir_through_ghidra_db(tmp_path: Path) -> None:
    """export_ghidra_context (the acquire.py entrypoint) must not refuse a real project."""

    project = _first_available_project()
    assert project is not None

    report = export_ghidra_context(source=project, out_dir=tmp_path / "ghidra")

    assert report["status"] == "complete"
    assert report["mode"] == "project-db-read-only"
    assert report["factCount"] > 0


@_needs_any_project
def test_acquire_context_with_project_flag_populates_ghidra_reports(tmp_path: Path) -> None:
    project = _first_available_project()
    assert project is not None

    receipt = acquire_context(
        target_input=None,
        context_paths=[],
        out_dir=tmp_path / "acquisition",
        project=project,
        register=False,
    )

    assert receipt["ghidraErrors"] == []
    assert len(receipt["ghidraReports"]) == 1
    report = receipt["ghidraReports"][0]
    assert report["mode"] == "project-db-read-only"
    assert report["factCount"] > 0


# -- missing --project path fails clearly, not with a stack trace -----------


def test_project_input_error_reports_missing_path(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.rep"
    message = project_input_error(missing)
    assert message is not None
    assert "does not exist" in message


def test_open_project_names_context_missing_path_raises_value_error(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.rep"
    with pytest.raises(ValueError):
        open_project_names_context(source=missing, out_dir=tmp_path / "out")


@pytest.mark.xfail(
    reason="F3: --project not yet wired into cli.py's `recover acquire` subcommand -- "
    "cli.py has uncommitted work from a concurrent session and this piece was deferred "
    "rather than force a merge through it. See .mission/queue.md follow-up F3. The "
    "equivalent flag on the primary agentdecompile-reconstruct entrypoint (frontdoor.py) "
    "is wired and covered by test_acquire_context_with_project_flag_populates_ghidra_reports.",
    strict=True,
)
def test_run_acquire_cli_missing_project_exits_cleanly_without_traceback(tmp_path: Path, capsys) -> None:
    parser = cli.build_parser()
    args = parser.parse_args(
        [
            "acquire",
            "--out-dir",
            str(tmp_path / "acquisition"),
            "--project",
            str(tmp_path / "does-not-exist.rep"),
            "--no-register",
        ]
    )
    exit_code = cli.run_acquire(args)
    captured = capsys.readouterr()

    assert exit_code == 2
    assert "does not exist" in captured.err
    # A clean argparse-style failure prints one line to stderr, no Python traceback.
    assert "Traceback" not in captured.err


def test_run_acquire_missing_non_project_shaped_directory_is_a_clear_error(tmp_path: Path) -> None:
    """A directory that exists but isn't a Ghidra project also fails cleanly."""

    not_a_project = tmp_path / "just-a-folder"
    not_a_project.mkdir()

    message = project_input_error(not_a_project)
    assert message is not None
    assert "does not exist" not in message  # it exists; the problem is the layout


# -- a run WITHOUT --project behaves exactly as before (regression) ---------


def test_acquire_context_without_project_is_unaffected(tmp_path: Path) -> None:
    """Omitting `project` (the pre-U10 call shape) must behave exactly as before."""

    receipt = acquire_context(
        target_input=None,
        context_paths=[],
        out_dir=tmp_path / "acquisition",
        register=False,
    )

    assert receipt["ghidraReports"] == []
    assert receipt["ghidraErrors"] == []
    assert receipt["routing"]["ghidraSources"] == []


@pytest.mark.xfail(reason="F3: --project not yet wired into cli.py's `recover acquire` subcommand", strict=True)
def test_cli_acquire_parser_defaults_project_to_none() -> None:
    parser = cli.build_parser()
    args = parser.parse_args(["acquire", "--out-dir", "/tmp/whatever"])
    assert args.project is None
    assert args.project_program is None


@pytest.mark.xfail(reason="F3: --project not yet wired into cli.py's `recover acquire` subcommand", strict=True)
def test_run_acquire_without_project_does_not_touch_project_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """run_acquire must not call project_input_error at all when --project is absent."""

    called = {"count": 0}

    def _boom(_path: Path) -> str | None:
        called["count"] += 1
        return None

    monkeypatch.setattr(cli, "project_input_error", _boom)

    args = argparse.Namespace(
        input=None,
        context=[],
        out_dir=tmp_path / "acquisition",
        preferred_name=None,
        no_register=True,
        project=None,
        project_program=None,
    )
    exit_code = cli.run_acquire(args)

    assert exit_code == 0
    assert called["count"] == 0


# -- acquire_context's own status must not paper over a bad --project ------
#
# The CLI layer (cli.run_acquire, frontdoor.run_one_shot) both pre-validate
# via project_input_error() before calling acquire_context. But
# acquire_context itself is a public function any other caller (a future MCP
# entrypoint, a test harness, the programmatic frontdoor path) could invoke
# directly without replicating that pre-flight check -- and until this fix,
# doing so with a bad project path returned status:"complete" with the
# failure buried in ghidraErrors, a silent-success receipt for curated data
# that was never actually read.


def test_acquire_context_bad_project_path_does_not_report_complete(tmp_path: Path) -> None:
    bad_project = tmp_path / "does-not-exist.rep"

    result = acquire_context(
        target_input=None,
        out_dir=tmp_path / "acquisition",
        project=bad_project,
        register=False,
    )

    assert result["status"] != "complete"
    assert len(result["ghidraErrors"]) == 1
    assert result["ghidraErrors"][0]["source"] == str(bad_project)


@_needs_odyssey
def test_acquire_context_good_project_path_still_reports_complete(tmp_path: Path) -> None:
    """Regression guard for the fix itself: a project that opens successfully
    must not be caught by the new check."""

    result = acquire_context(
        target_input=None,
        out_dir=tmp_path / "acquisition",
        project=ODYSSEY_REP,
        register=False,
    )

    assert result["status"] == "complete"
    assert result["ghidraErrors"] == []
    assert result["ghidraReports"]
