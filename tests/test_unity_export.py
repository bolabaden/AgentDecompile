"""Unit tests for the pure parts of the headless AssetRipper driver.

AssetRipper is never launched here and no socket talks to anything but the
loopback allocator. These cover the three helpers that decide how a run is
*judged* after the fact:

* :func:`looks_like_memory_failure` -- the difference between "AssetRipper died
  because the title is too big for this host" (re-run staged) and "AssetRipper
  died for some other reason" (a real bug). Misclassifying either way sends the
  next run down the wrong road.
* :func:`find_exported_project` / :func:`project_version_file` -- the success
  signal is a file on disk, not a return code, and AssetRipper nests its output
  at a depth that varies by version.
* :func:`pick_free_port` -- a hardcoded port collides deterministically with a
  leaked AssetRipper from an earlier run.
"""

from __future__ import annotations

import socket

from pathlib import Path

import pytest

from agentdecompile_recovery import unity_export

pytestmark = pytest.mark.unit


# --- memory-failure classification -------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "Unhandled exception. System.OutOfMemoryException: Exception of type 'System.OutOfMemoryException' was thrown.",
        "terminate called after throwing an instance of 'std::bad_alloc'",
        "OUT OF MEMORY while processing sharedassets0.assets",
        "Out of memory: Killed process 4711 (AssetRipper)",
        "kernel: oom-killer: gfp_mask=0x100cca",
    ],
)
def test_looks_like_memory_failure_recognizes_oom_output(text: str) -> None:
    assert unity_export.looks_like_memory_failure(text) is True


@pytest.mark.parametrize(
    "text",
    [
        "Exporting assets... 42%",
        "System.IO.FileNotFoundException: Could not find file 'level0'",
        "",
    ],
)
def test_looks_like_memory_failure_is_false_for_ordinary_output(text: str) -> None:
    assert unity_export.looks_like_memory_failure(text) is False


def test_looks_like_memory_failure_treats_sigkill_as_a_suspected_oom() -> None:
    # A Popen returncode of -9 is what the Linux OOM killer leaves behind; it is
    # indistinguishable from a manual `kill -9`, hence "suspected", never asserted.
    assert unity_export.looks_like_memory_failure("Exporting assets...", -9) is True


def test_looks_like_memory_failure_also_accepts_a_shell_style_137_exit_code() -> None:
    # 128+9 is the same SIGKILL, as reported by a shell (`$?`) or a container
    # runtime rather than by Popen. Accepted so an OOM kill arriving through one
    # of those paths is not silently reclassified as an ordinary failure; a false
    # positive only over-states a value already named "suspected".
    assert unity_export.looks_like_memory_failure("Exporting assets...", 137) is True


def test_looks_like_memory_failure_ignores_a_clean_exit() -> None:
    assert unity_export.looks_like_memory_failure("Export complete", 0) is False


# --- locating the exported project -------------------------------------------


def _project_tree(root: Path) -> Path:
    (root / "Assets").mkdir(parents=True)
    settings = root / "ProjectSettings"
    settings.mkdir(parents=True)
    (settings / "ProjectVersion.txt").write_text("m_EditorVersion: 2022.3.62f2\n", encoding="utf-8")
    return root


def test_find_exported_project_prefers_the_direct_child(tmp_path: Path) -> None:
    direct = _project_tree(tmp_path / "ExportedProject")
    _project_tree(tmp_path / "extra" / "ExportedProject")

    assert unity_export.find_exported_project(tmp_path) == direct


def test_find_exported_project_looks_through_a_created_subfolder(tmp_path: Path) -> None:
    # `CreateSubfolder` and version differences add a level between the
    # destination and ExportedProject/.
    nested = _project_tree(tmp_path / "TheGame" / "ExportedProject")
    assert unity_export.find_exported_project(tmp_path) == nested


def test_find_exported_project_looks_two_levels_deep(tmp_path: Path) -> None:
    nested = _project_tree(tmp_path / "a" / "b" / "ExportedProject")
    assert unity_export.find_exported_project(tmp_path) == nested


def test_find_exported_project_accepts_a_destination_that_is_itself_a_project(tmp_path: Path) -> None:
    _project_tree(tmp_path)
    assert unity_export.find_exported_project(tmp_path) == tmp_path


def test_find_exported_project_returns_none_when_nothing_was_written(tmp_path: Path) -> None:
    (tmp_path / "AuxiliaryFiles").mkdir()
    assert unity_export.find_exported_project(tmp_path) is None


def test_find_exported_project_returns_none_for_a_missing_output_dir(tmp_path: Path) -> None:
    assert unity_export.find_exported_project(tmp_path / "never-ran") is None


def test_project_version_file_points_at_the_success_signal(tmp_path: Path) -> None:
    exported = _project_tree(tmp_path / "ExportedProject")
    version_file = unity_export.project_version_file(exported)
    assert version_file == exported / "ProjectSettings" / "ProjectVersion.txt"
    assert version_file.is_file()


def test_project_version_file_does_not_require_the_file_to_exist(tmp_path: Path) -> None:
    # The caller decides what a missing file means; this helper only names it.
    version_file = unity_export.project_version_file(tmp_path / "empty")
    assert version_file.name == "ProjectVersion.txt"
    assert not version_file.exists()


# --- port allocation ---------------------------------------------------------


def test_pick_free_port_returns_a_bindable_ephemeral_port() -> None:
    port = unity_export.pick_free_port()

    assert isinstance(port, int)
    assert 1024 < port < 65536
    # It must be released again, or the AssetRipper we launch cannot claim it.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", port))


# --- misc pure helpers -------------------------------------------------------


def test_load_route_picks_loadfile_for_a_player_executable(tmp_path: Path) -> None:
    executable = tmp_path / "TheGame.exe"
    executable.write_bytes(b"MZ")
    assert unity_export._load_route(executable) == "/LoadFile"


def test_load_route_picks_loadfolder_for_an_install_root(tmp_path: Path) -> None:
    assert unity_export._load_route(tmp_path) == "/LoadFolder"


def test_staged_containers_reads_the_plan_and_tolerates_an_absent_one() -> None:
    plan = {"export": {"mode": "staged", "includedContainers": ["level0", "globalgamemanagers"]}}
    assert unity_export._staged_containers(plan) == ["level0", "globalgamemanagers"]
    assert unity_export._staged_containers(None) == []
    assert unity_export._staged_containers({}) == []


def test_no_redirect_handler_refuses_to_replay_a_post_as_a_get() -> None:
    # Following AssetRipper's 302 re-enters its web UI, which on some builds
    # re-runs work or 404s and masks an otherwise successful export.
    handler = unity_export._NoRedirect()
    assert handler.redirect_request(None, None, 302, "Found", {}, "http://127.0.0.1:1/") is None
