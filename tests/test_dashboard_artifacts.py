from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from agentdecompile_recovery.corpus.dashboard import pages as dashboard

pytestmark = pytest.mark.unit


def test_repository_files_outside_evidence_roots_are_refused() -> None:
    target, error = dashboard._resolve_artifact("ghidra_server/xid_key")
    assert target is None
    assert "outside the public evidence roots" in error or "unset" in error


def test_root_browser_is_refused() -> None:
    target, error = dashboard._resolve_artifact(".")
    assert target is None
    assert "outside the public evidence roots" in error or "unset" in error


def test_suffixless_and_sensitive_files_are_refused_inside_evidence(tmp_path: Path) -> None:
    output = tmp_path / "output"
    output.mkdir()
    (output / "private_key").write_text("do not serve")
    with patch.object(dashboard, "ROOT", tmp_path), \
            patch.object(dashboard, "ARTIFACT_ROOT_NAMES", ("output",)):
        target, error = dashboard._resolve_artifact("output/private_key")
    assert target is None
    assert "sensitive" in error


def test_known_text_evidence_is_allowed(tmp_path: Path) -> None:
    output = tmp_path / "output"
    output.mkdir()
    report = output / "progress.json"
    report.write_text("{}")
    with patch.object(dashboard, "ROOT", tmp_path), \
            patch.object(dashboard, "ARTIFACT_ROOT_NAMES", ("output",)):
        target, error = dashboard._resolve_artifact("output/progress.json")
    assert target == report.resolve()
    assert error is None


def test_directory_listing_hides_denied_children(tmp_path: Path) -> None:
    output = tmp_path / "output"
    output.mkdir()
    (output / "progress.json").write_text("{}")
    (output / "private_token.txt").write_text("hidden")
    (output / "opaque").write_text("hidden")
    with patch.object(dashboard, "ROOT", tmp_path), \
            patch.object(dashboard, "ARTIFACT_ROOT_NAMES", ("output",)):
        rendered = dashboard._artifact_dir(output)
    assert "progress.json" in rendered
    assert "private_token" not in rendered
    assert "opaque" not in rendered
