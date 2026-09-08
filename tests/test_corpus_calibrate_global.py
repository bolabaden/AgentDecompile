from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentdecompile_recovery.corpus.dashboard.actions import catalog, introspect
from agentdecompile_recovery.corpus.pipeline import write_calibrate_global_receipt

pytestmark = pytest.mark.unit


def test_stub_profile_writes_partial_receipt(tmp_path: Path) -> None:
    profile = tmp_path / "compiler-profile.json"
    profile.write_text("{}", encoding="utf-8")
    receipt = write_calibrate_global_receipt(
        tmp_path,
        compiler_profile=profile,
    )
    assert receipt["wineStarted"] is False
    assert receipt["state"] == "partial"
    assert receipt["compiler"]["state"] == "present"
    assert receipt["types"] == "missing" or receipt["types"].get("state") == "missing"
    dest = tmp_path / "calibrate-global.json"
    assert dest.is_file()
    assert json.loads(dest.read_text(encoding="utf-8"))["state"] == "partial"


def test_missing_types_named_on_receipt(tmp_path: Path) -> None:
    receipt = write_calibrate_global_receipt(tmp_path)
    assert receipt["wineStarted"] is False
    assert receipt["state"] == "partial"
    assert "types" in receipt["gaps"]
    assert receipt["types"] == "missing" or receipt["types"].get("state") == "missing"


def test_catalog_lists_calibrate_global() -> None:
    ids = {item.id for item in catalog.list_actions()}
    assert "corpus.calibrate-global" in ids
    generated = {item.id for item in introspect.generate_actions()}
    assert "corpus.calibrate-global" in generated


def test_receipt_names_composed_fragments(tmp_path: Path) -> None:
    profile = tmp_path / "compiler-profile.json"
    profile.write_text("{}", encoding="utf-8")
    receipt = write_calibrate_global_receipt(tmp_path, compiler_profile=profile)
    fragments = receipt["fragments"]
    assert fragments["compiler-profile-corpus"]["state"] == "present"
    assert fragments["export-types"]["state"] == "missing"
    assert fragments["propagate"]["state"] == "missing"
    assert fragments["build-types-header"]["state"] == "missing"
    assert receipt["wineStarted"] is False


def test_calibrate_global_cli_requires_work_dir() -> None:
    from agentdecompile_recovery.corpus.cli import main as corpus_main

    with pytest.raises(SystemExit):
        corpus_main(["calibrate-global"])
