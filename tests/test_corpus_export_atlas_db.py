from __future__ import annotations

from pathlib import Path
from unittest import mock

import pytest

from agentdecompile_recovery.corpus import export_atlas_db
from agentdecompile_recovery.corpus.export_atlas_db import ATLAS_YAML, atlas_target

pytestmark = pytest.mark.unit


def test_architecture_mapping_never_substitutes_gba() -> None:
    expected = {
        "x86": "x86",
        "x86_64": "x86_64",
        "ARM": "arm",
        "AARCH64": "aarch64",
        "PowerPC": "ppc",
    }
    for arch, target in expected.items():
        assert atlas_target(arch) == target
        assert atlas_target(arch) != "gba"


def test_yaml_uses_derived_target() -> None:
    rendered = ATLAS_YAML.format(root="/tmp/project", target="x86")
    assert "target: x86" in rendered
    assert "target: gba" not in rendered


def test_write_emits_architecture_target_in_json_and_yaml(tmp_path: Path) -> None:
    dump = {
        "version": 1, "platform": "x86", "decompFunctions": [],
        "vectors": [], "indexMetadata": {},
    }
    with mock.patch(
        "agentdecompile_recovery.corpus.export_atlas_db.build", return_value=dump
    ):
        out = export_atlas_db.write("/arbitrary/game.bin", out_root=tmp_path)
        root = out.parent
        json_text = out.read_text()
        yaml_text = (root / "atlas.yaml").read_text()
    assert export_atlas_db.json.loads(json_text)["platform"] == "x86"
    assert "target: x86" in yaml_text
    assert "gba" not in (json_text + yaml_text).lower()
    assert "game boy" not in (json_text + yaml_text).lower()
