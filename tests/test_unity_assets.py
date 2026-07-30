"""Unit tests for the optional Unity asset-export module (agentdecompile[unity]).

UnityPy itself is not exercised here (no real Unity asset fixtures are
available in this repo, and UnityPy is an optional dependency) -- these tests
cover the pure filesystem/naming logic that doesn't need it, plus the
lazy-import error path.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery import unity_assets

pytestmark = pytest.mark.unit


def test_sanitize_asset_name_replaces_unsafe_characters() -> None:
    assert unity_assets.sanitize_asset_name('a/b\\c:d*e?f"g<h>i|j') == "a_b_c_d_e_f_g_h_i_j"


def test_sanitize_asset_name_strips_whitespace() -> None:
    assert unity_assets.sanitize_asset_name("  spaced  ") == "spaced"


def test_sanitize_asset_name_never_returns_empty() -> None:
    assert unity_assets.sanitize_asset_name("") == "unnamed"
    assert unity_assets.sanitize_asset_name("   ") == "unnamed"


def test_discover_data_files_skips_companion_and_metadata_files(tmp_path: Path) -> None:
    data_dir = tmp_path / "Game_Data"
    data_dir.mkdir()
    (data_dir / "resources.assets").write_bytes(b"x")
    (data_dir / "resources.assets.resS").write_bytes(b"x")
    (data_dir / "resources.resource").write_bytes(b"x")
    (data_dir / "ScriptingAssemblies.json").write_bytes(b"x")
    (data_dir / "RuntimeInitializeOnLoads.json").write_bytes(b"x")
    (data_dir / "boot.config").write_bytes(b"x")
    (data_dir / "app.info").write_bytes(b"x")
    (data_dir / "level0").write_bytes(b"x")
    (data_dir / "sub").mkdir()

    files = unity_assets.discover_data_files(data_dir)

    assert [f.name for f in files] == ["level0", "resources.assets"]


def test_discover_data_files_empty_dir_returns_empty_list(tmp_path: Path) -> None:
    data_dir = tmp_path / "Empty_Data"
    data_dir.mkdir()
    assert unity_assets.discover_data_files(data_dir) == []


def test_find_unity_data_dir_locates_the_data_folder(tmp_path: Path) -> None:
    install_root = tmp_path / "MyGame"
    install_root.mkdir()
    (install_root / "MyGame_Data").mkdir()
    (install_root / "MyGame.exe").write_bytes(b"x")

    found = unity_assets.find_unity_data_dir(install_root)

    assert found == install_root / "MyGame_Data"


def test_find_unity_data_dir_returns_none_when_absent(tmp_path: Path) -> None:
    install_root = tmp_path / "NotUnity"
    install_root.mkdir()
    (install_root / "readme.txt").write_bytes(b"x")

    assert unity_assets.find_unity_data_dir(install_root) is None


def test_export_primary_content_reports_error_when_no_data_dir(tmp_path: Path) -> None:
    install_root = tmp_path / "NotUnity"
    install_root.mkdir()
    output_dir = tmp_path / "out"

    receipt = unity_assets.export_primary_content(install_root, output_dir)

    assert receipt["status"] == "error"
    assert "no *_Data directory" in receipt["reason"]


def test_require_unitypy_raises_actionable_error_when_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    import builtins

    real_import = builtins.__import__

    def _fake_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "UnityPy":
            raise ImportError("No module named 'UnityPy'")
        return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(builtins, "__import__", _fake_import)

    with pytest.raises(ImportError, match=r"agentdecompile\[unity\]"):
        unity_assets._require_unitypy()
