"""Unit tests for the pure filesystem half of managed-assembly decompilation.

ILSpy itself is never invoked here -- these cover the two functions that decide
what a decompiled tree looks like once it lands in ``Assets/``.

The regression they guard against is the expensive kind: ILSpy project-mode
scaffolding (``Properties/AssemblyInfo.cs``, ``UnitySourceGeneratedAssembly-
MonoScriptTypes_v1.cs``) surviving into a Unity project, where it fails the
import with a CS0579/CS0101 that points nowhere near this stage. A missed file
here costs an entire Editor round trip to rediscover.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery import unity_managed

pytestmark = pytest.mark.unit


def _write(path: Path, text: str = "// code\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# --- strip_scaffolding -------------------------------------------------------


def test_strip_scaffolding_removes_both_ilspy_artifacts_recursively(tmp_path: Path) -> None:
    source = tmp_path / "Assembly-CSharp"
    _write(source / "Properties" / "AssemblyInfo.cs")
    _write(source / "Deep" / "Nested" / "UnitySourceGeneratedAssemblyMonoScriptTypes_v1.cs")
    real = _write(source / "Game" / "Player.cs", "public class Player {}\n")

    removed = unity_managed.strip_scaffolding(source)

    assert sorted(removed) == [
        "Deep/Nested/UnitySourceGeneratedAssemblyMonoScriptTypes_v1.cs",
        "Properties/AssemblyInfo.cs",
    ]
    assert real.is_file()


def test_strip_scaffolding_returns_paths_relative_to_the_source_dir(tmp_path: Path) -> None:
    # The receipt has to stay meaningful after the tree is moved into Assets/.
    source = tmp_path / "Assembly-CSharp-firstpass"
    _write(source / "Properties" / "AssemblyInfo.cs")

    removed = unity_managed.strip_scaffolding(source)

    assert removed == ["Properties/AssemblyInfo.cs"]
    assert not any(Path(entry).is_absolute() for entry in removed)


def test_strip_scaffolding_prunes_a_properties_dir_it_emptied(tmp_path: Path) -> None:
    # An empty Properties/ would be imported by Unity as a stray asset folder.
    source = tmp_path / "Assembly-CSharp"
    _write(source / "Properties" / "AssemblyInfo.cs")

    unity_managed.strip_scaffolding(source)

    assert not (source / "Properties").exists()


def test_strip_scaffolding_keeps_a_directory_that_still_holds_source(tmp_path: Path) -> None:
    source = tmp_path / "Assembly-CSharp"
    _write(source / "Properties" / "AssemblyInfo.cs")
    sibling = _write(source / "Properties" / "Settings.cs", "public class Settings {}\n")

    unity_managed.strip_scaffolding(source)

    assert sibling.is_file()
    assert (source / "Properties").is_dir()


def test_strip_scaffolding_leaves_a_tree_without_scaffolding_untouched(tmp_path: Path) -> None:
    source = tmp_path / "Assembly-CSharp"
    _write(source / "Game" / "Player.cs")

    assert unity_managed.strip_scaffolding(source) == []
    assert (source / "Game" / "Player.cs").is_file()


def test_strip_scaffolding_returns_empty_for_a_missing_directory(tmp_path: Path) -> None:
    assert unity_managed.strip_scaffolding(tmp_path / "never-decompiled") == []


# --- discover_game_assemblies ------------------------------------------------


def _managed(tmp_path: Path, *names: str) -> Path:
    data_dir = tmp_path / "Game_Data"
    managed = data_dir / "Managed"
    managed.mkdir(parents=True)
    for name in names:
        (managed / name).write_bytes(b"MZ")
    return data_dir


def test_discover_game_assemblies_finds_the_default_pair(tmp_path: Path) -> None:
    data_dir = _managed(
        tmp_path,
        "Assembly-CSharp.dll",
        "Assembly-CSharp-firstpass.dll",
        "UnityEngine.dll",
        "DOTween.dll",
    )

    found = unity_managed.discover_game_assemblies(data_dir)

    assert [path.name for path in found] == ["Assembly-CSharp.dll", "Assembly-CSharp-firstpass.dll"]


def test_discover_game_assemblies_skips_a_default_that_did_not_ship(tmp_path: Path) -> None:
    data_dir = _managed(tmp_path, "Assembly-CSharp.dll")
    assert [path.name for path in unity_managed.discover_game_assemblies(data_dir)] == ["Assembly-CSharp.dll"]


def test_discover_game_assemblies_respects_an_explicit_name_list(tmp_path: Path) -> None:
    data_dir = _managed(tmp_path, "Assembly-CSharp.dll", "DOTween.dll")

    found = unity_managed.discover_game_assemblies(data_dir, ["DOTween"])

    assert [path.name for path in found] == ["DOTween.dll"]


def test_discover_game_assemblies_accepts_names_with_or_without_the_dll_suffix(tmp_path: Path) -> None:
    data_dir = _managed(tmp_path, "DOTween.dll")

    with_suffix = unity_managed.discover_game_assemblies(data_dir, ["DOTween.DLL"])
    without_suffix = unity_managed.discover_game_assemblies(data_dir, ["DOTween"])

    assert with_suffix == without_suffix == [data_dir / "Managed" / "DOTween.dll"]


def test_discover_game_assemblies_returns_empty_without_a_managed_dir(tmp_path: Path) -> None:
    data_dir = tmp_path / "Game_Data"
    data_dir.mkdir()
    assert unity_managed.discover_game_assemblies(data_dir) == []


def test_default_game_assemblies_are_kept_separate(tmp_path: Path) -> None:
    # Assembly-CSharp and -firstpass may legally declare the same type names, so
    # they must stay two distinct targets rather than one merged tree.
    assert unity_managed.DEFAULT_GAME_ASSEMBLIES == ("Assembly-CSharp", "Assembly-CSharp-firstpass")
    assert len(set(unity_managed.DEFAULT_GAME_ASSEMBLIES)) == 2
