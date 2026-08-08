"""Unit tests for composing a re-openable Unity project out of exported trees.

Everything here is filesystem work on tmp_path -- no exporter, no Editor. The
class of regression these protect against is the one the module was written to
stop: composition quietly destroying something it did not create.

Concretely, they pin down that merging is additive (a pre-existing file the
export knows nothing about survives), that an existing package pin always beats
an incoming guessed ``"*"``, that an unparseable manifest is backed up rather
than overwritten, that plugin ``.meta`` GUIDs are derived from the path so a
re-run cannot rebind every reference to a plugin, that duplicate-type risks are
*reported* and not deleted, and that composing into a directory which already
holds a project at a different editor version preserves its
``ProjectVersion.txt`` instead of triggering an irreversible asset upgrade.
"""

from __future__ import annotations

import json

from pathlib import Path

import pytest

from agentdecompile_recovery import unity_compose

pytestmark = pytest.mark.unit


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _project_version(version: str) -> str:
    return f"m_EditorVersion: {version}\nm_EditorVersionWithRevision: {version} (abcdef012345)\n"


# --- merge_tree --------------------------------------------------------------


def test_merge_tree_copies_nested_structure_and_reports_counts(tmp_path: Path) -> None:
    src = tmp_path / "src"
    _write(src / "a.txt", "a")
    _write(src / "deep" / "nested" / "b.txt", "bb")

    counts = unity_compose.merge_tree(src, tmp_path / "dst")

    assert (tmp_path / "dst" / "deep" / "nested" / "b.txt").read_text(encoding="utf-8") == "bb"
    assert counts["copied"] == 2
    assert counts["directories"] == 2
    assert counts["bytes"] == 3
    assert counts["sourceMissing"] == 0


def test_merge_tree_is_additive_and_keeps_unrelated_destination_files(tmp_path: Path) -> None:
    # The target may be someone's real repo; a merge must never behave like a sync.
    src = tmp_path / "src"
    _write(src / "shared.txt", "from export")
    dst = tmp_path / "dst"
    _write(dst / "mine.txt", "hand written")
    _write(dst / "shared.txt", "older")

    counts = unity_compose.merge_tree(src, dst, overwrite=True)

    assert (dst / "mine.txt").read_text(encoding="utf-8") == "hand written"
    assert (dst / "shared.txt").read_text(encoding="utf-8") == "from export"
    assert counts["copied"] == 1


def test_merge_tree_honors_overwrite_false(tmp_path: Path) -> None:
    src = tmp_path / "src"
    _write(src / "shared.txt", "from export")
    dst = tmp_path / "dst"
    _write(dst / "shared.txt", "keep")

    counts = unity_compose.merge_tree(src, dst, overwrite=False)

    assert (dst / "shared.txt").read_text(encoding="utf-8") == "keep"
    assert counts["skipped"] == 1
    assert counts["copied"] == 0


def test_merge_tree_excludes_by_relative_path(tmp_path: Path) -> None:
    src = tmp_path / "src"
    _write(src / "Game.cs", "class Game {}")
    _write(src / "Game.csproj", "<Project />")
    _write(src / "Properties" / "AssemblyInfo.cs", "[assembly: X]")

    counts = unity_compose.merge_tree(src, tmp_path / "dst", exclude=unity_compose._ilspy_project_artifact)

    dst = tmp_path / "dst"
    assert (dst / "Game.cs").is_file()
    assert not (dst / "Game.csproj").exists()
    assert not (dst / "Properties" / "AssemblyInfo.cs").exists()
    assert counts["excluded"] == 2
    assert counts["copied"] == 1


def test_merge_tree_reports_a_missing_source_instead_of_raising(tmp_path: Path) -> None:
    counts = unity_compose.merge_tree(tmp_path / "nope", tmp_path / "dst")
    assert counts["sourceMissing"] == 1
    assert counts["copied"] == 0


# --- package manifest --------------------------------------------------------


def _manifest(tmp_path: Path, payload: dict[str, object]) -> Path:
    return _write(tmp_path / "Packages" / "manifest.json", json.dumps(payload, indent=2))


def test_augment_package_manifest_uses_the_emitted_manifest_as_the_base(tmp_path: Path) -> None:
    path = _manifest(tmp_path, {"dependencies": {"com.unity.modules.ui": "1.0.0"}})

    result = unity_compose.augment_package_manifest(path, {"com.unity.inputsystem": "*"})

    written = json.loads(path.read_text(encoding="utf-8"))
    # The built-ins AssetRipper emitted for *this* build must survive augmentation.
    assert written["dependencies"]["com.unity.modules.ui"] == "1.0.0"
    assert written["dependencies"]["com.unity.inputsystem"] == "*"
    assert result["existed"] is True
    assert result["synthesized"] is False
    assert result["added"] == ["com.unity.inputsystem"]


def test_augment_package_manifest_keeps_an_existing_pin_over_an_incoming_star(tmp_path: Path) -> None:
    # A version the export knows beats a version we guessed from assembly names.
    path = _manifest(tmp_path, {"dependencies": {"com.unity.ugui": "1.0.0"}})

    result = unity_compose.augment_package_manifest(path, {"com.unity.ugui": "*"})

    assert json.loads(path.read_text(encoding="utf-8"))["dependencies"]["com.unity.ugui"] == "1.0.0"
    assert result["preserved"] == ["com.unity.ugui"]
    assert result["added"] == []


def test_augment_package_manifest_writes_dependencies_sorted(tmp_path: Path) -> None:
    path = _manifest(tmp_path, {"dependencies": {"com.unity.zzz": "1.0.0", "com.unity.aaa": "1.0.0"}})

    unity_compose.augment_package_manifest(path, {"com.unity.mmm": "*"})

    written = json.loads(path.read_text(encoding="utf-8"))
    assert list(written["dependencies"]) == ["com.unity.aaa", "com.unity.mmm", "com.unity.zzz"]


def test_augment_package_manifest_is_idempotent(tmp_path: Path) -> None:
    path = _manifest(tmp_path, {"dependencies": {"com.unity.modules.ui": "1.0.0"}})
    extra = {"com.unity.inputsystem": "*"}

    unity_compose.augment_package_manifest(path, extra)
    first = path.read_text(encoding="utf-8")
    second_result = unity_compose.augment_package_manifest(path, extra)

    assert path.read_text(encoding="utf-8") == first
    assert second_result["added"] == []
    assert second_result["preserved"] == ["com.unity.inputsystem"]


def test_augment_package_manifest_synthesizes_when_the_file_is_absent(tmp_path: Path) -> None:
    path = tmp_path / "Packages" / "manifest.json"

    result = unity_compose.augment_package_manifest(path, {"com.unity.inputsystem": "*"})

    assert result["existed"] is False
    assert result["synthesized"] is True
    assert json.loads(path.read_text(encoding="utf-8"))["dependencies"] == {"com.unity.inputsystem": "*"}


def test_augment_package_manifest_backs_up_an_unparseable_base(tmp_path: Path) -> None:
    path = _write(tmp_path / "Packages" / "manifest.json", "{ this is not json")

    result = unity_compose.augment_package_manifest(path, {"com.unity.inputsystem": "*"})

    backup = Path(str(result["backupPath"]))
    assert result["unparseableBase"] is True
    assert backup.read_text(encoding="utf-8") == "{ this is not json"
    assert json.loads(path.read_text(encoding="utf-8"))["dependencies"] == {"com.unity.inputsystem": "*"}


def test_augment_package_manifest_appends_a_scoped_registry_only_once(tmp_path: Path) -> None:
    path = _manifest(tmp_path, {"dependencies": {}})
    registry = {"name": "OpenUPM", "url": "https://package.openupm.com", "scopes": ["com.example"]}

    first = unity_compose.augment_package_manifest(path, {}, scoped_registry=registry)
    second = unity_compose.augment_package_manifest(path, {}, scoped_registry=registry)

    assert first["scopedRegistryAdded"] is True
    assert second["scopedRegistryAdded"] is False
    assert len(json.loads(path.read_text(encoding="utf-8"))["scopedRegistries"]) == 1


# --- plugin meta policy ------------------------------------------------------


def test_write_plugin_meta_policy_turns_off_reference_validation_on_an_existing_meta(tmp_path: Path) -> None:
    plugins = tmp_path / "Plugins"
    _write(plugins / "Steamworks.dll", "MZ")
    meta = _write(
        plugins / "Steamworks.dll.meta",
        "fileFormatVersion: 2\nguid: 1111\nPluginImporter:\n  serializedVersion: 2\n  validateReferences: 1\n",
    )

    touched = unity_compose.write_plugin_meta_policy(plugins)

    assert touched == [str(meta)]
    assert "validateReferences: 0" in meta.read_text(encoding="utf-8")
    # The exporter's GUID must survive: rewriting it would rebind every reference.
    assert "guid: 1111" in meta.read_text(encoding="utf-8")


def test_write_plugin_meta_policy_leaves_an_already_compliant_meta_alone(tmp_path: Path) -> None:
    plugins = tmp_path / "Plugins"
    _write(plugins / "Steamworks.dll", "MZ")
    _write(
        plugins / "Steamworks.dll.meta",
        "fileFormatVersion: 2\nguid: 1111\nPluginImporter:\n  validateReferences: 0\n",
    )

    assert unity_compose.write_plugin_meta_policy(plugins) == []


def test_write_plugin_meta_policy_generates_a_meta_when_none_was_emitted(tmp_path: Path) -> None:
    plugins = tmp_path / "Plugins"
    _write(plugins / "x86_64" / "Native.dll", "MZ")

    touched = unity_compose.write_plugin_meta_policy(plugins)

    meta = plugins / "x86_64" / "Native.dll.meta"
    body = meta.read_text(encoding="utf-8")
    assert touched == [str(meta)]
    assert body.startswith("fileFormatVersion: 2\n")
    assert f"guid: {unity_compose.meta_guid_for('x86_64/Native.dll')}" in body
    assert "validateReferences: 0" in body


def test_write_plugin_meta_policy_returns_empty_for_a_missing_plugins_dir(tmp_path: Path) -> None:
    assert unity_compose.write_plugin_meta_policy(tmp_path / "nope") == []


def test_meta_guid_for_is_deterministic_and_path_dependent() -> None:
    guid = unity_compose.meta_guid_for("x86_64/Native.dll")
    assert guid == unity_compose.meta_guid_for("x86_64/Native.dll")
    assert len(guid) == 32
    assert guid == guid.lower()
    assert all(char in "0123456789abcdef" for char in guid)
    assert guid != unity_compose.meta_guid_for("x86/Native.dll")


def test_patch_validate_references_inserts_the_key_when_it_is_absent() -> None:
    text = "fileFormatVersion: 2\nguid: 1111\nPluginImporter:\n  serializedVersion: 2\n"
    patched, changed = unity_compose.patch_validate_references(text)
    assert changed is True
    assert "  validateReferences: 0" in patched


def test_patch_validate_references_reports_no_change_when_already_zero() -> None:
    text = "PluginImporter:\n  validateReferences: 0\n"
    patched, changed = unity_compose.patch_validate_references(text)
    assert (patched, changed) == (text, False)


# --- script conflict reporting ----------------------------------------------


def test_resolve_script_conflicts_counts_superseded_files_without_deleting_them(tmp_path: Path) -> None:
    exported = tmp_path / "exported"
    ilspy = tmp_path / "ilspy"
    _write(exported / "Game" / "Player.cs", "// stub")
    _write(exported / "Game" / "OnlyExported.cs", "// stub")
    _write(ilspy / "Game" / "Player.cs", "// real body")
    _write(ilspy / "Game" / "OnlyIlspy.cs", "// real body")

    report = unity_compose.resolve_script_conflicts(exported, ilspy)

    assert report["policy"] == "ilspy-wins"
    assert report["supersededCount"] == 1
    assert report["supersededFiles"] == ["game/player.cs"]
    assert report["exportedOnlyCount"] == 1
    assert report["ilspyOnlyCount"] == 1
    # Read-only: reporting must not have touched either tree.
    assert (exported / "Game" / "Player.cs").is_file()
    assert (ilspy / "Game" / "OnlyIlspy.cs").is_file()


def test_resolve_script_conflicts_flags_a_same_type_at_a_different_path_as_a_duplicate_risk(tmp_path: Path) -> None:
    # Two definitions of one type survive the overwrite and become CS0101 at import
    # time; guessing which file is real is exactly what this module refuses to do.
    exported = tmp_path / "exported"
    ilspy = tmp_path / "ilspy"
    _write(exported / "Assembly-CSharp" / "Enemy.cs", "// stub")
    _write(ilspy / "Assembly-CSharp" / "AI" / "Enemy.cs", "// real body")

    report = unity_compose.resolve_script_conflicts(exported, ilspy)

    assert report["supersededCount"] == 0
    assert report["duplicateTypeRiskCount"] == 1
    risk = report["duplicateTypeRisks"][0]
    assert risk["type"] == "enemy"
    assert risk["exported"] == ["assembly-csharp/enemy.cs"]
    assert risk["ilspy"] == ["assembly-csharp/ai/enemy.cs"]
    assert (exported / "Assembly-CSharp" / "Enemy.cs").is_file()
    assert (ilspy / "Assembly-CSharp" / "AI" / "Enemy.cs").is_file()


def test_resolve_script_conflicts_handles_missing_trees(tmp_path: Path) -> None:
    report = unity_compose.resolve_script_conflicts(tmp_path / "nope", tmp_path / "also-nope")
    assert report["exportedFileCount"] == 0
    assert report["ilspyFileCount"] == 0
    assert report["duplicateTypeRiskCount"] == 0


# --- compose_unity_project ---------------------------------------------------


def _exported_project(tmp_path: Path, *, version: str = "2022.3.62f2") -> Path:
    exported = tmp_path / "rip" / "ExportedProject"
    _write(exported / "Assets" / "Scenes" / "Main.unity", "%YAML 1.1\n")
    _write(exported / "ProjectSettings" / "ProjectVersion.txt", _project_version(version))
    _write(
        exported / "Packages" / "manifest.json",
        json.dumps({"dependencies": {"com.unity.modules.ui": "1.0.0"}}, indent=2),
    )
    return exported


def test_compose_unity_project_reports_ready_when_the_openable_markers_land(tmp_path: Path) -> None:
    exported = _exported_project(tmp_path)
    target = tmp_path / "recovered"

    receipt = unity_compose.compose_unity_project(exported, target, extra_packages={"com.unity.inputsystem": "*"})

    assert receipt["status"] == "complete"
    assert receipt["openable"]["ready"] is True
    assert receipt["openable"]["missing"] == []
    assert receipt["openable"]["editorVersion"] == "2022.3.62f2"
    assert (target / "Assets" / "Scenes" / "Main.unity").is_file()
    assert json.loads((target / "Packages" / "manifest.json").read_text(encoding="utf-8"))["dependencies"] == {
        "com.unity.inputsystem": "*",
        "com.unity.modules.ui": "1.0.0",
    }


def test_compose_unity_project_preserves_a_conflicting_pre_existing_project_version(tmp_path: Path) -> None:
    # Silently rewriting ProjectVersion.txt is how you trigger an irreversible
    # asset upgrade in someone else's project.
    exported = _exported_project(tmp_path, version="2022.3.62f2")
    target = tmp_path / "recovered"
    _write(target / "ProjectSettings" / "ProjectVersion.txt", _project_version("2021.3.30f1"))
    keep = _write(target / "Assets" / "MyWork" / "notes.txt", "hand written")

    receipt = unity_compose.compose_unity_project(exported, target)

    assert receipt["preExistingProject"]["detected"] is True
    assert receipt["preExistingProject"]["editorVersion"] == "2021.3.30f1"
    assert receipt["preExistingProject"]["versionConflict"] is True
    assert receipt["preExistingProject"]["projectVersionPreserved"] is True
    assert unity_compose.read_editor_version(target / "ProjectSettings") == "2021.3.30f1"
    assert receipt["openable"]["exportEditorVersion"] == "2022.3.62f2"
    assert any("2021.3.30f1" in warning for warning in receipt["warnings"])
    # An unrelated pre-existing file has nothing to do with the export and must survive.
    assert keep.read_text(encoding="utf-8") == "hand written"


def test_compose_unity_project_records_no_conflict_when_versions_agree(tmp_path: Path) -> None:
    exported = _exported_project(tmp_path, version="2022.3.62f2")
    target = tmp_path / "recovered"
    _write(target / "ProjectSettings" / "ProjectVersion.txt", _project_version("2022.3.62f2"))

    receipt = unity_compose.compose_unity_project(exported, target)

    assert receipt["preExistingProject"]["versionConflict"] is False
    assert receipt["warnings"] == []


def test_compose_unity_project_layers_ilspy_source_and_drops_msbuild_scaffolding(tmp_path: Path) -> None:
    exported = _exported_project(tmp_path)
    _write(exported / "Assets" / "Scripts" / "Player.cs", "// AssetRipper stub")
    managed = tmp_path / "managed" / "Assembly-CSharp"
    _write(managed / "Player.cs", "// ILSpy body")
    _write(managed / "Assembly-CSharp.csproj", "<Project />")
    target = tmp_path / "recovered"

    receipt = unity_compose.compose_unity_project(exported, target, managed_source=managed)

    assert receipt["scripts"]["applied"] is True
    assert (target / "Assets" / "Scripts" / "Player.cs").read_text(encoding="utf-8") == "// ILSpy body"
    assert not (target / "Assets" / "Scripts" / "Assembly-CSharp.csproj").exists()


def test_compose_unity_project_rejects_a_directory_that_is_not_an_export(tmp_path: Path) -> None:
    from agentdecompile_recovery.tools import ToolchainError

    not_an_export = tmp_path / "random"
    (not_an_export / "stuff").mkdir(parents=True)

    with pytest.raises(ToolchainError):
        unity_compose.compose_unity_project(not_an_export, tmp_path / "recovered")
