"""Unit tests for Unity install probing and reconstruction planning.

No real Unity player ships in this repo, so these build minimal synthetic
``*_Data`` layouts on tmp_path. That is enough to cover the whole point of the
module: every reconstruction decision (scene build order, scripting backend,
package set, memory-driven container staging, editor selection) is derived from
the shipped layout rather than hardcoded per game.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery import unity_probe

pytestmark = pytest.mark.unit


def _make_data_dir(tmp_path: Path, *, name: str = "Game_Data", version: bytes = b"2022.3.62f2") -> Path:
    data_dir = tmp_path / name
    data_dir.mkdir()
    # Unity stores the version as an ASCII run near the head of globalgamemanagers.
    (data_dir / "globalgamemanagers").write_bytes(b"\x00" * 32 + version + b"\x00" * 32)
    return data_dir


# --- version detection -------------------------------------------------------


def test_detect_unity_version_reads_globalgamemanagers(tmp_path: Path) -> None:
    data_dir = _make_data_dir(tmp_path)
    assert unity_probe.detect_unity_version(data_dir) == "2022.3.62f2"


def test_detect_unity_version_handles_unity_6_scheme(tmp_path: Path) -> None:
    data_dir = _make_data_dir(tmp_path, version=b"6000.5.6f1")
    assert unity_probe.detect_unity_version(data_dir) == "6000.5.6f1"


def test_detect_unity_version_returns_none_when_absent(tmp_path: Path) -> None:
    data_dir = tmp_path / "Game_Data"
    data_dir.mkdir()
    (data_dir / "globalgamemanagers").write_bytes(b"\x00" * 64)
    assert unity_probe.detect_unity_version(data_dir) is None


# --- scripting backend -------------------------------------------------------


def test_detect_scripting_backend_mono(tmp_path: Path) -> None:
    data_dir = _make_data_dir(tmp_path)
    managed = data_dir / "Managed"
    managed.mkdir()
    (managed / "Assembly-CSharp.dll").write_bytes(b"MZ")
    assert unity_probe.detect_scripting_backend(tmp_path, data_dir) == "mono"


def test_detect_scripting_backend_il2cpp(tmp_path: Path) -> None:
    data_dir = _make_data_dir(tmp_path)
    (data_dir / "il2cpp_data").mkdir()
    (tmp_path / "GameAssembly.dll").write_bytes(b"MZ")
    assert unity_probe.detect_scripting_backend(tmp_path, data_dir) == "il2cpp"


def test_detect_scripting_backend_unknown_when_no_markers(tmp_path: Path) -> None:
    data_dir = _make_data_dir(tmp_path)
    assert unity_probe.detect_scripting_backend(tmp_path, data_dir) == "unknown"


# --- scenes ------------------------------------------------------------------


def test_discover_scenes_recovers_build_order_from_level_filenames(tmp_path: Path) -> None:
    data_dir = _make_data_dir(tmp_path)
    # Created out of order on purpose: build index comes from the name, not walk order.
    for index in (2, 0, 3, 1):
        (data_dir / f"level{index}").write_bytes(b"x" * (index + 1))
    (data_dir / "level2.resS").write_bytes(b"y" * 10)

    scenes = unity_probe.discover_scenes(data_dir)

    assert [scene["buildIndex"] for scene in scenes] == [0, 1, 2, 3]
    assert [scene["container"] for scene in scenes] == ["level0", "level1", "level2", "level3"]
    assert scenes[2]["streamedResourceBytes"] == 10
    assert scenes[0]["streamedResourceBytes"] == 0


def test_discover_scenes_ignores_non_level_containers(tmp_path: Path) -> None:
    data_dir = _make_data_dir(tmp_path)
    (data_dir / "level0").write_bytes(b"x")
    (data_dir / "sharedassets0.assets").write_bytes(b"x")
    (data_dir / "resources.assets").write_bytes(b"x")
    (data_dir / "levelfoo").write_bytes(b"x")

    assert [scene["container"] for scene in unity_probe.discover_scenes(data_dir)] == ["level0"]


# --- assemblies and packages -------------------------------------------------


def test_discover_managed_assemblies_classifies_game_and_third_party(tmp_path: Path) -> None:
    data_dir = _make_data_dir(tmp_path)
    managed = data_dir / "Managed"
    managed.mkdir()
    for name in ("Assembly-CSharp", "Assembly-CSharp-firstpass", "UnityEngine", "DOTween", "Unity.InputSystem"):
        (managed / f"{name}.dll").write_bytes(b"MZ")

    by_name = {entry["name"]: entry for entry in unity_probe.discover_managed_assemblies(data_dir)}

    assert by_name["Assembly-CSharp"]["isGameAssembly"] is True
    assert by_name["Assembly-CSharp-firstpass"]["isGameAssembly"] is True
    assert by_name["DOTween"]["isThirdParty"] is True
    assert by_name["UnityEngine"]["isThirdParty"] is False
    # Assembly-CSharp* is first-party to the game, not a third-party plugin.
    assert by_name["Assembly-CSharp"]["isThirdParty"] is False


def test_map_assemblies_to_packages_derives_upm_ids() -> None:
    assemblies = [
        {"name": "Unity.InputSystem", "package": "com.unity.inputsystem"},
        {"name": "UnityEngine.UI", "package": "com.unity.ugui"},
        {"name": "SomeGameCode", "package": None},
    ]
    assert unity_probe.map_assemblies_to_packages(assemblies) == {
        "com.unity.inputsystem": "*",
        "com.unity.ugui": "*",
    }


def test_detect_xr_flags_vr_builds() -> None:
    assemblies = [{"name": "Unity.XR.OpenVR"}, {"name": "SteamVR"}, {"name": "DOTween"}]
    result = unity_probe.detect_xr(assemblies)
    assert result["present"] is True
    assert "SteamVR" in result["assemblies"]
    assert "DOTween" not in result["assemblies"]


def test_detect_xr_absent_on_flat_build() -> None:
    assert unity_probe.detect_xr([{"name": "DOTween"}])["present"] is False


# --- probe receipt -----------------------------------------------------------


def test_probe_reports_not_detected_without_data_dir(tmp_path: Path) -> None:
    probe = unity_probe.probe_unity_install(tmp_path)
    assert probe["status"] == "complete"
    assert probe["detected"] is False
    assert "claimBoundary" in probe


def test_probe_errors_on_missing_install_root(tmp_path: Path) -> None:
    probe = unity_probe.probe_unity_install(tmp_path / "nope")
    assert probe["status"] == "error"
    assert probe["detected"] is False


def test_probe_collects_facts_for_a_mono_game(tmp_path: Path) -> None:
    data_dir = _make_data_dir(tmp_path)
    managed = data_dir / "Managed"
    managed.mkdir()
    (managed / "Assembly-CSharp.dll").write_bytes(b"MZ")
    (managed / "Unity.InputSystem.dll").write_bytes(b"MZ")
    (data_dir / "level0").write_bytes(b"x")
    (data_dir / "level1").write_bytes(b"x")

    probe = unity_probe.probe_unity_install(tmp_path)

    assert probe["detected"] is True
    assert probe["gameName"] == "Game"
    assert probe["unityVersion"] == "2022.3.62f2"
    assert probe["scriptingBackend"] == "mono"
    assert probe["sceneCount"] == 2
    assert probe["gameAssemblies"] == ["Assembly-CSharp"]
    assert probe["impliedPackages"] == {"com.unity.inputsystem": "*"}
    assert probe["dataBytes"] > 0


# --- planning ----------------------------------------------------------------


def _probe_with_containers(sizes: dict[str, int], **overrides: object) -> dict:
    probe = {
        "detected": True,
        "unityVersion": "2022.3.62f2",
        "scriptingBackend": "mono",
        "containers": [{"name": name, "sizeBytes": size} for name, size in sizes.items()],
        "dataBytes": sum(sizes.values()),
        "impliedPackages": {},
        "xr": {"present": False, "assemblies": []},
    }
    probe.update(overrides)
    return probe


def test_plan_skips_non_unity_target() -> None:
    plan = unity_probe.build_unity_plan({"detected": False, "reason": "no *_Data directory"})
    assert plan["status"] == "skipped"


def test_plan_uses_full_export_when_data_fits_budget() -> None:
    probe = _probe_with_containers({"level0": 1_000, "resources.assets": 2_000})
    plan = unity_probe.build_unity_plan(probe, max_memory_gb=8, installed_editors={})
    assert plan["export"]["mode"] == "full"
    assert plan["export"]["excludedContainers"] == []


def test_plan_drops_resources_assets_when_over_budget() -> None:
    gib = 1024**3
    probe = _probe_with_containers(
        {
            "level0": gib // 2,
            "sharedassets0.assets": gib // 2,
            "resources.assets": 8 * gib,
            "resources.assets.resS": 4 * gib,
        }
    )
    plan = unity_probe.build_unity_plan(probe, max_memory_gb=2, installed_editors={})

    assert plan["export"]["mode"] == "staged"
    assert set(plan["export"]["excludedContainers"]) == {"resources.assets", "resources.assets.resS"}
    # Scene-critical containers always survive staging -- that is the whole point.
    assert "level0" in plan["export"]["includedContainers"]
    assert "sharedassets0.assets" in plan["export"]["includedContainers"]
    assert plan["export"]["stagedBytes"] < plan["export"]["totalBytes"]


def test_plan_honors_explicit_resources_inclusion_over_budget() -> None:
    gib = 1024**3
    probe = _probe_with_containers({"level0": gib, "resources.assets": 12 * gib})
    plan = unity_probe.build_unity_plan(
        probe, max_memory_gb=2, include_resources_assets=True, installed_editors={}
    )
    assert plan["export"]["mode"] == "full"
    assert plan["export"]["excludedContainers"] == []


def test_plan_blocks_on_il2cpp() -> None:
    probe = _probe_with_containers({"level0": 10}, scriptingBackend="il2cpp")
    plan = unity_probe.build_unity_plan(probe, installed_editors={})
    assert plan["status"] == "blocked"
    assert "il2cpp" in (plan["blockedReason"] or "")


def test_plan_flags_editor_version_drift() -> None:
    probe = _probe_with_containers({"level0": 10})
    plan = unity_probe.build_unity_plan(
        probe,
        installed_editors={"6000.5.6f1": Path("/opt/unity/6000.5.6f1/Editor/Unity")},
    )
    assert plan["editor"]["selectedVersion"] == "6000.5.6f1"
    assert plan["editor"]["match"] == "fallback"
    # Opening a 2022.3 project in Unity 6 silently upgrades assets; never let that pass unrecorded.
    assert plan["editor"]["versionDrift"] is True


def test_plan_reports_no_editor_when_none_installed() -> None:
    probe = _probe_with_containers({"level0": 10})
    plan = unity_probe.build_unity_plan(probe, installed_editors={})
    assert plan["editor"]["selectedVersion"] is None
    assert plan["editor"]["match"] == "none"
    assert plan["editor"]["versionDrift"] is False


# --- staging -----------------------------------------------------------------


def test_stage_export_tree_links_only_requested_containers(tmp_path: Path) -> None:
    data_dir = _make_data_dir(tmp_path)
    (data_dir / "level0").write_bytes(b"x")
    (data_dir / "resources.assets").write_bytes(b"y" * 100)
    managed = data_dir / "Managed"
    managed.mkdir()
    (managed / "Assembly-CSharp.dll").write_bytes(b"MZ")

    result = unity_probe.stage_export_tree(data_dir, tmp_path / "staging", ["globalgamemanagers", "level0"])

    staged = Path(result["dataDir"])
    assert staged.name == "Game_Data"
    assert (staged / "level0").is_symlink()
    assert (staged / "Managed").is_symlink()
    assert not (staged / "resources.assets").exists()
    # Symlinks, not copies: staging a subset must not duplicate gigabytes.
    assert (staged / "level0").resolve() == (data_dir / "level0").resolve()


def test_stage_export_tree_is_idempotent(tmp_path: Path) -> None:
    data_dir = _make_data_dir(tmp_path)
    (data_dir / "level0").write_bytes(b"x")
    staging = tmp_path / "staging"

    first = unity_probe.stage_export_tree(data_dir, staging, ["level0"])
    second = unity_probe.stage_export_tree(data_dir, staging, ["level0"])

    assert first["linked"] == second["linked"]
    assert Path(second["dataDir"]).is_dir()
