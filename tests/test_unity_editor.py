"""Unit tests for the Unity Editor log parsers, recipe classifier, and file-delete repair.

No Editor is launched here. The point of this module's design is that the
fragile part -- turning a noisy batchmode log into structured findings, and
turning a finding into a destructive action -- is pure and testable without
Unity, so that is exactly what these cover.

The regressions guarded against are:

* a parser that raises, or silently drops the one error that explains the run,
  because Unity phrased it slightly differently (no column, no file, a Windows
  drive path, an msbuild ``[...csproj]`` suffix);
* an inflated error count from the same line being reported twice, which would
  defeat the repair loop's "did the count decrease?" convergence guard;
* routine ``[Package Manager]`` chatter being escalated into a package error;
* :func:`apply_delete_file` -- the only destructive recipe -- deleting anything
  outside ``<project>/Assets``, or acting on an error that never asked for a
  deletion.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery import unity_editor

pytestmark = pytest.mark.unit


# A single realistic log holding every compile-error shape Unity actually emits.
_COMPILE_LOG = "\n".join(
    [
        "Refreshing native plugins compatible for Editor in 1.20 ms",
        "Assets/Scripts/Game/Player.cs(12,7): error CS0246: The type or namespace name 'DOTween' could not be found",
        "Assets/Scripts/Assembly-CSharp/Properties/AssemblyInfo.cs(5,12): error CS0579: Duplicate 'AssemblyVersion' attribute",
        "Assets/Scripts/Dup.cs(3): error CS0101: The namespace '<global namespace>' already contains a definition for 'Foo'",
        r"C:\Proj\Assets\Scripts\Dup.cs(88,14): error CS0111: Type 'Foo' already defines a member called 'Bar' "
        r"with the same parameter types [C:\Proj\Assembly-CSharp.csproj]",
        # Byte-identical repeat of the first error: Unity logs it once per compile pass.
        "Assets/Scripts/Game/Player.cs(12,7): error CS0246: The type or namespace name 'DOTween' could not be found",
        "error CS0006: Metadata file 'UnityEngine.UI.dll' could not be found",
        "Exiting batchmode successfully now!",
    ]
)


def _by_code(log_text: str) -> dict[str, dict[str, object]]:
    return {str(error["code"]): error for error in unity_editor.parse_compile_errors(log_text)}


# --- compile errors ----------------------------------------------------------


def test_parse_compile_errors_extracts_file_line_column_for_the_canonical_form() -> None:
    error = _by_code(_COMPILE_LOG)["CS0246"]
    assert error["file"] == "Assets/Scripts/Game/Player.cs"
    assert error["line"] == 12
    assert error["column"] == 7
    assert error["message"] == "The type or namespace name 'DOTween' could not be found"


def test_parse_compile_errors_keeps_the_ilspy_assemblyinfo_path_intact() -> None:
    # The delete-file recipe deletes exactly this path, so it must survive parsing verbatim.
    error = _by_code(_COMPILE_LOG)["CS0579"]
    assert error["file"] == "Assets/Scripts/Assembly-CSharp/Properties/AssemblyInfo.cs"
    assert error["line"] == 5


def test_parse_compile_errors_handles_a_missing_column() -> None:
    error = _by_code(_COMPILE_LOG)["CS0101"]
    assert error["file"] == "Assets/Scripts/Dup.cs"
    assert error["line"] == 3
    assert error["column"] is None


def test_parse_compile_errors_keeps_windows_drive_paths_and_strips_the_msbuild_suffix() -> None:
    error = _by_code(_COMPILE_LOG)["CS0111"]
    assert error["file"] == r"C:\Proj\Assets\Scripts\Dup.cs"
    assert error["line"] == 88
    assert error["column"] == 14
    # The trailing " [C:\...\Assembly-CSharp.csproj]" is msbuild noise, not part of the message.
    assert error["message"] == "Type 'Foo' already defines a member called 'Bar' with the same parameter types"


def test_parse_compile_errors_captures_file_less_driver_errors() -> None:
    error = _by_code(_COMPILE_LOG)["CS0006"]
    assert error["file"] is None
    assert error["line"] is None
    assert error["message"] == "Metadata file 'UnityEngine.UI.dll' could not be found"


def test_parse_compile_errors_deduplicates_identical_lines() -> None:
    errors = unity_editor.parse_compile_errors(_COMPILE_LOG)
    # Six error lines in the log, one of which is a byte-identical repeat.
    assert len(errors) == 5
    assert [error["code"] for error in errors].count("CS0246") == 1


def test_parse_compile_errors_preserves_first_appearance_order() -> None:
    # The first error is usually the causal one; reordering would hide it.
    assert [error["code"] for error in unity_editor.parse_compile_errors(_COMPILE_LOG)] == [
        "CS0246",
        "CS0579",
        "CS0101",
        "CS0111",
        "CS0006",
    ]


# --- missing references ------------------------------------------------------


_MISSING_LOG = "\n".join(
    [
        "The referenced script (Unknown) on this Behaviour is missing!",
        "The referenced script on this Behaviour (Game Object 'Player') is missing!",
        "The referenced script on this Behaviour (Game Object 'Player') is missing!",
        "Missing GUID 0123456789ABCDEF0123456789abcdef for asset Assets/Prefabs/Enemy.prefab",
        "Could not extract GUID in text file Assets/Scenes/Main.unity at line 42.",
    ]
)


def test_parse_missing_references_reads_the_unknown_script_form() -> None:
    entry = unity_editor.parse_missing_references(_MISSING_LOG)[0]
    assert entry["kind"] == "missing-script"
    assert entry["script"] == "Unknown"
    assert entry["gameObject"] is None


def test_parse_missing_references_names_the_owning_game_object() -> None:
    entry = unity_editor.parse_missing_references(_MISSING_LOG)[1]
    assert entry["kind"] == "missing-script"
    assert entry["gameObject"] == "Player"


def test_parse_missing_references_counts_repeats_instead_of_listing_them() -> None:
    # One dead script can produce thousands of identical lines; the count carries
    # the signal without the volume, and the repair loop's guard reads that count.
    entries = unity_editor.parse_missing_references(_MISSING_LOG)
    assert len(entries) == 4
    assert entries[1]["occurrences"] == 2
    assert entries[0]["occurrences"] == 1


def test_parse_missing_references_normalizes_a_32_hex_guid_to_lowercase() -> None:
    entry = unity_editor.parse_missing_references(_MISSING_LOG)[2]
    assert entry["kind"] == "missing-guid"
    assert entry["guid"] == "0123456789abcdef0123456789abcdef"


def test_parse_missing_references_flags_an_unextractable_guid_without_inventing_one() -> None:
    entry = unity_editor.parse_missing_references(_MISSING_LOG)[3]
    assert entry["kind"] == "missing-guid"
    assert entry["guid"] is None
    assert "Could not extract GUID" in str(entry["message"])


# --- package errors ----------------------------------------------------------


_PACKAGE_LOG = "\n".join(
    [
        "[Package Manager] Done resolving packages in 2s",
        "[Package Manager] Server::Start -- Port 51023 was selected",
        "Failed to resolve packages: com.example.missing@1.2.3 is not available.",
        "Cannot find package com.unity.nope",
        "Unable to add package [com.unity.xr.openvr@2.0.0]: package not found",
    ]
)


def test_parse_package_errors_classifies_each_upm_failure_shape() -> None:
    entries = unity_editor.parse_package_errors(_PACKAGE_LOG)
    assert [entry["kind"] for entry in entries] == [
        "resolve-failed",
        "package-not-found",
        "package-add-failed",
    ]


def test_parse_package_errors_extracts_the_package_id() -> None:
    packages = {entry["package"] for entry in unity_editor.parse_package_errors(_PACKAGE_LOG)}
    assert packages == {"com.example.missing@1.2.3", "com.unity.nope", "com.unity.xr.openvr@2.0.0"}


def test_parse_package_errors_ignores_routine_package_manager_chatter() -> None:
    # "[Package Manager] Done resolving packages" is success, not a finding; reporting
    # it would make every healthy run look like it had package errors.
    benign = "[Package Manager] Done resolving packages in 2s"
    assert unity_editor.parse_package_errors(benign) == []


# --- parser robustness -------------------------------------------------------


@pytest.mark.parametrize(
    "parser",
    [
        unity_editor.parse_compile_errors,
        unity_editor.parse_missing_references,
        unity_editor.parse_package_errors,
    ],
)
def test_parsers_return_empty_on_empty_input(parser) -> None:  # noqa: ANN001 - parametrized callable
    assert parser("") == []


@pytest.mark.parametrize(
    "parser",
    [
        unity_editor.parse_compile_errors,
        unity_editor.parse_missing_references,
        unity_editor.parse_package_errors,
    ],
)
def test_parsers_return_empty_on_a_clean_log(parser) -> None:  # noqa: ANN001 - parametrized callable
    clean = "\n".join(
        [
            "Initialize engine version: 2022.3.62f2 (b1cbc9a29b8d)",
            "Refreshing native plugins compatible for Editor in 1.20 ms",
            "[Package Manager] Done resolving packages in 2s",
            "[ADRecoveryValidate] wrote report: /proj/Temp/adrecovery-validate.json",
            "Exiting batchmode successfully now!",
        ]
    )
    assert parser(clean) == []


# --- summary -----------------------------------------------------------------


def test_summarize_log_counts_findings_and_marks_the_run_dirty() -> None:
    summary = unity_editor.summarize_log("\n".join([_COMPILE_LOG, _MISSING_LOG, _PACKAGE_LOG]))

    assert summary["compileErrorCount"] == 5
    assert summary["compileErrorCodes"] == {"CS0246": 1, "CS0579": 1, "CS0101": 1, "CS0111": 1, "CS0006": 1}
    assert summary["missingReferenceCount"] == 4
    # Occurrences, not distinct entries: the duplicated Player line counts twice.
    assert summary["missingReferenceOccurrences"] == 5
    assert summary["missingReferenceKinds"] == {"missing-script": 3, "missing-guid": 2}
    assert summary["packageErrorCount"] == 3
    assert summary["clean"] is False


def test_summarize_log_is_clean_when_only_missing_references_are_present() -> None:
    # Missing scripts do not stop a project from opening, so they must not flip
    # `clean` -- only compile and package failures do.
    summary = unity_editor.summarize_log(_MISSING_LOG)
    assert summary["missingReferenceCount"] == 4
    assert summary["clean"] is True


def test_summarize_log_is_clean_on_an_empty_log() -> None:
    summary = unity_editor.summarize_log("")
    assert summary["clean"] is True
    assert summary["compileErrors"] == []


# --- classification ----------------------------------------------------------


@pytest.mark.parametrize(
    ("code", "recipe"),
    [
        ("CS0579", "delete-file"),
        ("CS0101", "dedupe-type"),
        ("CS0111", "dedupe-type"),
        ("CS0246", "resolve-missing-type"),
        ("CS0234", "resolve-missing-type"),
    ],
)
def test_classify_error_maps_compile_codes_to_recipes(code: str, recipe: str) -> None:
    assert unity_editor.classify_error({"code": code}) == recipe


@pytest.mark.parametrize(
    ("kind", "recipe"),
    [
        ("missing-script", "remap-guid"),
        ("missing-guid", "remap-guid"),
        ("resolve-failed", "relax-package"),
        ("package-not-found", "relax-package"),
        ("package-add-failed", "relax-package"),
    ],
)
def test_classify_error_maps_finding_kinds_to_recipes(kind: str, recipe: str) -> None:
    assert unity_editor.classify_error({"kind": kind}) == recipe


def test_classify_error_returns_none_for_an_unknown_code() -> None:
    # Silence is the honest answer: inventing a recipe would let the repair loop
    # fire a destructive action on an error nobody has a fix for.
    assert unity_editor.classify_error({"code": "CS9999", "file": "Assets/X.cs"}) is None


def test_classify_error_never_raises_on_junk_input() -> None:
    assert unity_editor.classify_error({}) is None
    assert unity_editor.classify_error("not a dict") is None  # type: ignore[arg-type]
    assert unity_editor.classify_error({"code": 579}) is None


def test_every_classified_recipe_has_documentation_and_an_applier() -> None:
    assert set(unity_editor.RECIPE_APPLIERS) == set(unity_editor.RECIPES)
    assert unity_editor.IMPLEMENTED_RECIPES <= set(unity_editor.RECIPES)


# --- apply_delete_file (the only destructive recipe) -------------------------


def _project(tmp_path: Path) -> Path:
    project = tmp_path / "project"
    (project / "Assets" / "Scripts" / "Properties").mkdir(parents=True)
    return project


def _assembly_info(project: Path) -> Path:
    target = project / "Assets" / "Scripts" / "Properties" / "AssemblyInfo.cs"
    target.write_text("[assembly: AssemblyVersion(\"1.0.0.0\")]\n", encoding="utf-8")
    return target


def _cs0579(file_path: str) -> dict[str, object]:
    return {
        "file": file_path,
        "line": 5,
        "column": 12,
        "code": "CS0579",
        "message": "Duplicate 'AssemblyVersion' attribute",
    }


def test_apply_delete_file_removes_the_source_file_and_its_meta(tmp_path: Path) -> None:
    project = _project(tmp_path)
    target = _assembly_info(project)
    meta = target.with_name(target.name + ".meta")
    meta.write_text("fileFormatVersion: 2\nguid: deadbeef\n", encoding="utf-8")

    result = unity_editor.apply_delete_file(project, _cs0579("Assets/Scripts/Properties/AssemblyInfo.cs"))

    assert result["status"] == "applied"
    assert not target.exists()
    assert not meta.exists()
    assert sorted(result["deleted"]) == sorted([str(target), str(meta)])


def test_apply_delete_file_refuses_an_absolute_path_outside_the_project(tmp_path: Path) -> None:
    project = _project(tmp_path)
    outside = tmp_path / "outside.cs"
    outside.write_text("keep me\n", encoding="utf-8")

    result = unity_editor.apply_delete_file(project, _cs0579(str(outside)))

    assert result["status"] == "refused"
    assert outside.is_file()


def test_apply_delete_file_refuses_dotdot_traversal(tmp_path: Path) -> None:
    project = _project(tmp_path)
    outside = tmp_path / "outside.cs"
    outside.write_text("keep me\n", encoding="utf-8")

    result = unity_editor.apply_delete_file(project, _cs0579("Assets/../../outside.cs"))

    assert result["status"] == "refused"
    assert "outside" in str(result["reason"])
    assert outside.is_file()


def test_apply_delete_file_refuses_a_symlink_that_escapes_the_project(tmp_path: Path) -> None:
    # The containment check resolves symlinks first, so a link living inside
    # Assets/ cannot be used as a handle on a file outside the project.
    project = _project(tmp_path)
    outside = tmp_path / "outside.cs"
    outside.write_text("keep me\n", encoding="utf-8")
    link = project / "Assets" / "Scripts" / "Escape.cs"
    link.symlink_to(outside)

    result = unity_editor.apply_delete_file(project, _cs0579("Assets/Scripts/Escape.cs"))

    assert result["status"] == "refused"
    assert outside.is_file()
    assert link.is_symlink()


def test_apply_delete_file_refuses_the_assets_directory_itself(tmp_path: Path) -> None:
    project = _project(tmp_path)
    result = unity_editor.apply_delete_file(project, _cs0579("Assets"))

    assert result["status"] == "refused"
    assert (project / "Assets").is_dir()


def test_apply_delete_file_refuses_an_error_that_does_not_ask_for_a_deletion(tmp_path: Path) -> None:
    project = _project(tmp_path)
    target = _assembly_info(project)
    error = {
        "file": "Assets/Scripts/Properties/AssemblyInfo.cs",
        "line": 5,
        "column": 12,
        "code": "CS0246",
        "message": "The type or namespace name 'DOTween' could not be found",
    }

    result = unity_editor.apply_delete_file(project, error)

    assert result["status"] == "refused"
    assert "delete-file" in str(result["reason"])
    assert target.is_file()


def test_apply_delete_file_skips_an_error_with_no_file_path(tmp_path: Path) -> None:
    project = _project(tmp_path)
    result = unity_editor.apply_delete_file(project, _cs0579(""))
    assert result["status"] == "skipped"


def test_apply_delete_file_skips_an_already_removed_file(tmp_path: Path) -> None:
    project = _project(tmp_path)
    result = unity_editor.apply_delete_file(project, _cs0579("Assets/Scripts/Properties/AssemblyInfo.cs"))
    assert result["status"] == "skipped"
    assert "does not exist" in str(result["reason"])


def test_unimplemented_recipes_report_themselves_instead_of_faking_success(tmp_path: Path) -> None:
    # A stub that returned "applied" would make the repair loop report a
    # convergence it never achieved.
    project = _project(tmp_path)
    for recipe in sorted(set(unity_editor.RECIPE_APPLIERS) - unity_editor.IMPLEMENTED_RECIPES):
        result = unity_editor.RECIPE_APPLIERS[recipe](project, {"code": "CS0101"})
        assert result["status"] == "not-implemented"
        assert result["recipe"] == recipe


# --- validator installation --------------------------------------------------


def test_install_validator_rewrites_a_stale_probe(tmp_path: Path) -> None:
    project = _project(tmp_path)
    stale = project / unity_editor.VALIDATOR_RELATIVE_PATH
    stale.parent.mkdir(parents=True, exist_ok=True)
    stale.write_text("// an older probe that would report a different shape\n", encoding="utf-8")

    written = unity_editor.install_validator(project)

    assert written == stale
    assert written.read_text(encoding="utf-8") == unity_editor.VALIDATOR_SOURCE
    assert unity_editor.VALIDATOR_METHOD.split(".")[0] in unity_editor.VALIDATOR_SOURCE
