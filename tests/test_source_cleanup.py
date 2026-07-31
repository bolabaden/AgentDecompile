"""Tests for `cleanup_recovered_source_package`'s package-manifest walk.

Covers the `curated_hints` call site (U9): matching a curated hint onto a
function, leaving an unmatched function untouched, and the key-resolution
fallback precedence (`meta.entry` beats `meta.address` beats `item.entry`
beats `item.address`).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agentdecompile_recovery.source_cleanup import cleanup_recovered_source_package

pytestmark = pytest.mark.unit


def _write_function(
    package_dir: Path,
    *,
    stem: str,
    body: str,
    metadata: dict[str, Any],
) -> dict[str, str]:
    functions_dir = package_dir / "functions"
    functions_dir.mkdir(parents=True, exist_ok=True)
    source_path = functions_dir / f"{stem}.c"
    metadata_path = functions_dir / f"{stem}.json"
    source_path.write_text(body, encoding="utf-8")
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    return {
        "source": str(source_path.relative_to(package_dir)),
        "metadata": str(metadata_path.relative_to(package_dir)),
    }


def _write_manifest(package_dir: Path, functions: list[dict[str, Any]]) -> None:
    manifest = {
        "schema": "agentdecompile.recovered-source-package.v1",
        "status": "complete",
        "functions": functions,
        "functionCount": len(functions),
        "factCount": 0,
        "taskCount": 0,
        "claimBoundary": "test package",
    }
    (package_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def test_curated_hint_matched_by_entry_renames_local(tmp_path: Path) -> None:
    package_dir = tmp_path / "package"
    body = "int fn(void) { int local_8; local_8 = 1; return local_8; }\n"
    entry = _write_function(
        package_dir,
        stem="fn_00401000",
        body=body,
        metadata={"name": "fn", "entry": "00401000", "functionFact": {}},
    )
    _write_manifest(package_dir, [entry])

    curated_hints = {
        "00401000": {"plateComment": None, "locals": [{"name": "counter", "slot": "local_8"}]},
    }

    result = cleanup_recovered_source_package(
        package_dir=package_dir,
        out_dir=tmp_path / "cleaned",
        curated_hints=curated_hints,
    )

    assert result["functionCount"] == 1
    cleaned_source = Path(result["functions"][0]["source"])
    cleaned_text = cleaned_source.read_text(encoding="utf-8")
    assert "counter" in cleaned_text
    assert "local_8" not in cleaned_text


def test_curated_hints_supplied_but_no_match_leaves_function_unaffected(tmp_path: Path) -> None:
    package_dir = tmp_path / "package"
    body = "int fn(void) { int local_8; local_8 = 1; return local_8; }\n"
    entry = _write_function(
        package_dir,
        stem="fn_00401000",
        body=body,
        metadata={"name": "fn", "entry": "00401000", "functionFact": {}},
    )
    _write_manifest(package_dir, [entry])

    curated_hints = {
        "00402000": {"plateComment": None, "locals": [{"name": "counter", "slot": "local_8"}]},
    }

    result = cleanup_recovered_source_package(
        package_dir=package_dir,
        out_dir=tmp_path / "cleaned",
        curated_hints=curated_hints,
    )

    cleaned_source = Path(result["functions"][0]["source"])
    cleaned_text = cleaned_source.read_text(encoding="utf-8")
    assert "local_8" in cleaned_text
    assert "counter" not in cleaned_text


def test_curated_hints_key_resolution_prefers_meta_entry_over_other_fields(tmp_path: Path) -> None:
    """`meta.entry` must win over `meta.address` / `item.entry` / `item.address`."""

    package_dir = tmp_path / "package"
    body = "int fn(void) { int local_8; local_8 = 1; return local_8; }\n"
    entry = _write_function(
        package_dir,
        stem="fn_00401000",
        body=body,
        metadata={
            "name": "fn",
            "entry": "00401000",
            "address": "00402000",
            "functionFact": {},
        },
    )
    entry["entry"] = "00403000"
    entry["address"] = "00404000"
    _write_manifest(package_dir, [entry])

    curated_hints = {
        "00401000": {"plateComment": None, "locals": [{"name": "fromMetaEntry", "slot": "local_8"}]},
        "00402000": {"plateComment": None, "locals": [{"name": "fromMetaAddress", "slot": "local_8"}]},
        "00403000": {"plateComment": None, "locals": [{"name": "fromItemEntry", "slot": "local_8"}]},
        "00404000": {"plateComment": None, "locals": [{"name": "fromItemAddress", "slot": "local_8"}]},
    }

    result = cleanup_recovered_source_package(
        package_dir=package_dir,
        out_dir=tmp_path / "cleaned",
        curated_hints=curated_hints,
    )

    cleaned_source = Path(result["functions"][0]["source"])
    cleaned_text = cleaned_source.read_text(encoding="utf-8")
    assert "fromMetaEntry" in cleaned_text
    assert "fromMetaAddress" not in cleaned_text
    assert "fromItemEntry" not in cleaned_text
    assert "fromItemAddress" not in cleaned_text
