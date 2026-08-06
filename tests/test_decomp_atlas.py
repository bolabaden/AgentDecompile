"""Tests for decomp_atlas.py, ported from the upstream reference retrieval module.

decomp_atlas is a self-contained, stdlib-only local retrieval tool: it scores
matched prompt folders and feature-index rows against a query by simple token
overlap, to surface similar already-matched examples as advisory prompt
context. It never claims a match itself -- objdiff zero remains the gate.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentdecompile_recovery.decomp_atlas import (
    load_index_rows,
    load_jsonl,
    parse_simple_case_yaml,
    query_keys,
    run_decomp_atlas,
    write_prompt_similar_examples,
)

pytestmark = pytest.mark.unit


def _write_case_yaml(prompt_dir: Path, **fields: str) -> None:
    prompt_dir.mkdir(parents=True, exist_ok=True)
    lines = [f"{key}: {value}" for key, value in fields.items()]
    (prompt_dir / "case.yaml").write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_load_jsonl_skips_malformed_lines(tmp_path: Path) -> None:
    path = tmp_path / "rows.jsonl"
    path.write_text('{"a": 1}\nnot json\n{"b": 2}\n\n', encoding="utf-8")

    rows = load_jsonl(path)

    assert rows == [{"a": 1}, {"b": 2}]


def test_load_jsonl_missing_file_returns_empty(tmp_path: Path) -> None:
    assert load_jsonl(tmp_path / "missing.jsonl") == []


def test_load_index_rows_tags_each_row_with_index_name(tmp_path: Path) -> None:
    index_root = tmp_path / "index"
    (index_root / "sub_1000").mkdir(parents=True)
    (index_root / "sub_1000" / "retrieval.jsonl").write_text('{"name": "sub_1000"}\n', encoding="utf-8")

    rows = load_index_rows(index_root, "retrieval.jsonl")

    assert rows == [{"name": "sub_1000", "_index": "sub_1000"}]


def test_query_keys_extracts_fun_and_hex_addresses() -> None:
    keys = query_keys("looking at FUN_00401230 near fcn.401240 and 004012a0")

    assert "fun_00401230" in keys
    assert "401240" in keys
    assert "fun_401240" in keys
    assert "004012a0" in keys


def test_parse_simple_case_yaml_strips_quotes() -> None:
    path_content = 'status: matched\nfunctionName: "sub_1234"\n'
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "case.yaml"
        path.write_text(path_content, encoding="utf-8")
        values = parse_simple_case_yaml(path)

    assert values == {"status": "matched", "functionName": "sub_1234"}


def test_run_decomp_atlas_finds_matched_prompt_by_exact_name(tmp_path: Path) -> None:
    prompts_dir = tmp_path / "prompts"
    target_dir = prompts_dir / "sub_1000"
    _write_case_yaml(target_dir, status="matched", functionName="sub_1000", targetFamily="stdcall-helper")
    (target_dir / "candidate.c").write_text("int sub_1000(void) { return 1; }\n", encoding="utf-8")

    index_root = tmp_path / "index"
    index_root.mkdir()

    receipt = run_decomp_atlas(
        prompt_name="sub_1000",
        query=None,
        prompts_dir=prompts_dir,
        index_root=index_root,
        top_k=5,
    )

    assert receipt["status"] == "complete"
    assert receipt["resultCount"] == 1
    assert receipt["results"][0]["name"] == "sub_1000"
    assert receipt["claimBoundary"]


def test_run_decomp_atlas_no_local_examples_when_nothing_matches(tmp_path: Path) -> None:
    prompts_dir = tmp_path / "prompts"
    prompts_dir.mkdir()
    index_root = tmp_path / "index"
    index_root.mkdir()

    receipt = run_decomp_atlas(
        prompt_name=None,
        query="nothing to find here",
        prompts_dir=prompts_dir,
        index_root=index_root,
        top_k=5,
    )

    assert receipt["status"] == "no-local-examples"
    assert receipt["results"] == []


def test_run_decomp_atlas_ignores_unmatched_prompts(tmp_path: Path) -> None:
    prompts_dir = tmp_path / "prompts"
    _write_case_yaml(prompts_dir / "sub_2000", status="pending", functionName="sub_2000")
    index_root = tmp_path / "index"
    index_root.mkdir()

    receipt = run_decomp_atlas(
        prompt_name="sub_2000",
        query=None,
        prompts_dir=prompts_dir,
        index_root=index_root,
        top_k=5,
    )

    assert receipt["promptExampleCount"] == 0


def test_write_prompt_similar_examples_inserts_section(tmp_path: Path) -> None:
    prompt_dir = tmp_path / "sub_3000"
    prompt_dir.mkdir()
    (prompt_dir / "prompt.md").write_text("# sub_3000\n\nSome existing content.\n", encoding="utf-8")
    receipt = {"results": [{"name": "sub_1000", "entry": "1000", "strategyClass": "stdcall-helper", "nearestMatchedExamples": []}]}

    result = write_prompt_similar_examples(prompt_dir, receipt)

    assert result["status"] == "updated"
    updated_text = (prompt_dir / "prompt.md").read_text(encoding="utf-8")
    assert "## Similar Examples" in updated_text
    assert "sub_1000" in updated_text


def test_write_prompt_similar_examples_skipped_when_prompt_missing(tmp_path: Path) -> None:
    prompt_dir = tmp_path / "sub_4000"
    prompt_dir.mkdir()

    result = write_prompt_similar_examples(prompt_dir, {"results": []})

    assert result == {"status": "skipped", "reason": "prompt.md not found"}
