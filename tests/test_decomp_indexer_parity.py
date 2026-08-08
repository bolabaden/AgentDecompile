"""Tests for index_parity_work_dir: the work-dir front door to the indexer.

Fixtures are built on disk in the real layout rather than mocked, matching
this repo's convention of using real files and injectable seams instead of
patched IO.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentdecompile_recovery.decomp_indexer import (
    ParityCaseIndexConfig,
    index_parity_work_dir,
)
from agentdecompile_recovery.semantic_embedder import SemanticEmbedder

pytestmark = pytest.mark.unit


def _objdiff_output(match_percent: float) -> str:
    return json.dumps(
        {
            "left": {
                "sections": [{"name": ".text", "kind": "SECTION_CODE", "match_percent": match_percent}],
                "symbols": [
                    {"name": "[.text]", "kind": "SYMBOL_SECTION", "match_percent": 0.0},
                    {"name": "_f", "kind": "SYMBOL_OBJECT", "match_percent": match_percent},
                ],
            }
        }
    )


def _write_case(
    cases_root: Path,
    name: str,
    *,
    rule: str = "packaged-source",
    profiles: dict[str, float],
    target_rows: list[str] | None = None,
    candidate_rows: list[str] | None = None,
    candidate_c: str | None = "void f(void) { }",
    entry: str = "0x401000",
) -> Path:
    case_dir = cases_root / name
    case_dir.mkdir(parents=True)
    (case_dir / "generation.json").write_text(
        json.dumps({"name": name, "rule": rule, "entry": entry, "symbol": f"_{name}"}), encoding="utf-8"
    )
    if candidate_c is not None:
        (case_dir / "candidate.c").write_text(candidate_c, encoding="utf-8")
    for index, (profile, score) in enumerate(profiles.items()):
        profile_dir = case_dir / f"profile_{index:02d}_{profile}"
        profile_dir.mkdir()
        targets = target_rows if target_rows is not None else ["push esi", "mov esi, ecx", "ret"]
        candidates = candidate_rows if candidate_rows is not None else ["push esi", "call __free", "ret"]
        (profile_dir / "verify.json").write_text(
            json.dumps(
                {
                    "status": "matched" if score >= 100 else "mismatched",
                    "output": _objdiff_output(score),
                    "alignedDiff": [
                        {"target": t, "candidate": c, "differs": t != c}
                        for t, c in zip(targets, candidates)
                    ],
                }
            ),
            encoding="utf-8",
        )
    return case_dir


@pytest.fixture
def work_dir(tmp_path: Path) -> Path:
    root = tmp_path / "parity"
    (root / "source-synthesis" / "cases").mkdir(parents=True)
    return root


def _cases(work_dir: Path) -> Path:
    return work_dir / "source-synthesis" / "cases"


class TestScanning:
    def test_indexes_a_case_with_its_match_outcome(self, work_dir: Path):
        _write_case(_cases(work_dir), "sub_1000", profiles={"O2": 73.5})
        result = index_parity_work_dir(ParityCaseIndexConfig(work_dir=work_dir))

        assert [fn.name for fn in result.dump.functions] == ["sub_1000"]
        assert result.dump.functions[0].match_percent == 73.5
        assert result.stats.matched_functions == 1

    def test_keeps_the_best_scoring_profile(self, work_dir: Path):
        _write_case(_cases(work_dir), "sub_1000", profiles={"O2": 40.0, "O1": 91.0, "Od": 12.0})
        result = index_parity_work_dir(ParityCaseIndexConfig(work_dir=work_dir))
        assert result.dump.functions[0].match_percent == 91.0

    def test_asm_code_is_the_target_column(self, work_dir: Path):
        _write_case(
            _cases(work_dir), "sub_1000", profiles={"O2": 50.0},
            target_rows=["push esi", "ret"], candidate_rows=["push edi", "ret"],
        )
        result = index_parity_work_dir(ParityCaseIndexConfig(work_dir=work_dir))
        assert result.dump.functions[0].asm_code == "push esi\nret"

    def test_call_edges_come_from_the_candidate_column(self, work_dir: Path):
        # The target object carries no relocations, so only the compiled
        # candidate names its callees.
        _write_case(
            _cases(work_dir), "sub_1000", profiles={"O2": 50.0},
            target_rows=["call 0x223d30", "ret"], candidate_rows=["call __free", "ret"],
        )
        result = index_parity_work_dir(ParityCaseIndexConfig(work_dir=work_dir))
        assert result.dump.functions[0].calls_functions == ["__free"]

    def test_entry_address_becomes_rom_address(self, work_dir: Path):
        _write_case(_cases(work_dir), "sub_1000", profiles={"O2": 50.0}, entry="0x4d6660")
        result = index_parity_work_dir(ParityCaseIndexConfig(work_dir=work_dir))
        assert result.dump.functions[0].rom_address == 0x4D6660

    def test_case_without_a_verify_report_is_skipped(self, work_dir: Path):
        case_dir = _cases(work_dir) / "sub_2000"
        (case_dir / "profile_00_O2").mkdir(parents=True)
        (case_dir / "generation.json").write_text(json.dumps({"name": "sub_2000"}), encoding="utf-8")
        result = index_parity_work_dir(ParityCaseIndexConfig(work_dir=work_dir))
        assert result.dump.functions == []

    def test_case_without_c_source_lands_in_unmatched(self, work_dir: Path):
        _write_case(_cases(work_dir), "sub_1000", profiles={"O2": 50.0}, candidate_c=None)
        result = index_parity_work_dir(ParityCaseIndexConfig(work_dir=work_dir))
        assert result.stats.matched_functions == 0
        assert result.stats.unmatched_functions == 1

    def test_same_function_across_cases_keeps_the_better_score(self, work_dir: Path):
        _write_case(_cases(work_dir), "sub_1000", profiles={"O2": 30.0})
        second = _cases(work_dir) / "sub_1000_alt"
        _write_case(_cases(work_dir), "sub_1000_alt", profiles={"O2": 88.0})
        (second / "generation.json").write_text(
            json.dumps({"name": "sub_1000", "rule": "packaged-source", "entry": "0x401000"}), encoding="utf-8"
        )
        result = index_parity_work_dir(ParityCaseIndexConfig(work_dir=work_dir))
        assert len(result.dump.functions) == 1
        assert result.dump.functions[0].match_percent == 88.0


class TestByteEmissionExclusion:
    def test_masm_byte_emission_is_excluded_by_default(self, work_dir: Path):
        # These score 100% by copying the target bytes. As worked examples
        # they teach the exact cheat the rewrite gate bans.
        _write_case(_cases(work_dir), "sub_1000", rule="compact-terminal-ret-masm", profiles={"O2": 100.0})
        result = index_parity_work_dir(ParityCaseIndexConfig(work_dir=work_dir))
        assert result.dump.functions == []

    def test_byte_emission_can_be_opted_back_in(self, work_dir: Path):
        _write_case(_cases(work_dir), "sub_1000", rule="compact-terminal-ret-masm", profiles={"O2": 100.0})
        result = index_parity_work_dir(
            ParityCaseIndexConfig(work_dir=work_dir, exclude_byte_emission_rules=False)
        )
        assert [fn.name for fn in result.dump.functions] == ["sub_1000"]


class TestFiltering:
    def test_min_match_percent_drops_low_scorers(self, work_dir: Path):
        _write_case(_cases(work_dir), "sub_low", profiles={"O2": 12.0})
        _write_case(_cases(work_dir), "sub_high", profiles={"O2": 96.0})
        result = index_parity_work_dir(ParityCaseIndexConfig(work_dir=work_dir, min_match_percent=80.0))
        assert [fn.name for fn in result.dump.functions] == ["sub_high"]


class TestEmbeddingAndIncrementality:
    def test_embeds_every_document(self, work_dir: Path):
        _write_case(_cases(work_dir), "sub_1000", profiles={"O2": 50.0})
        embedder = SemanticEmbedder(lambda texts: [[1.0, 0.0] for _ in texts])
        result = index_parity_work_dir(ParityCaseIndexConfig(work_dir=work_dir), embedder=embedder)
        assert len(result.dump.vectors) == 1

    def test_unchanged_content_reuses_its_vector(self, work_dir: Path):
        _write_case(_cases(work_dir), "sub_1000", profiles={"O2": 50.0})
        embedder = SemanticEmbedder(lambda texts: [[1.0, 0.0] for _ in texts])
        first = index_parity_work_dir(ParityCaseIndexConfig(work_dir=work_dir), embedder=embedder)

        calls: list[int] = []

        def counting(texts: list[str]) -> list[list[float]]:
            calls.append(len(texts))
            return [[0.0, 1.0] for _ in texts]

        second = index_parity_work_dir(
            ParityCaseIndexConfig(work_dir=work_dir),
            existing_dump=first.dump,
            existing_content_hashes=first.content_hashes,
            embedder=SemanticEmbedder(counting),
        )
        assert second.stats.unchanged_count == 1
        assert calls == []
        assert second.dump.vectors[0].embedding == [1.0, 0.0]


class TestErrors:
    def test_missing_cases_directory_is_a_clear_error(self, tmp_path: Path):
        with pytest.raises(ValueError, match="No source-synthesis/cases directory"):
            index_parity_work_dir(ParityCaseIndexConfig(work_dir=tmp_path))
