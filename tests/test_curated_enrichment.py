"""Tests for U9 (re-scoped): curated parameter names and comments (curated_enrichment).

Unit tests exercise the pure joins/substitution against synthetic
`GhidraProgram`-shaped data (no real database needed). The integration test
at the bottom runs `build_curated_hints` against the real curated Odyssey
fixture and is skipped when that fixture is unavailable.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

import pytest

from agentdecompile_recovery.curated_enrichment import (
    CuratedFunctionHints,
    build_curated_hints,
    curated_hints_to_json,
    curated_params_for_function,
    header_comment_for_function,
    merge_curated_locals_into_fact,
    normalize_entry_key,
    param_slot_name,
    sanitize_header_comment_text,
)
from agentdecompile_recovery.ghidra_db.program import (
    CommentSet,
    Function,
    LocalVariable,
    SymbolType,
    open_program,
)
from agentdecompile_recovery.source_cleanup import clean_source_text
from agentdecompile_recovery.source_dump import dump_source_tree

pytestmark = pytest.mark.unit

ODYSSEY_GBF = Path("/home/brunner56/Odyssey.rep/idata/00/~00000000.db/db.1.gbf")
_needs_odyssey = pytest.mark.skipif(not ODYSSEY_GBF.is_file(), reason="Odyssey project fixture unavailable")


# -- fixtures / builders ------------------------------------------------------


def _local(
    *,
    symbol_id: int,
    name: str,
    function_symbol_id: int,
    symbol_type: int = SymbolType.PARAMETER,
    ordinal: int | None = 0,
) -> LocalVariable:
    return LocalVariable(
        symbol_id=symbol_id,
        name=name,
        function_symbol_id=function_symbol_id,
        symbol_type=symbol_type,
        ordinal=ordinal,
        datatype_id=None,
    )


def _function(*, symbol_id: int, entry: int, name: str = "") -> Function:
    return Function(
        symbol_id=symbol_id,
        name=name,
        entry=entry,
        namespace_id=0,
        return_datatype_id=None,
        stack_purge=None,
        stack_return_offset=None,
        stack_local_size=None,
        flags=None,
        calling_convention_id=None,
        address=None,
    )


class FakeProgram:
    """Duck-typed stand-in for `GhidraProgram`: only the three methods used."""

    def __init__(
        self,
        *,
        functions: list[Function],
        locals_by_symbol: dict[int, list[LocalVariable]],
        comments: list[CommentSet],
    ) -> None:
        self._functions = functions
        self._locals_by_symbol = locals_by_symbol
        self._comments = comments

    def functions(self) -> list[Function]:
        return self._functions

    def locals_by_function(self) -> dict[int, list[LocalVariable]]:
        return self._locals_by_symbol

    def comments(self) -> Iterator[CommentSet]:
        return iter(self._comments)


# -- param_slot_name / curated_params_for_function ---------------------------


def test_param_slot_name_is_1_indexed() -> None:
    assert param_slot_name(0) == "param_1"
    assert param_slot_name(1) == "param_2"
    assert param_slot_name(3) == "param_4"


def test_param_slot_name_none_for_unplaceable_ordinal() -> None:
    assert param_slot_name(None) is None
    assert param_slot_name(-1) is None


def test_curated_params_for_function_keeps_only_named_parameters() -> None:
    variables = [
        _local(symbol_id=1, name="pDst", function_symbol_id=99, symbol_type=SymbolType.PARAMETER, ordinal=0),
        _local(symbol_id=2, name="cbSize", function_symbol_id=99, symbol_type=SymbolType.PARAMETER, ordinal=1),
        # Local variable: excluded even though it is named (re-scoped: params only).
        _local(symbol_id=3, name="tmp", function_symbol_id=99, symbol_type=SymbolType.LOCAL_VAR, ordinal=8),
        # Unnamed parameter: excluded.
        _local(symbol_id=4, name="", function_symbol_id=99, symbol_type=SymbolType.PARAMETER, ordinal=2),
    ]

    pairs = curated_params_for_function(variables)

    assert pairs == [
        {"name": "pDst", "slot": "param_1"},
        {"name": "cbSize", "slot": "param_2"},
    ]


def test_curated_params_for_function_empty_input_is_empty_output() -> None:
    assert curated_params_for_function([]) == []


# -- header_comment_for_function ----------------------------------------------


def test_header_comment_prefers_plate() -> None:
    comment = header_comment_for_function({"Plate": "Decrypts the save header.", "EOL": "short"})
    assert comment == "Decrypts the save header."


def test_header_comment_falls_back_to_short_eol() -> None:
    comment = header_comment_for_function({"EOL": "checks bounds"})
    assert comment == "checks bounds"


def test_header_comment_ignores_long_non_plate_comment() -> None:
    long_text = "x" * 200
    assert header_comment_for_function({"EOL": long_text}) is None


def test_header_comment_none_when_nothing_stored() -> None:
    assert header_comment_for_function({}) is None


def test_sanitize_header_comment_flattens_newlines_and_closes_comment_marker() -> None:
    raw = "line one\nline two */ trailing"
    sanitized = sanitize_header_comment_text(raw)
    assert "\n" not in sanitized
    assert "*/" not in sanitized
    assert "line one line two * / trailing" == sanitized


# -- normalize_entry_key -------------------------------------------------------


def test_normalize_entry_key_accepts_int_and_hex_variants() -> None:
    # Matches source_dump.normalize_entry_hex: int -> zero-padded 8 hex digits,
    # bare/0x-prefixed hex strings pass through as-is (no zero-padding), so
    # keys built either way still collide correctly when both sides use ints.
    assert normalize_entry_key(0x401000) == "00401000"
    assert normalize_entry_key("0x401000") == "401000"
    assert normalize_entry_key("401000") == "401000"
    assert normalize_entry_key(None) is None


# -- build_curated_hints (joins) ----------------------------------------------


def test_build_curated_hints_joins_params_and_comments_by_entry() -> None:
    program = FakeProgram(
        functions=[_function(symbol_id=100, entry=0x401000, name="FUN_00401000")],
        locals_by_symbol={
            100: [_local(symbol_id=1, name="pBuf", function_symbol_id=100, ordinal=0)],
        },
        comments=[CommentSet(entry=0x401000, comments={"Plate": "Copies a buffer."})],
    )

    hints = build_curated_hints(program)

    assert set(hints) == {0x401000}
    hint = hints[0x401000]
    assert hint.header_comment == "Copies a buffer."
    assert hint.params == [{"name": "pBuf", "slot": "param_1"}]


def test_build_curated_hints_omits_functions_with_neither_curated_source() -> None:
    program = FakeProgram(
        functions=[_function(symbol_id=200, entry=0x402000, name="FUN_00402000")],
        locals_by_symbol={},
        comments=[],
    )

    hints = build_curated_hints(program)

    assert hints == {}


def test_build_curated_hints_skips_external_functions() -> None:
    program = FakeProgram(
        functions=[_function(symbol_id=300, entry=None, name="ExternalImport")],
        locals_by_symbol={300: [_local(symbol_id=1, name="p", function_symbol_id=300, ordinal=0)]},
        comments=[],
    )

    assert build_curated_hints(program) == {}


def test_curated_hints_to_json_shape() -> None:
    hints = {
        0x401000: CuratedFunctionHints(
            entry=0x401000,
            header_comment="Copies a buffer.",
            params=[{"name": "pBuf", "slot": "param_1"}],
        )
    }

    as_json = curated_hints_to_json(hints)

    assert as_json == {
        "00401000": {
            "plateComment": "Copies a buffer.",
            "locals": [{"name": "pBuf", "slot": "param_1"}],
        }
    }


# -- merge_curated_locals_into_fact -------------------------------------------


def test_merge_curated_locals_into_fact_adds_when_fact_has_none() -> None:
    fact = {"name": "CopyBuffer"}
    curated = {"locals": [{"name": "pBuf", "slot": "param_1"}]}

    merged = merge_curated_locals_into_fact(fact, curated)

    assert merged["locals"] == [{"name": "pBuf", "slot": "param_1"}]
    assert fact.get("locals") is None  # original untouched


def test_merge_curated_locals_into_fact_existing_slot_wins() -> None:
    fact = {"locals": [{"name": "buffer", "slot": "param_1"}]}
    curated = {"locals": [{"name": "pBuf", "slot": "param_1"}, {"name": "cb", "slot": "param_2"}]}

    merged = merge_curated_locals_into_fact(fact, curated)

    assert merged["locals"] == [
        {"name": "buffer", "slot": "param_1"},
        {"name": "cb", "slot": "param_2"},
    ]


def test_merge_curated_locals_into_fact_no_curated_is_noop() -> None:
    fact = {"name": "CopyBuffer"}
    assert merge_curated_locals_into_fact(fact, None) is fact
    assert merge_curated_locals_into_fact(fact, {}) is fact


# -- end-to-end: clean_source_text actually substitutes curated names --------


def test_clean_source_text_substitutes_curated_parameter_name() -> None:
    source = "void FUN_00401000(int param_1, int param_2)\n{\n  return param_1 + param_2;\n}\n"
    fact = {"locals": [{"name": "pBuf", "slot": "param_1"}]}

    cleaned, replacements = clean_source_text(source, fact)

    assert "pBuf" in cleaned
    assert "param_1" not in cleaned
    assert "param_2" in cleaned  # untouched: no curated name for it
    assert replacements == [{"from": "param_1", "to": "pBuf", "reason": "agentdecompile-local-name"}]


def test_clean_source_text_unaffected_when_fact_has_no_locals() -> None:
    source = "void FUN_00401000(int param_1)\n{\n  return param_1;\n}\n"

    cleaned, replacements = clean_source_text(source, {})

    assert cleaned == source
    assert replacements == []


# -- end-to-end: dump_source_tree emits curated header + substituted body ----


def _ghidra_facts_jsonl(tmp_path: Path, *, entry: str, name: str, decompiled: str, prototype: str) -> Path:
    import json

    facts_path = tmp_path / "ghidra-facts.jsonl"
    facts_path.write_text(
        json.dumps(
            {
                "entry": entry,
                "entryOffset": int(entry, 16),
                "name": name,
                "decompiled": decompiled,
                "decompilationStatus": "complete",
                "prototype": prototype,
                "module": "recovered/unmapped",
                "provenance": "ghidra-symbol",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return facts_path


def test_dump_source_tree_applies_curated_comment_and_param_name(tmp_path: Path) -> None:
    entry = "00401000"
    decompiled = "void FUN_00401000(int param_1)\n\n{\n  return;\n}\n"
    facts = _ghidra_facts_jsonl(
        tmp_path,
        entry=entry,
        name="FUN_00401000",
        decompiled=decompiled,
        prototype="void FUN_00401000(int param_1)",
    )
    curated_hints = {
        entry: {
            "plateComment": "Initializes the subsystem.",
            "locals": [{"name": "flags", "slot": "param_1"}],
        }
    }

    result = dump_source_tree(
        out_dir=tmp_path / "dump",
        summaries=[],
        ghidra_facts=facts,
        target_name="test.exe",
        layers="advisory",
        curated_hints=curated_hints,
    )

    advisory_files = list((tmp_path / "dump" / "advisory" / "ghidra").glob("*.c"))
    assert len(advisory_files) == 1
    text = advisory_files[0].read_text(encoding="utf-8")

    assert "Comment: Initializes the subsystem." in text
    assert "flags" in text
    assert "param_1" not in text
    assert result["schema"]


def test_dump_source_tree_unaffected_when_no_curated_hint_for_entry(tmp_path: Path) -> None:
    entry = "00402000"
    decompiled = "void FUN_00402000(int param_1)\n\n{\n  return;\n}\n"
    facts = _ghidra_facts_jsonl(
        tmp_path,
        entry=entry,
        name="FUN_00402000",
        decompiled=decompiled,
        prototype="void FUN_00402000(int param_1)",
    )

    dump_source_tree(
        out_dir=tmp_path / "dump",
        summaries=[],
        ghidra_facts=facts,
        target_name="test.exe",
        layers="advisory",
        curated_hints={"00401000": {"plateComment": "unrelated", "locals": []}},
    )

    advisory_files = list((tmp_path / "dump" / "advisory" / "ghidra").glob("*.c"))
    assert len(advisory_files) == 1
    text = advisory_files[0].read_text(encoding="utf-8")

    assert "Comment:" not in text
    assert "param_1" in text  # left as Ghidra emitted it: no curated data for this entry


# -- end-to-end: the matched-rows/objdiff loop has its own, separately-coded --
# curated lookup (source_dump.py's `for row in matched:` block) from the
# advisory/ghidra loop tested above -- it must not silently drift out of sync.


def test_dump_source_tree_matched_verified_row_gets_curated_param_name(tmp_path: Path) -> None:
    import json

    entry = "00401000"
    source_path = tmp_path / "fn.c"
    source_path.write_text(
        "void FUN_00401000(int param_1)\n{\n  param_1 = 1;\n}\n", encoding="utf-8"
    )
    summary = tmp_path / "summary.jsonl"
    summary.write_text(
        json.dumps(
            {
                "name": "FUN_00401000",
                "entry": entry,
                "status": "matched",
                "differences": 0,
                "source": str(source_path),
                "sourceQuality": "high-level-c",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    curated_hints = {
        entry: {
            "plateComment": "Sets the flag.",
            "locals": [{"name": "flags", "slot": "param_1"}],
        }
    }

    dump_source_tree(
        out_dir=tmp_path / "dump",
        summaries=[summary],
        reference_root=tmp_path,
        curated_hints=curated_hints,
    )

    verified_files = list((tmp_path / "dump" / "verified").glob("*.c"))
    assert len(verified_files) == 1
    text = verified_files[0].read_text(encoding="utf-8")

    assert "Comment: Sets the flag." in text
    assert "flags" in text
    assert "param_1" not in text


def test_dump_source_tree_matched_verified_row_unaffected_when_no_curated_hint(
    tmp_path: Path,
) -> None:
    import json

    entry = "00402000"
    source_path = tmp_path / "fn.c"
    source_path.write_text(
        "void FUN_00402000(int param_1)\n{\n  param_1 = 1;\n}\n", encoding="utf-8"
    )
    summary = tmp_path / "summary.jsonl"
    summary.write_text(
        json.dumps(
            {
                "name": "FUN_00402000",
                "entry": entry,
                "status": "matched",
                "differences": 0,
                "source": str(source_path),
                "sourceQuality": "high-level-c",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    dump_source_tree(
        out_dir=tmp_path / "dump",
        summaries=[summary],
        reference_root=tmp_path,
        curated_hints={"00401000": {"plateComment": "unrelated", "locals": []}},
    )

    verified_files = list((tmp_path / "dump" / "verified").glob("*.c"))
    assert len(verified_files) == 1
    text = verified_files[0].read_text(encoding="utf-8")

    assert "Comment:" not in text
    assert "param_1" in text  # left as-is: no curated data for this entry


# -- integration: real curated Odyssey database -------------------------------


@_needs_odyssey
def test_build_curated_hints_against_real_odyssey_database() -> None:
    with open_program(ODYSSEY_GBF) as program:
        hints = build_curated_hints(program)

    assert hints, "expected at least one function with curated params or a comment"
    # Re-scoped claim: this is parameter-name coverage, not a general local-var
    # rename -- every emitted local-fact entry must be a param_N slot.
    total_params = 0
    for hint in hints.values():
        for item in hint.params:
            assert item["slot"].startswith("param_")
            total_params += 1
    assert total_params > 0
