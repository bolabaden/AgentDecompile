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
    CuratedTypeIndex,
    build_curated_hints,
    build_curated_signatures,
    curated_hints_to_json,
    curated_params_for_function,
    curated_signatures_to_json,
    header_comment_for_function,
    merge_curated_locals_into_fact,
    msvc_thiscall_to_fastcall,
    normalize_entry_key,
    param_slot_name,
    sanitize_header_comment_text,
)
from agentdecompile_recovery.ghidra_db.program import (
    CommentSet,
    Function,
    LocalVariable,
    Symbol,
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


# -- curated prototypes: type resolution --------------------------------------


class FakeSignatureProgram:
    """Duck-typed `GhidraProgram` for the prototype join.

    Carries the four surfaces `build_curated_signatures` reads: the data-type
    tables (via `table`/`rows`), namespace and parameter symbols (via
    `symbols`), and the function rows themselves.
    """

    def __init__(
        self,
        *,
        tables: dict[str, list[dict[str, object]]],
        symbols: list[Symbol],
        functions: list[Function],
    ) -> None:
        self._tables = tables
        self._symbols = symbols
        self._functions = functions

    def table(self, name: str) -> object | None:
        return object() if name in self._tables else None

    def rows(self, name: str) -> Iterator[dict[str, object]]:
        return iter(self._tables.get(name, []))

    def symbols(self, types=None, *, named_only: bool = False) -> Iterator[Symbol]:
        wanted = None if types is None else {int(value) for value in types}
        for symbol in self._symbols:
            if wanted is not None and symbol.symbol_type not in wanted:
                continue
            if named_only and not symbol.name:
                continue
            yield symbol

    def functions(self, *, include_external: bool = False) -> Iterator[Function]:
        return iter(self._functions)


def _symbol(
    *,
    symbol_id: int,
    name: str,
    symbol_type: int,
    namespace_id: int = 0,
    ordinal: int | None = None,
    datatype_id: int | None = None,
) -> Symbol:
    return Symbol(
        symbol_id=symbol_id,
        name=name,
        symbol_type=symbol_type,
        namespace_id=namespace_id,
        flags=0,
        address=None,
        entry=None,
        datatype_id=datatype_id,
        variable_offset=ordinal,
    )


def _typed_function(
    *,
    symbol_id: int,
    entry: int,
    name: str,
    namespace_id: int = 0,
    return_datatype_id: int | None = None,
    stack_purge: int | None = None,
    calling_convention_id: int | None = None,
) -> Function:
    return Function(
        symbol_id=symbol_id,
        name=name,
        entry=entry,
        namespace_id=namespace_id,
        return_datatype_id=return_datatype_id,
        stack_purge=stack_purge,
        stack_return_offset=None,
        stack_local_size=None,
        flags=None,
        calling_convention_id=calling_convention_id,
        address=None,
    )


_INT_ID = 112
_UNDEFINED4_ID = 114
_COMPOSITE_ID = (1 << 56) | 7
_POINTER_TO_COMPOSITE_ID = (4 << 56) | 9
_TYPEDEF_ID = (5 << 56) | 3
_ARRAY_ID = (3 << 56) | 4
_ENUM_ID = (8 << 56) | 2

_TYPE_TABLES: dict[str, list[dict[str, object]]] = {
    "Built-in datatypes": [
        {"Data Type ID": _INT_ID, "Name": "int"},
        {"Data Type ID": _UNDEFINED4_ID, "Name": "undefined4"},
    ],
    "Composite Data Types": [{"Data Type ID": _COMPOSITE_ID, "Name": "CExoString"}],
    "Pointers": [{"Pointer ID": _POINTER_TO_COMPOSITE_ID, "Data Type ID": _COMPOSITE_ID}],
    "Typedefs": [{"Typedef ID": _TYPEDEF_ID, "Data Type ID": _INT_ID, "Name": "BOOL"}],
    "Arrays": [{"Array ID": _ARRAY_ID, "Data Type ID": _INT_ID, "Dimension": 4}],
    "Enumeration Data Types": [{"Enum ID": _ENUM_ID, "Name": "GFFFieldTypes"}],
    "Function Definitions": [],
    "Calling Conventions": [
        {"ID": 2, "Name": "__stdcall"},
        {"ID": 3, "Name": "__cdecl"},
        {"ID": 4, "Name": "__thiscall"},
    ],
}


def _type_index() -> CuratedTypeIndex:
    return CuratedTypeIndex.from_program(
        FakeSignatureProgram(tables=_TYPE_TABLES, symbols=[], functions=[])
    )


def test_type_index_resolves_each_data_type_table() -> None:
    types = _type_index()

    assert types.type_name(_INT_ID) == "int"
    assert types.type_name(_COMPOSITE_ID) == "CExoString"
    assert types.type_name(_POINTER_TO_COMPOSITE_ID) == "CExoString *"
    assert types.type_name(_TYPEDEF_ID) == "BOOL"
    assert types.type_name(_ARRAY_ID) == "int[4]"
    assert types.type_name(_ENUM_ID) == "GFFFieldTypes"


def test_type_index_reports_ghidra_placeholder_and_unknown_distinctly() -> None:
    types = _type_index()

    # Ghidra's DEFAULT_DATATYPE_ID is a placeholder the curator never chose.
    assert types.type_name(0) == "undefined"
    # NULL_DATATYPE_ID and an id this database does not contain are both unknown.
    assert types.type_name(-1) is None
    assert types.type_name((1 << 56) | 999) is None


def test_type_index_resolves_calling_conventions_and_refuses_unknown_ids() -> None:
    types = _type_index()

    assert types.calling_convention(4) == "__thiscall"
    # Ghidra reserves the low ids for unknown/default and does not store them;
    # inventing one would change the ABI of every generated candidate.
    assert types.calling_convention(0) is None
    assert types.calling_convention(None) is None


# -- curated prototypes: the arity gate ---------------------------------------


def _signature_program(
    *,
    functions: list[Function],
    symbols: list[Symbol],
) -> FakeSignatureProgram:
    return FakeSignatureProgram(tables=_TYPE_TABLES, symbols=symbols, functions=functions)


def test_thiscall_prototype_survives_when_ret_n_agrees() -> None:
    program = _signature_program(
        functions=[
            _typed_function(
                symbol_id=10,
                entry=0x401060,
                name="GetObjectTableManager",
                namespace_id=99,
                return_datatype_id=_UNDEFINED4_ID,
                stack_purge=4,
                calling_convention_id=4,
            )
        ],
        symbols=[
            _symbol(symbol_id=99, name="CAppManager", symbol_type=SymbolType.CLASS),
            _symbol(
                symbol_id=11,
                name="",
                symbol_type=SymbolType.PARAMETER,
                namespace_id=10,
                ordinal=0,
                datatype_id=_INT_ID,
            ),
        ],
    )

    signatures = build_curated_signatures(program)
    record = signatures[0x401060]

    assert record.arity_check == "match"
    assert record.calling_convention == "__thiscall"
    assert record.qualified_name == "CAppManager::GetObjectTableManager"
    assert record.signature == "undefined4 __thiscall CAppManager::GetObjectTableManager(int)"


def test_prototype_is_dropped_but_name_kept_when_ret_n_contradicts_it() -> None:
    """The safety rule from mission note 14, applied to the curator's own data.

    `ret 4` says this callee cleans one stack argument; the stored parameter
    list says it takes none. A prototype asserting `()` would silently produce
    a candidate with the wrong stack discipline, so it is discarded -- but the
    curated name is still evidence and survives.
    """

    program = _signature_program(
        functions=[
            _typed_function(
                symbol_id=20,
                entry=0x401380,
                name="CreateServer",
                namespace_id=99,
                stack_purge=4,
                calling_convention_id=4,
            )
        ],
        symbols=[_symbol(symbol_id=99, name="CAppManager", symbol_type=SymbolType.CLASS)],
    )

    record = build_curated_signatures(program)[0x401380]

    assert record.arity_check == "contradicted"
    assert record.signature is None
    assert record.name == "CreateServer"
    assert record.qualified_name == "CAppManager::CreateServer"


def test_cdecl_prototype_is_kept_as_undecidable_because_the_caller_cleans_up() -> None:
    program = _signature_program(
        functions=[
            _typed_function(
                symbol_id=30,
                entry=0x401C10,
                name="UpdateScreen",
                stack_purge=0,
                calling_convention_id=3,
            )
        ],
        symbols=[
            _symbol(
                symbol_id=31,
                name="fDelta",
                symbol_type=SymbolType.PARAMETER,
                namespace_id=30,
                ordinal=0,
                datatype_id=_INT_ID,
            )
        ],
    )

    record = build_curated_signatures(program)[0x401C10]

    assert record.arity_check == "undecidable"
    assert record.signature == "__cdecl UpdateScreen(int fDelta)"


def test_unnamed_but_typed_parameters_are_kept() -> None:
    """`locals_by_function` drops unnamed parameters; the prototype must not.

    On the curated KOTOR project only 2,962 of 22,578 parameters carry a name
    while 22,551 carry a type. Dropping the unnamed ones would make a
    `__thiscall` taking one stack argument look like it took none, which the
    arity gate would then read as a contradiction and discard.
    """

    program = _signature_program(
        functions=[
            _typed_function(
                symbol_id=40,
                entry=0x402000,
                name="SetName",
                stack_purge=4,
                calling_convention_id=4,
            )
        ],
        symbols=[
            _symbol(
                symbol_id=41,
                name="",
                symbol_type=SymbolType.PARAMETER,
                namespace_id=40,
                ordinal=0,
                datatype_id=_POINTER_TO_COMPOSITE_ID,
            )
        ],
    )

    record = build_curated_signatures(program)[0x402000]

    assert [item.type_name for item in record.parameters] == ["CExoString *"]
    assert record.arity_check == "match"
    assert record.signature == "__thiscall SetName(CExoString *)"


def test_functions_without_a_curated_name_are_skipped() -> None:
    program = _signature_program(
        functions=[_typed_function(symbol_id=50, entry=0x403000, name="", calling_convention_id=3)],
        symbols=[],
    )

    assert build_curated_signatures(program) == {}


def test_nested_namespaces_join_into_a_qualified_name() -> None:
    program = _signature_program(
        functions=[
            _typed_function(
                symbol_id=60,
                entry=0x404000,
                name="Inner",
                namespace_id=71,
                calling_convention_id=3,
            )
        ],
        symbols=[
            _symbol(symbol_id=70, name="Outer", symbol_type=SymbolType.NAMESPACE),
            _symbol(symbol_id=71, name="Middle", symbol_type=SymbolType.CLASS, namespace_id=70),
        ],
    )

    record = build_curated_signatures(program)[0x404000]

    assert record.qualified_name == "Outer::Middle::Inner"
    assert record.namespace == "Outer::Middle"


def test_curated_signatures_to_json_is_entry_hex_keyed() -> None:
    program = _signature_program(
        functions=[
            _typed_function(symbol_id=80, entry=0x401000, name="Ping", calling_convention_id=3)
        ],
        symbols=[],
    )

    payload = curated_signatures_to_json(build_curated_signatures(program))

    assert list(payload) == ["00401000"]
    assert payload["00401000"]["callingConvention"] == "__cdecl"


# -- integration: real curated KOTOR corpus program ----------------------------


@_needs_odyssey
def test_build_curated_signatures_against_real_odyssey_database() -> None:
    with open_program(ODYSSEY_GBF) as program:
        signatures = build_curated_signatures(program)

    assert signatures, "expected curated prototypes in the curated project"
    # Every emitted signature must have passed the arity gate.
    for record in signatures.values():
        if record.signature is not None:
            assert record.arity_check != "contradicted"


# -- making a curated __thiscall decompile compilable --------------------------


def test_thiscall_signature_becomes_fastcall_with_a_dead_edx_argument() -> None:
    """MSVC rejects `__thiscall` on a free function; `__fastcall` is the same ABI.

    `this` in ECX, the dead argument in EDX, real arguments on the stack,
    callee-cleaned `ret N`.
    """

    text = (
        "\nundefined4 __thiscall GetObjectTableManager(void *this,int param_1)\n"
        "\n{\n  return 0;\n}\n"
    )

    rewritten = msvc_thiscall_to_fastcall(text)

    assert "__thiscall" not in rewritten
    assert (
        "undefined4 __fastcall GetObjectTableManager(void *this, int __edx_unused, int param_1)"
        in rewritten
    )
    # Body is untouched.
    assert rewritten.endswith("\n{\n  return 0;\n}\n")


def test_thiscall_rewrite_handles_a_this_only_signature() -> None:
    text = "\nvoid __thiscall Release(void *this)\n\n{\n  return;\n}\n"

    rewritten = msvc_thiscall_to_fastcall(text)

    assert "void __fastcall Release(void *this, int __edx_unused)" in rewritten


def test_non_thiscall_source_is_returned_unchanged() -> None:
    text = "\nundefined4 FUN_00401060(int param_1)\n\n{\n  return 0;\n}\n"

    assert msvc_thiscall_to_fastcall(text) == text


def test_thiscall_inside_a_body_cast_is_not_rewritten() -> None:
    """Ghidra emits `__thiscall` in function-pointer casts too.

    Rewriting one would change a call site's ABI, so only the signature ahead
    of the body-opening brace is considered.
    """

    text = (
        "\nvoid FUN_00401000(void)\n"
        "\n{\n  (**(code **)(*piVar1 + 4))();\n"
        "  /* __thiscall dispatch */\n}\n"
    )

    assert msvc_thiscall_to_fastcall(text) == text


def test_thiscall_with_no_parameters_is_left_alone() -> None:
    """No `this` to keep in ECX means the rewrite would invent one."""

    text = "\nvoid __thiscall Broken(void)\n\n{\n  return;\n}\n"

    assert msvc_thiscall_to_fastcall(text) == text
