"""Tests for the typed program façade (U6).

The load-bearing assertions here are counts against the curated Odyssey
database. A join bug in this layer does not raise -- it produces a plausible map
with the wrong names at the wrong addresses -- so the only proof that works is
"the numbers still match the database we measured".

Measured on `/home/brunner56/Odyssey.rep` (swkotor2.exe, image base 0x400000):

    27,318  Function Data rows == function symbols
    26,975  function symbols that decode to real memory
       343  externals, excluded from every VA-keyed result
    25,586  of the 26,975 that carry a curated (non-empty) name
     5,151  comment rows, all with at least one non-empty comment
       273  composite data types
     2,236  named parameter/local symbols across 1,032 functions

A second, independently-produced database -- `k1_win_gog_swkotor.exe.gzf`, the
original (2003) KOTOR rather than TSL -- is exercised too, packed rather than
loose, to pin the reader against a `.gzf` it wasn't written against. It is a
genuinely distinct program, not a copy of the Odyssey fixture: different
program name (`swkotor.exe` vs `swkotor2.exe`) and different counts throughout.

Measured on `/home/brunner56/Desktop/k1_win_gog_swkotor.exe.gzf` (swkotor.exe,
image base 0x400000):

    24,591  Function Data rows == function symbols
    24,242  function symbols that decode to real memory
       349  externals, excluded from every VA-keyed result
    24,060  of the 24,242 that carry a curated (non-empty) name
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

import pytest

from agentdecompile_recovery.ghidra_db.address_map import TYPE_EXTERNAL, TYPE_RELOCATABLE
from agentdecompile_recovery.ghidra_db.buffer_file import BufferFileError
from agentdecompile_recovery.ghidra_db.packed import open_packed_database
from agentdecompile_recovery.ghidra_db.program import (
    COMMENT_KINDS,
    CommentSet,
    Function,
    GhidraProgram,
    GhidraProgramError,
    LocalVariable,
    MemoryBlock,
    Symbol,
    SymbolType,
    comment_texts,
    open_program,
    symbol_type_name,
)

pytestmark = pytest.mark.unit

ODYSSEY_GBF = Path("/home/brunner56/Odyssey.rep/idata/00/~00000000.db/db.1.gbf")
GHIDRA_GBF = Path(
    "/home/brunner56/Downloads/biodecompwarehouse/projects/agentdecompile.rep"
    "/versioned/00/~00000000.db/db.1.gbf"
)
K1_GZF = Path("/home/brunner56/Desktop/k1_win_gog_swkotor.exe.gzf")

_needs_odyssey = pytest.mark.skipif(not ODYSSEY_GBF.is_file(), reason="Odyssey project fixture unavailable")
_needs_ghidra_fixture = pytest.mark.skipif(not GHIDRA_GBF.is_file(), reason="Ghidra program fixture unavailable")
_needs_k1_gzf = pytest.mark.skipif(not K1_GZF.is_file(), reason="k1 packed .gzf fixture unavailable")

ODYSSEY_IMAGE_BASE = 0x400000
ODYSSEY_FUNCTION_DATA_ROWS = 27318
ODYSSEY_MEMORY_FUNCTIONS = 26975
ODYSSEY_EXTERNAL_FUNCTIONS = 343
ODYSSEY_CURATED_NAMES = 25586
ODYSSEY_COMMENT_ROWS = 5151
ODYSSEY_COMPOSITES = 273

K1_IMAGE_BASE = 0x400000
K1_PROGRAM_NAME = "swkotor.exe"
K1_FUNCTION_DATA_ROWS = 24591
K1_MEMORY_FUNCTIONS = 24242
K1_EXTERNAL_FUNCTIONS = 349
K1_CURATED_NAMES = 24060


@pytest.fixture(scope="module")
def odyssey() -> Iterator[GhidraProgram]:
    if not ODYSSEY_GBF.is_file():
        pytest.skip("Odyssey project fixture unavailable")
    with open_program(ODYSSEY_GBF) as program:
        yield program


@pytest.fixture(scope="module")
def k1(tmp_path_factory: pytest.TempPathFactory) -> Iterator[GhidraProgram]:
    if not K1_GZF.is_file():
        pytest.skip("k1 packed .gzf fixture unavailable")
    workdir = tmp_path_factory.mktemp("k1-gzf")
    with open_packed_database(K1_GZF, workdir=workdir):
        pass
    extracted = workdir / f"{K1_GZF.stem}.gbf"
    with open_program(extracted) as program:
        yield program


def _encode(address_type: int, offset: int, base_index: int = 0) -> int:
    return (address_type << 60) | (base_index << 32) | offset


# -- pure helpers -----------------------------------------------------------


def test_symbol_type_ids_match_ghidras_enum() -> None:
    """Transcribed from ghidra.program.model.symbol.SymbolType; 2 is unused."""

    assert SymbolType.LABEL == 0
    assert SymbolType.LIBRARY == 1
    assert SymbolType.NAMESPACE == 3
    assert SymbolType.CLASS == 4
    assert SymbolType.FUNCTION == 5
    assert SymbolType.PARAMETER == 6
    assert SymbolType.LOCAL_VAR == 7
    assert 2 not in {member.value for member in SymbolType}


def test_symbol_type_name_is_readable() -> None:
    assert symbol_type_name(5) == "function"
    assert symbol_type_name(6) == "parameter"
    assert symbol_type_name(7) == "local_var"


def test_unknown_symbol_type_is_reported_not_hidden() -> None:
    """An id we have not seen must be visible, not silently coerced to a label."""

    assert symbol_type_name(99) == "unknown(99)"
    assert symbol_type_name(None) == "none"


def test_comment_texts_drops_empty_and_missing_kinds() -> None:
    row = {"EOL": "real comment", "Pre": None, "Post": "", "Plate": None, "Repeatable": None}

    assert comment_texts(row) == {"EOL": "real comment"}


def test_comment_texts_of_an_all_empty_row_is_empty() -> None:
    """Deleting a comment leaves the row behind; it must not become a blank comment."""

    row = dict.fromkeys(COMMENT_KINDS)

    assert comment_texts(row) == {}


def test_symbol_with_external_address_is_not_curated_location() -> None:
    from agentdecompile_recovery.ghidra_db.address_map import decode_address

    symbol = Symbol(
        symbol_id=1,
        name="glDepthMask",
        symbol_type=SymbolType.FUNCTION,
        namespace_id=0,
        flags=3,
        address=decode_address(_encode(TYPE_EXTERNAL, 0x2)),
        entry=None,
        datatype_id=None,
        variable_offset=None,
    )

    assert symbol.is_external
    assert symbol.has_curated_name


def test_symbol_with_empty_name_is_not_curated() -> None:
    """Ghidra synthesises `FUN_00401000` at display time; that is not knowledge."""

    from agentdecompile_recovery.ghidra_db.address_map import decode_address

    symbol = Symbol(
        symbol_id=2,
        name="",
        symbol_type=SymbolType.FUNCTION,
        namespace_id=0,
        flags=2,
        address=decode_address(_encode(TYPE_RELOCATABLE, 0x1000)),
        entry=0x401000,
        datatype_id=None,
        variable_offset=None,
    )

    assert not symbol.has_curated_name
    assert not symbol.is_external


def test_function_without_entry_is_external() -> None:
    function = Function(
        symbol_id=3,
        name="wglSwapBuffers",
        entry=None,
        namespace_id=0,
        return_datatype_id=None,
        stack_purge=None,
        stack_return_offset=None,
        stack_local_size=None,
        flags=None,
        calling_convention_id=None,
        address=None,
    )

    assert function.is_external
    assert function.to_json()["entry"] is None


def test_memory_block_range_is_half_open() -> None:
    block = MemoryBlock(name=".text", start=0x401000, length=0x10, permissions=5, comment=None)

    assert block.contains(0x401000)
    assert block.contains(0x40100F)
    assert not block.contains(0x401010)
    assert block.end == 0x401010


def test_local_variable_knows_parameters_from_locals() -> None:
    parameter = LocalVariable(1, "lpFileName", 100, SymbolType.PARAMETER, 0, None)
    local = LocalVariable(2, "retryCount", 100, SymbolType.LOCAL_VAR, None, None)

    assert parameter.is_parameter
    assert not local.is_parameter
    assert local.type_name == "local_var"


def test_comment_set_lookup() -> None:
    comments = CommentSet(entry=0x401000, comments={"Plate": "entry point"})

    assert comments.get("Plate") == "entry point"
    assert comments.get("EOL") is None


# -- error paths ------------------------------------------------------------


def test_opening_a_non_database_raises(tmp_path: Path) -> None:
    junk = tmp_path / "not-a-database.gbf"
    junk.write_bytes(b"\x00" * 64)

    with pytest.raises(BufferFileError):
        GhidraProgram(junk)


def test_opening_a_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(OSError):
        GhidraProgram(tmp_path / "absent.gbf")


@_needs_odyssey
def test_missing_table_is_named_in_the_error(odyssey: GhidraProgram) -> None:
    with pytest.raises(GhidraProgramError, match="No Such Table"):
        odyssey.require_table("No Such Table")


@_needs_odyssey
def test_absent_table_lookup_returns_none(odyssey: GhidraProgram) -> None:
    assert odyssey.table("No Such Table") is None


# -- metadata ---------------------------------------------------------------


@_needs_odyssey
def test_odyssey_metadata_matches_the_curated_project(odyssey: GhidraProgram) -> None:
    assert odyssey.image_base == ODYSSEY_IMAGE_BASE
    assert odyssey.program_name == "swkotor2.exe"
    assert odyssey.language_id == "x86:LE:32:default"
    assert odyssey.metadata.db_version == "32"
    assert odyssey.metadata.compiler_spec_id == "windows"


@_needs_odyssey
def test_image_offset_is_parsed_as_hex(odyssey: GhidraProgram) -> None:
    """`Image Offset` is stored as hex text with no 0x prefix; decimal would be 400000."""

    assert odyssey.metadata.raw["Image Offset"] == "400000"
    assert odyssey.image_base == 0x400000


@_needs_ghidra_fixture
def test_second_real_database_also_parses() -> None:
    """Ghidra's own `decompile` binary: a different language and image base."""

    with open_program(GHIDRA_GBF) as program:
        assert program.program_name == "decompile"
        assert program.language_id is not None
        assert program.image_base >= 0
        assert program.memory_blocks()


# -- address resolution -----------------------------------------------------


@_needs_odyssey
def test_relocatable_addresses_gain_the_image_base(odyssey: GhidraProgram) -> None:
    assert odyssey.virtual_address(_encode(TYPE_RELOCATABLE, 0x1000)) == 0x401000


@_needs_odyssey
def test_external_addresses_never_resolve_to_a_va(odyssey: GhidraProgram) -> None:
    """0x4 as RAM would be 0x400004 -- a real address inside the Headers block."""

    assert odyssey.virtual_address(_encode(TYPE_EXTERNAL, 0x4)) is None
    assert odyssey.decode_address(_encode(TYPE_EXTERNAL, 0x4)).type_name == "external"


# -- functions --------------------------------------------------------------


@_needs_odyssey
def test_function_count_excludes_externals_by_default(odyssey: GhidraProgram) -> None:
    functions = list(odyssey.functions())

    assert len(functions) == ODYSSEY_MEMORY_FUNCTIONS
    assert all(function.entry is not None for function in functions)


@_needs_odyssey
def test_externals_are_available_but_carry_no_address(odyssey: GhidraProgram) -> None:
    functions = list(odyssey.functions(include_external=True))
    externals = [function for function in functions if function.is_external]

    assert len(functions) == ODYSSEY_FUNCTION_DATA_ROWS
    assert len(externals) == ODYSSEY_EXTERNAL_FUNCTIONS
    assert all(function.entry is None for function in externals)
    # These are the OpenGL imports whose ordinals would masquerade as addresses.
    assert any(function.name.startswith("gl") for function in externals)


@_needs_odyssey
def test_curated_function_names_join_to_known_addresses(odyssey: GhidraProgram) -> None:
    names = odyssey.names_by_entry()

    assert len(names) == ODYSSEY_CURATED_NAMES
    assert names[0x401000] == "HasNormalMap"
    assert names[0x4016F0] == "CAppManager"
    assert names[0x401B80] == "CreateServer"


@_needs_odyssey
def test_unnamed_functions_are_kept_out_of_the_name_map(odyssey: GhidraProgram) -> None:
    """26,975 resolve to memory but only 25,586 store a name of their own."""

    functions = list(odyssey.functions())
    curated = [function for function in functions if function.has_curated_name]

    assert len(curated) == ODYSSEY_CURATED_NAMES
    assert len(functions) - len(curated) == ODYSSEY_MEMORY_FUNCTIONS - ODYSSEY_CURATED_NAMES
    assert len(odyssey.names_by_entry(curated_only=False)) == ODYSSEY_MEMORY_FUNCTIONS


@_needs_odyssey
def test_function_entries_land_inside_a_memory_block(odyssey: GhidraProgram) -> None:
    """A wrong image base or address type would put entries outside every block."""

    blocks = odyssey.memory_blocks()
    outside = [
        function
        for function in odyssey.functions()
        if not any(block.contains(function.entry) for block in blocks)
    ]

    assert outside == []


@_needs_odyssey
def test_functions_carry_their_signature_row(odyssey: GhidraProgram) -> None:
    by_entry = {function.entry: function for function in odyssey.functions()}
    create_server = by_entry[0x401B80]

    assert create_server.name == "CreateServer"
    assert create_server.return_datatype_id is not None
    assert create_server.stack_purge is not None
    assert create_server.calling_convention_id is not None


@_needs_odyssey
def test_function_without_a_data_row_still_yields_its_name(
    odyssey: GhidraProgram, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Dropping such rows would silently shrink the map on other DB versions."""

    monkeypatch.setattr(GhidraProgram, "_read_function_data", lambda self: {})
    functions = list(odyssey.functions())

    assert len(functions) == ODYSSEY_MEMORY_FUNCTIONS
    assert all(function.return_datatype_id is None for function in functions)
    assert {function.entry for function in functions} >= {0x401000, 0x4016F0, 0x401B80}


# -- symbols ----------------------------------------------------------------


@_needs_odyssey
def test_symbols_can_be_filtered_by_type(odyssey: GhidraProgram) -> None:
    functions = list(odyssey.symbols(types=(SymbolType.FUNCTION,)))

    assert len(functions) == ODYSSEY_FUNCTION_DATA_ROWS
    assert {symbol.type_name for symbol in functions} == {"function"}


@_needs_odyssey
def test_library_symbols_name_the_imported_dlls(odyssey: GhidraProgram) -> None:
    libraries = {symbol.name for symbol in odyssey.symbols(types=(SymbolType.LIBRARY,))}

    assert "KERNEL32.DLL" in libraries
    assert "OPENGL32.DLL" in libraries


# -- comments ---------------------------------------------------------------


@_needs_odyssey
def test_comments_resolve_to_addresses_and_are_never_empty(odyssey: GhidraProgram) -> None:
    comments = list(odyssey.comments())

    assert len(comments) == ODYSSEY_COMMENT_ROWS
    assert all(comment.comments for comment in comments)
    assert all(comment.entry >= ODYSSEY_IMAGE_BASE for comment in comments)
    assert set().union(*(set(comment.comments) for comment in comments)) <= set(COMMENT_KINDS)


# -- locals -----------------------------------------------------------------


@_needs_odyssey
def test_locals_group_under_their_owning_function(odyssey: GhidraProgram) -> None:
    grouped = odyssey.locals_by_function()
    function_ids = {function.symbol_id for function in odyssey.functions(include_external=True)}

    assert grouped
    assert set(grouped) <= function_ids
    assert all(
        variable.function_symbol_id == owner
        for owner, variables in grouped.items()
        for variable in variables
    )


@_needs_odyssey
def test_locals_are_only_the_named_ones(odyssey: GhidraProgram) -> None:
    """Most variable symbols store an empty name and carry no information."""

    grouped = odyssey.locals_by_function()
    named = sum(len(variables) for variables in grouped.values())
    all_variable_symbols = sum(
        1 for _ in odyssey.symbols(types=(SymbolType.PARAMETER, SymbolType.LOCAL_VAR))
    )

    assert all(variable.name for variables in grouped.values() for variable in variables)
    assert 0 < named < all_variable_symbols


@_needs_odyssey
def test_parameters_sort_before_locals_in_ordinal_order(odyssey: GhidraProgram) -> None:
    grouped = odyssey.locals_by_function()
    multi = next(variables for variables in grouped.values() if len(variables) > 1)
    parameters = [variable for variable in multi if variable.is_parameter]

    assert [variable.is_parameter for variable in multi] == sorted(
        (variable.is_parameter for variable in multi), reverse=True
    )
    assert [variable.ordinal for variable in parameters] == sorted(
        variable.ordinal for variable in parameters
    )


# -- memory and data types --------------------------------------------------


@_needs_odyssey
def test_memory_blocks_carry_pe_section_layout(odyssey: GhidraProgram) -> None:
    blocks = {block.name: block for block in odyssey.memory_blocks()}

    assert blocks["Headers"].start == 0x400000
    assert blocks[".text"].start == 0x401000
    assert blocks[".text"].length == 5782528
    assert [block.start for block in odyssey.memory_blocks()] == sorted(
        block.start for block in odyssey.memory_blocks()
    )


@_needs_odyssey
def test_composite_data_types_are_readable(odyssey: GhidraProgram) -> None:
    composites = list(odyssey.composite_data_types())

    assert len(composites) == ODYSSEY_COMPOSITES
    assert all(composite.name for composite in composites)


@_needs_odyssey
def test_to_json_summarises_without_scanning_symbols(odyssey: GhidraProgram) -> None:
    summary = odyssey.to_json()

    assert summary["metadata"]["imageBase"] == "0x400000"
    assert summary["metadata"]["programName"] == "swkotor2.exe"
    assert len(summary["memoryBlocks"]) == 7


# -- second real fixture: k1, unpacked from a .gzf --------------------------
#
# Regression pin for a second, independently-produced Odyssey-engine database,
# reached through `open_packed_database` rather than a loose `.gbf`, so the
# `.gzf` extraction path and the program facade are proven together.


@_needs_k1_gzf
def test_k1_metadata_matches_the_packed_database(k1: GhidraProgram) -> None:
    assert k1.image_base == K1_IMAGE_BASE
    assert k1.program_name == K1_PROGRAM_NAME
    assert k1.language_id == "x86:LE:32:default"


@_needs_k1_gzf
def test_k1_function_count_excludes_externals_by_default(k1: GhidraProgram) -> None:
    functions = list(k1.functions())

    assert len(functions) == K1_MEMORY_FUNCTIONS


@_needs_k1_gzf
def test_k1_externals_are_available_but_carry_no_address(k1: GhidraProgram) -> None:
    functions = list(k1.functions(include_external=True))
    externals = [function for function in functions if function.entry is None]

    assert len(functions) == K1_FUNCTION_DATA_ROWS
    assert len(externals) == K1_EXTERNAL_FUNCTIONS


@_needs_k1_gzf
def test_k1_curated_function_names_join_to_known_addresses(k1: GhidraProgram) -> None:
    names = k1.names_by_entry()

    assert len(names) == K1_CURATED_NAMES
    assert all(entry >= K1_IMAGE_BASE for entry in names)


@_needs_k1_gzf
def test_k1_is_a_distinct_program_from_odyssey_tsl(k1: GhidraProgram) -> None:
    """A second fixture only proves the reader generalizes if it is a different game."""

    assert k1.program_name != "swkotor2.exe"
    assert (K1_FUNCTION_DATA_ROWS, K1_MEMORY_FUNCTIONS, K1_CURATED_NAMES) != (
        ODYSSEY_FUNCTION_DATA_ROWS,
        ODYSSEY_MEMORY_FUNCTIONS,
        ODYSSEY_CURATED_NAMES,
    )
