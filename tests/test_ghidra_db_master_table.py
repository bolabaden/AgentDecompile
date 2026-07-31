"""Tests for B-tree traversal and the master table catalogue (U3/U4).

The real-fixture tests are the load-bearing ones: a B-tree offset error produces
records that decode without raising and are simply wrong, so synthetic tests
alone cannot prove the reader works. The expected counts below were confirmed
against these exact files.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery.ghidra_db.btree import (
    LONGKEY_VAR_REC_NODE,
    NEXT_LEAF_ID_OFFSET,
    RECORD_LEAF_HEADER_SIZE,
    BTreeError,
    fixed_record_length,
    iter_table_records,
    key_count,
    node_type,
)
from agentdecompile_recovery.ghidra_db.buffer_file import BufferFile
from agentdecompile_recovery.ghidra_db.fields import INT_TYPE, LONG_TYPE, STRING_TYPE, build_schema
from agentdecompile_recovery.ghidra_db.master_table import (
    MASTER_TABLE_SCHEMA,
    find_table,
    iter_rows,
    master_table_root_id,
    read_db_parms,
    read_table_catalogue,
)

pytestmark = pytest.mark.unit

GHIDRA_FIXTURE = Path(
    "/home/brunner56/Downloads/biodecompwarehouse/projects/agentdecompile.rep"
    "/versioned/00/~00000000.db/db.1.gbf"
)
ODYSSEY_FIXTURE = Path("/home/brunner56/Odyssey.rep/idata/00/~00000000.db/db.1.gbf")

_needs_ghidra_fixture = pytest.mark.skipif(
    not GHIDRA_FIXTURE.is_file(), reason="Ghidra program fixture unavailable"
)
_needs_odyssey_fixture = pytest.mark.skipif(
    not ODYSSEY_FIXTURE.is_file(), reason="Odyssey project fixture unavailable"
)


# -- layout constants -------------------------------------------------------


def test_long_key_leaf_header_is_thirteen_bytes() -> None:
    """type(1) + keyCount(4) + prevLeaf(4) + nextLeaf(4); confirmed from db.LongKeyRecordNode."""

    assert RECORD_LEAF_HEADER_SIZE == 13
    assert NEXT_LEAF_ID_OFFSET == 9


def test_node_type_and_key_count_readers() -> None:
    node = bytes([LONGKEY_VAR_REC_NODE]) + (7).to_bytes(4, "big") + bytes(20)

    assert node_type(node) == LONGKEY_VAR_REC_NODE
    assert key_count(node) == 7


def test_fixed_record_length_sums_column_widths() -> None:
    schema = build_schema(
        key_type=LONG_TYPE,
        encoded_field_types=bytes([LONG_TYPE, INT_TYPE]),
        packed_field_names="Key;A;B",
    )

    assert fixed_record_length(schema) == 12


def test_fixed_record_length_rejects_variable_schema() -> None:
    schema = build_schema(
        key_type=LONG_TYPE,
        encoded_field_types=bytes([STRING_TYPE]),
        packed_field_names="Key;Name",
    )

    with pytest.raises(BTreeError, match="variable-length"):
        fixed_record_length(schema)


def test_empty_table_yields_nothing() -> None:
    """root_buffer_id of -1 marks an empty table; it must not be read as buffer -1."""

    assert list(iter_table_records(None, -1, MASTER_TABLE_SCHEMA)) == []  # type: ignore[arg-type]


def test_unsupported_node_type_is_refused(tmp_path: Path) -> None:
    """Fixed-key nodes raise rather than being misread as long-key.

    Long-key (0-2) and var-key (3-4) nodes are supported; fixed-key (5-7) are
    not, and must fail loudly since a misread node decodes without error.
    """

    import struct

    from agentdecompile_recovery.ghidra_db.buffer_file import BUFFER_PREFIX_SIZE, MAGIC_NUMBER

    block = 64
    header = bytearray(block)
    struct.pack_into(">q", header, 0, MAGIC_NUMBER)
    struct.pack_into(">q", header, 8, 1)
    struct.pack_into(">i", header, 16, 1)
    struct.pack_into(">i", header, 20, block)
    struct.pack_into(">i", header, 24, -1)
    struct.pack_into(">i", header, 28, 0)
    body = bytearray(block)
    struct.pack_into(">i", body, 1, 0)
    body[BUFFER_PREFIX_SIZE] = 6  # FIXEDKEY_VAR_REC_NODE
    path = tmp_path / "db.1.gbf"
    path.write_bytes(bytes(header) + bytes(body))

    with BufferFile(path) as bf:
        with pytest.raises(BTreeError, match="fixed-key nodes"):
            list(iter_table_records(bf, 0, MASTER_TABLE_SCHEMA))


# -- real Ghidra program database -------------------------------------------


@_needs_ghidra_fixture
def test_reads_db_parms_and_master_root() -> None:
    with BufferFile(GHIDRA_FIXTURE) as bf:
        parms = read_db_parms(bf)

        assert len(parms) >= 3
        assert master_table_root_id(bf) == parms[0] >= 0


@_needs_ghidra_fixture
def test_table_catalogue_contains_expected_program_tables() -> None:
    with BufferFile(GHIDRA_FIXTURE) as bf:
        names = {table.name for table in read_table_catalogue(bf)}

    assert {"Symbols", "Comments", "Function Data", "ADDRESS MAP", "Memory Blocks"} <= names


@_needs_ghidra_fixture
def test_known_table_schema_versions_and_counts() -> None:
    """Pinned to this fixture: catches silent regressions in record decoding."""

    with BufferFile(GHIDRA_FIXTURE) as bf:
        tables = {table.name: table for table in read_table_catalogue(bf)}

    assert tables["Symbols"].schema_version == 4
    assert tables["Symbols"].record_count == 11777
    assert tables["Comments"].schema_version == 1
    assert tables["Comments"].record_count == 12217
    assert tables["Function Data"].schema_version == 3


@_needs_ghidra_fixture
def test_index_tables_are_excluded_by_default() -> None:
    with BufferFile(GHIDRA_FIXTURE) as bf:
        primary = read_table_catalogue(bf)
        everything = read_table_catalogue(bf, include_index_tables=True)

    assert len(everything) > len(primary)
    assert all(not table.is_index_table for table in primary)


@_needs_ghidra_fixture
def test_symbol_rows_decode_to_real_names() -> None:
    """End-to-end: buffer file -> b-tree -> sparse record -> a usable name."""

    with BufferFile(GHIDRA_FIXTURE) as bf:
        table = find_table(bf, "Symbols")
        assert table is not None
        names = [row.get("Name") for _, row in zip(range(400), iter_rows(bf, table))]

    assert any(name and name.startswith("__DT_") for name in names)


@_needs_ghidra_fixture
def test_comment_rows_decode_to_text() -> None:
    with BufferFile(GHIDRA_FIXTURE) as bf:
        table = find_table(bf, "Comments")
        assert table is not None
        rows = [row for _, row in zip(range(200), iter_rows(bf, table))]

    assert any(row.get("EOL") for row in rows)
    assert set(rows[0]) >= {"EOL", "Pre", "Post", "Plate", "Repeatable"}


@_needs_ghidra_fixture
def test_missing_table_returns_none() -> None:
    with BufferFile(GHIDRA_FIXTURE) as bf:
        assert find_table(bf, "NoSuchTable") is None


# -- real curated Odyssey project -------------------------------------------


@_needs_odyssey_fixture
def test_odyssey_project_exposes_curated_scale() -> None:
    """The curated project this work exists to read.

    Counts pinned from the live file; they are the reason the ingestion is worth
    doing at all -- ~95% of its functions already carry real names.
    """

    with BufferFile(ODYSSEY_FIXTURE) as bf:
        tables = {table.name: table for table in read_table_catalogue(bf)}

    assert tables["Symbols"].record_count == 213734
    assert tables["Function Data"].record_count == 27318
    assert tables["Comments"].record_count == 5151
    assert tables["Composite Data Types"].record_count == 273


@_needs_odyssey_fixture
def test_odyssey_function_symbols_are_mostly_named() -> None:
    import re

    default = re.compile(r"^(FUN_|DAT_|LAB_|SUB_|UNK_|switchD|caseD|PTR_|s_|u_|Rsrc_)")
    function_symbol_type = 5

    with BufferFile(ODYSSEY_FIXTURE) as bf:
        table = find_table(ODYSSEY_FIXTURE and bf, "Symbols")
        assert table is not None
        total = named = 0
        for row in iter_rows(bf, table):
            if row.get("Symbol Type") != function_symbol_type:
                continue
            total += 1
            name = row.get("Name") or ""
            if name and not default.match(name):
                named += 1

    assert total > 25000
    assert named / total > 0.9
