"""Tests for B-tree traversal and the master table catalogue (U3/U4).

The real-fixture tests are the load-bearing ones: a B-tree offset error produces
records that decode without raising and are simply wrong, so synthetic tests
alone cannot prove the reader works. The expected counts below were confirmed
against these exact files.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from agentdecompile_recovery.ghidra_db.btree import (
    FIXEDKEY_FIXED_REC_NODE,
    FIXEDKEY_INTERIOR_NODE,
    FIXEDKEY_NEXT_LEAF_ID_OFFSET,
    FIXEDKEY_NODE_HEADER_SIZE,
    FIXEDKEY_VAR_REC_NODE,
    LONGKEY_VAR_REC_NODE,
    NEXT_LEAF_ID_OFFSET,
    RECORD_LEAF_HEADER_SIZE,
    BTreeError,
    fixed_record_length,
    iter_table_records,
    key_count,
    key_field_size,
    node_type,
)
from agentdecompile_recovery.ghidra_db.buffer_file import BUFFER_PREFIX_SIZE, MAGIC_NUMBER, BufferFile
from agentdecompile_recovery.ghidra_db.fields import (
    BYTE_TYPE,
    INT_TYPE,
    LONG_TYPE,
    SHORT_TYPE,
    STRING_TYPE,
    build_schema,
)
from agentdecompile_recovery.ghidra_db.master_table import (
    MASTER_TABLE_SCHEMA,
    find_table,
    iter_rows,
    master_table_root_id,
    read_db_parms,
    read_table_catalogue,
)

pytestmark = pytest.mark.unit


def _write_buffer_file(tmp_path: Path, buffers: list[bytes], *, block: int = 64) -> Path:
    """Build a minimal synthetic `.gbf` file: a header block plus one block per buffer.

    Each buffer is a live (non-empty) buffer whose id equals its index, matching
    `db.buffers.BufferMgr`'s "use source buffer id as index" convention.
    """

    header = bytearray(block)
    struct.pack_into(">q", header, 0, MAGIC_NUMBER)
    struct.pack_into(">q", header, 8, 1)
    struct.pack_into(">i", header, 16, 1)
    struct.pack_into(">i", header, 20, block)
    struct.pack_into(">i", header, 24, -1)
    struct.pack_into(">i", header, 28, 0)

    out = bytearray(header)
    for index, payload in enumerate(buffers):
        body = bytearray(block)
        struct.pack_into(">i", body, 1, index)
        body[BUFFER_PREFIX_SIZE : BUFFER_PREFIX_SIZE + len(payload)] = payload
        out += body

    path = tmp_path / "db.1.gbf"
    path.write_bytes(bytes(out))
    return path

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
    """A node type outside 0-7 raises rather than being misread.

    Long-key (0-2), var-key (3-4) and fixed-key (5-7) nodes are all supported;
    anything else must fail loudly since a misread node decodes without error.
    """

    node = bytearray(64 - BUFFER_PREFIX_SIZE)
    struct.pack_into(">i", node, 1, 0)
    node[0] = 42  # no such node type
    path = _write_buffer_file(tmp_path, [bytes(node)])

    with BufferFile(path) as bf:
        with pytest.raises(BTreeError, match="unrecognized type"):
            list(iter_table_records(bf, 0, MASTER_TABLE_SCHEMA))


# -- fixed-key node layout (types 5-7) ---------------------------------------


def test_fixedkey_leaf_header_is_thirteen_bytes() -> None:
    """type(1) + keyCount(4) + prevLeaf(4) + nextLeaf(4); confirmed from db.FixedKeyRecordNode.

    Fixed-key nodes carry no key-type byte (unlike var-key nodes), so the
    header offsets are numerically identical to long-key nodes'.
    """

    assert FIXEDKEY_NODE_HEADER_SIZE == 5
    assert FIXEDKEY_NEXT_LEAF_ID_OFFSET == 9
    assert FIXEDKEY_NODE_HEADER_SIZE == RECORD_LEAF_HEADER_SIZE - 8


def test_key_field_size_matches_schema_key_field_width() -> None:
    byte_schema = build_schema(key_type=BYTE_TYPE, encoded_field_types=b"", packed_field_names="Key")
    short_schema = build_schema(key_type=SHORT_TYPE, encoded_field_types=b"", packed_field_names="Key")
    long_schema = build_schema(key_type=LONG_TYPE, encoded_field_types=b"", packed_field_names="Key")

    assert key_field_size(byte_schema) == 1
    assert key_field_size(short_schema) == 2
    assert key_field_size(long_schema) == 8


def test_key_field_size_rejects_variable_length_key() -> None:
    string_key_schema = build_schema(key_type=STRING_TYPE, encoded_field_types=b"", packed_field_names="Key")

    with pytest.raises(BTreeError, match="unsupported fixed key field type"):
        key_field_size(string_key_schema)


def _fixedkey_var_rec_leaf(*, key: int, record: bytes, prev: int, next_leaf: int, block: int = 64) -> bytes:
    """Node payload for one `FixedKeyVarRecNode` leaf holding a single byte-keyed record."""

    node_len = block - BUFFER_PREFIX_SIZE
    node = bytearray(node_len)
    node[0] = FIXEDKEY_VAR_REC_NODE
    struct.pack_into(">i", node, 1, 1)  # keyCount
    struct.pack_into(">i", node, 5, prev)
    struct.pack_into(">i", node, 9, next_leaf)

    rec_offset = node_len - len(record)
    entry = 13
    node[entry] = key & 0xFF
    struct.pack_into(">i", node, entry + 1, rec_offset)
    node[entry + 5] = 0  # not indirect
    node[rec_offset : rec_offset + len(record)] = record
    return bytes(node)


def test_fixedkey_var_rec_leaves_chain_across_buffers(tmp_path: Path) -> None:
    """Two `FixedKeyVarRecNode` leaves, joined by `nextLeafId`, scan as one table."""

    leaf_a = _fixedkey_var_rec_leaf(key=1, record=b"AAAA", prev=-1, next_leaf=2)
    leaf_b = _fixedkey_var_rec_leaf(key=2, record=b"BBBB", prev=1, next_leaf=-1)
    path = _write_buffer_file(tmp_path, [b"", leaf_a, leaf_b])

    schema = build_schema(key_type=BYTE_TYPE, encoded_field_types=b"", packed_field_names="Key")

    with BufferFile(path) as bf:
        rows = list(iter_table_records(bf, 1, schema))

    assert rows == [(1, b"AAAA"), (2, b"BBBB")]


def test_fixedkey_interior_node_descends_to_leftmost_leaf(tmp_path: Path) -> None:
    """`FixedKeyInteriorNode`: `[key(keySize) childId(4)]`, child right after key0."""

    leaf = _fixedkey_var_rec_leaf(key=9, record=b"ZZ", prev=-1, next_leaf=-1)

    interior = bytearray(64 - BUFFER_PREFIX_SIZE)
    interior[0] = FIXEDKEY_INTERIOR_NODE
    struct.pack_into(">i", interior, 1, 1)  # keyCount
    entry = FIXEDKEY_NODE_HEADER_SIZE
    interior[entry] = 0xFF  # separator key, irrelevant to a leftmost descend
    struct.pack_into(">i", interior, entry + 1, 2)  # child buffer index

    path = _write_buffer_file(tmp_path, [b"", bytes(interior), leaf])
    schema = build_schema(key_type=BYTE_TYPE, encoded_field_types=b"", packed_field_names="Key")

    with BufferFile(path) as bf:
        rows = list(iter_table_records(bf, 1, schema))

    assert rows == [(9, b"ZZ")]


def test_fixedkey_fixed_rec_leaf_packs_entries_forward(tmp_path: Path) -> None:
    """`FixedKeyFixedRecNode`: `[key(keySize) rec(L)]` packed forward/contiguously."""

    schema = build_schema(key_type=BYTE_TYPE, encoded_field_types=bytes([INT_TYPE]), packed_field_names="Key;Value")

    node = bytearray(64 - BUFFER_PREFIX_SIZE)
    node[0] = FIXEDKEY_FIXED_REC_NODE
    struct.pack_into(">i", node, 1, 2)  # keyCount
    struct.pack_into(">i", node, 5, -1)  # prev
    struct.pack_into(">i", node, 9, -1)  # next

    entry0 = 13
    node[entry0] = 7
    struct.pack_into(">i", node, entry0 + 1, 42)
    entry1 = entry0 + 5
    node[entry1] = 8
    struct.pack_into(">i", node, entry1 + 1, 99)

    path = _write_buffer_file(tmp_path, [bytes(node)])

    with BufferFile(path) as bf:
        rows = list(iter_table_records(bf, 0, schema))

    assert rows == [(7, struct.pack(">i", 42)), (8, struct.pack(">i", 99))]


def test_fixedkey_leaf_chain_cycle_is_refused(tmp_path: Path) -> None:
    """A `nextLeafId` pointing back into the chain must not hang the scan."""

    leaf = _fixedkey_var_rec_leaf(key=1, record=b"A", prev=-1, next_leaf=0)
    path = _write_buffer_file(tmp_path, [leaf])
    schema = build_schema(key_type=BYTE_TYPE, encoded_field_types=b"", packed_field_names="Key")

    with BufferFile(path) as bf:
        with pytest.raises(BTreeError, match="revisits buffer"):
            list(iter_table_records(bf, 0, schema))


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


@_needs_odyssey_fixture
def test_calling_conventions_table_reads_via_fixedkey_var_rec_nodes() -> None:
    """The load-bearing case for F1: a byte-keyed table stored as `FixedKeyVarRecNode` leaves.

    Before fixed-key support, this table's root node (type 6) made
    `iter_table_records` raise; every other table in this project keys on a
    long or a string, so this is the only fixture that exercises types 5-7.
    """

    with BufferFile(ODYSSEY_FIXTURE) as bf:
        table = find_table(bf, "Calling Conventions")
        assert table is not None
        assert table.key_type == BYTE_TYPE
        rows = list(iter_rows(bf, table))

    assert len(rows) == 4
    assert {row["Name"] for row in rows} == {"__stdcall", "__cdecl", "__thiscall", "__fastcall"}
