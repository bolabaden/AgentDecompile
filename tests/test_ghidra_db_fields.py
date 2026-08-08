"""Unit tests for field/schema/record decoding (U2).

Reference: Ghidra's db.Field, db.Schema, db.DBRecord, db.SparseRecord.
Records carry no header of their own, so a wrong schema silently yields wrong
values rather than an error -- these tests pin the encoding precisely.
"""

from __future__ import annotations

import struct

import pytest

from agentdecompile_recovery.ghidra_db.fields import (
    BINARY_OBJ_TYPE,
    BOOLEAN_TYPE,
    BYTE_TYPE,
    FIXED_10_TYPE,
    INT_TYPE,
    LONG_TYPE,
    SHORT_TYPE,
    STRING_TYPE,
    FieldDecodeError,
    build_schema,
    decode_field,
    decode_record,
    is_variable_length,
    parse_encoded_field_types,
    record_to_dict,
)

pytestmark = pytest.mark.unit


def _string(value: str | None) -> bytes:
    if value is None:
        return struct.pack(">i", -1)
    encoded = value.encode("utf-8")
    return struct.pack(">i", len(encoded)) + encoded


# -- individual field codecs ------------------------------------------------


def test_fixed_width_integers_are_signed_big_endian() -> None:
    assert decode_field(b"\xff", 0, BYTE_TYPE) == (-1, 1)
    assert decode_field(b"\xff\xff", 0, SHORT_TYPE) == (-1, 2)
    assert decode_field(b"\x00\x00\x01\x00", 0, INT_TYPE) == (256, 4)
    assert decode_field(b"\x00" * 7 + b"\x05", 0, LONG_TYPE) == (5, 8)


def test_boolean_and_fixed10() -> None:
    assert decode_field(b"\x01", 0, BOOLEAN_TYPE) == (True, 1)
    assert decode_field(b"\x00", 0, BOOLEAN_TYPE) == (False, 1)
    value, offset = decode_field(bytes(range(10)), 0, FIXED_10_TYPE)
    assert value == bytes(range(10)) and offset == 10


def test_string_roundtrip_and_offset() -> None:
    data = _string("CatBoolean") + b"trailing"
    value, offset = decode_field(data, 0, STRING_TYPE)

    assert value == "CatBoolean"
    assert offset == 4 + len("CatBoolean")


def test_null_string_is_none_not_empty() -> None:
    """Length -1 means null; conflating it with "" loses information."""

    assert decode_field(_string(None), 0, STRING_TYPE) == (None, 4)
    assert decode_field(_string(""), 0, STRING_TYPE) == ("", 4)


def test_binary_field_returns_bytes() -> None:
    payload = b"\xde\xad\xbe\xef"
    data = struct.pack(">i", len(payload)) + payload

    assert decode_field(data, 0, BINARY_OBJ_TYPE) == (payload, 8)


def test_truncated_field_raises() -> None:
    with pytest.raises(FieldDecodeError, match="truncated"):
        decode_field(b"\x00", 0, LONG_TYPE)


def test_implausible_length_raises() -> None:
    with pytest.raises(FieldDecodeError, match="implausible"):
        decode_field(struct.pack(">i", 9999), 0, STRING_TYPE)


def test_is_variable_length() -> None:
    assert is_variable_length(STRING_TYPE)
    assert is_variable_length(BINARY_OBJ_TYPE)
    assert not is_variable_length(LONG_TYPE)


# -- schema parsing ---------------------------------------------------------


def test_parses_plain_column_types() -> None:
    types, sparse = parse_encoded_field_types(bytes([STRING_TYPE, LONG_TYPE, INT_TYPE]))

    assert types == (STRING_TYPE, LONG_TYPE, INT_TYPE)
    assert sparse == frozenset()


def test_parses_sparse_extension() -> None:
    """-1 ends the column list; extension 1 lists sparse column indexes."""

    encoded = bytes([STRING_TYPE, LONG_TYPE, INT_TYPE, 0xFF, 1, 1, 2, 0xFF])
    types, sparse = parse_encoded_field_types(encoded)

    assert types == (STRING_TYPE, LONG_TYPE, INT_TYPE)
    assert sparse == frozenset({1, 2})


def test_unknown_extension_does_not_corrupt_columns() -> None:
    encoded = bytes([STRING_TYPE, LONG_TYPE, 0xFF, 99, 7, 7])
    types, sparse = parse_encoded_field_types(encoded)

    assert types == (STRING_TYPE, LONG_TYPE)
    assert sparse == frozenset()


def test_build_schema_splits_key_name_from_columns() -> None:
    schema = build_schema(
        key_type=LONG_TYPE,
        encoded_field_types=bytes([STRING_TYPE, LONG_TYPE]),
        packed_field_names="Key;Name;Address",
    )

    assert schema.key_name == "Key"
    assert schema.field_names == ("Name", "Address")
    assert schema.column_index("Address") == 1


def test_build_schema_tolerates_missing_names() -> None:
    schema = build_schema(
        key_type=LONG_TYPE,
        encoded_field_types=bytes([STRING_TYPE, LONG_TYPE]),
        packed_field_names="",
    )

    assert schema.column_count == 2
    assert schema.field_names == ("Column0", "Column1")


# -- record decoding --------------------------------------------------------


def test_decode_plain_record() -> None:
    schema = build_schema(
        key_type=LONG_TYPE,
        encoded_field_types=bytes([STRING_TYPE, INT_TYPE]),
        packed_field_names="Key;Name;Count",
    )
    data = _string("LoadArea") + struct.pack(">i", 42)

    assert decode_record(schema, data) == ["LoadArea", 42]


def test_decode_sparse_record_fills_absent_columns_with_none() -> None:
    """Mirrors the Symbols table: dense columns first, then a count byte and
    (columnIndex, value) pairs for whichever sparse columns exist."""

    schema = build_schema(
        key_type=LONG_TYPE,
        encoded_field_types=bytes([STRING_TYPE, LONG_TYPE, STRING_TYPE, 0xFF, 1, 2, 0xFF]),
        packed_field_names="Key;Name;Address;Comment",
    )
    data = _string("sub_1000") + struct.pack(">q", 0x401000) + bytes([0])

    assert decode_record(schema, data) == ["sub_1000", 0x401000, None]


def test_decode_sparse_record_reads_present_sparse_column() -> None:
    schema = build_schema(
        key_type=LONG_TYPE,
        encoded_field_types=bytes([STRING_TYPE, LONG_TYPE, STRING_TYPE, 0xFF, 1, 2, 0xFF]),
        packed_field_names="Key;Name;Address;Comment",
    )
    data = (
        _string("sub_1000")
        + struct.pack(">q", 0x401000)
        + bytes([1, 2])
        + _string("entry point")
    )

    assert decode_record(schema, data) == ["sub_1000", 0x401000, "entry point"]


def test_sparse_column_index_out_of_range_raises() -> None:
    schema = build_schema(
        key_type=LONG_TYPE,
        encoded_field_types=bytes([STRING_TYPE, 0xFF, 1, 1, 0xFF]),
        packed_field_names="Key;Name",
    )
    data = _string("x") + bytes([1, 9]) + _string("y")

    with pytest.raises(FieldDecodeError, match="outside schema arity"):
        decode_record(schema, data)


def test_record_to_dict_includes_key() -> None:
    schema = build_schema(
        key_type=LONG_TYPE,
        encoded_field_types=bytes([STRING_TYPE]),
        packed_field_names="SymbolID;Name",
    )

    assert record_to_dict(schema, 7, _string("LoadArea")) == {"SymbolID": 7, "Name": "LoadArea"}
