"""Field codecs, schema decoding, and record decoding for Ghidra databases.

Mirrors Ghidra's ``db.Field``, ``db.Schema``, ``db.DBRecord`` and
``db.SparseRecord`` (Apache-2.0). All integers are big-endian and signed, as
written by Java's DataOutput.

A record is simply its fields concatenated -- there is no per-record header, so
decoding depends entirely on having the right schema. Sparse schemas differ:
non-sparse columns appear in order, then a count byte, then `(columnIndex,
value)` pairs for whichever sparse columns are actually present. The Symbols
table uses sparse columns, so this is required rather than optional.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field as dataclass_field
from typing import Any

# db.Field
BYTE_TYPE = 0
SHORT_TYPE = 1
INT_TYPE = 2
LONG_TYPE = 3
STRING_TYPE = 4
BINARY_OBJ_TYPE = 5
BOOLEAN_TYPE = 6
FIXED_10_TYPE = 7
LEGACY_INDEX_LONG_TYPE = 8
FIELD_RESERVED_15_TYPE = 0x0F

FIELD_TYPE_MASK = 0x0F

# db.Schema
FIELD_EXTENSION_INDICATOR = -1
SPARSE_FIELD_LIST_EXTENSION = 1

_FIXED_WIDTHS = {
    BYTE_TYPE: 1,
    SHORT_TYPE: 2,
    INT_TYPE: 4,
    LONG_TYPE: 8,
    BOOLEAN_TYPE: 1,
    FIXED_10_TYPE: 10,
}

_TYPE_NAMES = {
    BYTE_TYPE: "byte",
    SHORT_TYPE: "short",
    INT_TYPE: "int",
    LONG_TYPE: "long",
    STRING_TYPE: "string",
    BINARY_OBJ_TYPE: "binary",
    BOOLEAN_TYPE: "boolean",
    FIXED_10_TYPE: "fixed10",
    LEGACY_INDEX_LONG_TYPE: "legacyIndexLong",
}


class FieldDecodeError(Exception):
    """Raised when field or record bytes do not match the declared schema."""


def field_type_name(field_type: int) -> str:
    return _TYPE_NAMES.get(field_type & FIELD_TYPE_MASK, f"unknown({field_type})")


def is_variable_length(field_type: int) -> bool:
    """Variable-length fields carry their own length prefix.

    LEGACY_INDEX_LONG is treated as variable-length, matching
    ``db.LegacyIndexField``.
    """

    base = field_type & FIELD_TYPE_MASK
    return base in (STRING_TYPE, BINARY_OBJ_TYPE, LEGACY_INDEX_LONG_TYPE)


def decode_field(data: bytes, offset: int, field_type: int) -> tuple[Any, int]:
    """Decode one field, returning `(value, next_offset)`.

    String and binary fields encode `int length` first; a length of -1 means
    null, which is distinct from an empty value and must survive as None.
    """

    base = field_type & FIELD_TYPE_MASK
    width = _FIXED_WIDTHS.get(base)

    if width is not None:
        if offset + width > len(data):
            raise FieldDecodeError(
                f"truncated {field_type_name(base)} field at offset {offset} "
                f"(need {width} bytes, have {len(data) - offset})"
            )
        chunk = data[offset : offset + width]
        if base == BOOLEAN_TYPE:
            return bool(chunk[0]), offset + width
        if base == FIXED_10_TYPE:
            return chunk, offset + width
        return int.from_bytes(chunk, "big", signed=True), offset + width

    if base in (STRING_TYPE, BINARY_OBJ_TYPE, LEGACY_INDEX_LONG_TYPE):
        if offset + 4 > len(data):
            raise FieldDecodeError(f"truncated length prefix at offset {offset}")
        (length,) = struct.unpack_from(">i", data, offset)
        offset += 4
        if length == -1:
            return None, offset
        if length < 0 or offset + length > len(data):
            raise FieldDecodeError(
                f"implausible {field_type_name(base)} length {length} at offset {offset}"
            )
        payload = data[offset : offset + length]
        offset += length
        if base == STRING_TYPE:
            return payload.decode("utf-8", errors="replace"), offset
        return payload, offset

    raise FieldDecodeError(f"unsupported field type {field_type}")


@dataclass(frozen=True)
class Schema:
    """Column layout for one table.

    `key_name` is the first entry of the packed name list; the remainder name
    the columns. `sparse_columns` are those declared via the schema's extension
    section and are encoded differently -- see `decode_record`.
    """

    key_type: int
    field_types: tuple[int, ...]
    key_name: str
    field_names: tuple[str, ...]
    sparse_columns: frozenset[int] = dataclass_field(default_factory=frozenset)
    version: int = 0

    @property
    def is_sparse(self) -> bool:
        return bool(self.sparse_columns)

    @property
    def column_count(self) -> int:
        return len(self.field_types)

    def column_index(self, name: str) -> int:
        try:
            return self.field_names.index(name)
        except ValueError as exc:
            raise KeyError(f"no column {name!r} in schema ({list(self.field_names)})") from exc


def parse_encoded_field_types(encoded: bytes) -> tuple[tuple[int, ...], frozenset[int]]:
    """Split the encoded type array into column types and sparse column indexes.

    A byte of -1 terminates the column list and begins extensions; extension
    type 1 lists sparse column indexes until the next -1 or end of data.
    """

    types: list[int] = []
    sparse: set[int] = set()
    index = 0
    while index < len(encoded):
        value = encoded[index]
        signed = value - 256 if value > 127 else value
        if signed == FIELD_EXTENSION_INDICATOR:
            index += 1
            break
        types.append(value)
        index += 1

    while index < len(encoded):
        extension = encoded[index]
        index += 1
        if extension != SPARSE_FIELD_LIST_EXTENSION:
            # Unknown extension: stop rather than misread the remainder as columns.
            break
        while index < len(encoded):
            value = encoded[index]
            signed = value - 256 if value > 127 else value
            if signed == FIELD_EXTENSION_INDICATOR:
                index += 1
                break
            sparse.add(value)
            index += 1

    return tuple(types), frozenset(sparse)


def build_schema(
    *,
    key_type: int,
    encoded_field_types: bytes,
    packed_field_names: str,
    version: int = 0,
) -> Schema:
    """Assemble a Schema from the raw master-table columns."""

    types, sparse = parse_encoded_field_types(encoded_field_types)
    names = packed_field_names.split(";") if packed_field_names else []
    key_name = names[0] if names else "Key"
    column_names = tuple(names[1:]) if len(names) > 1 else tuple()

    if column_names and len(column_names) != len(types):
        # Trust the type array for arity; pad or trim names so lookups stay safe.
        column_names = tuple(
            column_names[index] if index < len(column_names) else f"Column{index}"
            for index in range(len(types))
        )
    elif not column_names:
        column_names = tuple(f"Column{index}" for index in range(len(types)))

    return Schema(
        key_type=key_type,
        field_types=types,
        key_name=key_name,
        field_names=column_names,
        sparse_columns=sparse,
        version=version,
    )


def decode_record(schema: Schema, data: bytes) -> list[Any]:
    """Decode one record body into a list of column values.

    Sparse columns absent from the encoding come back as None.
    """

    if not schema.is_sparse:
        values: list[Any] = []
        offset = 0
        for field_type in schema.field_types:
            value, offset = decode_field(data, offset, field_type)
            values.append(value)
        return values

    values = [None] * schema.column_count
    offset = 0
    for index, field_type in enumerate(schema.field_types):
        if index in schema.sparse_columns:
            continue
        value, offset = decode_field(data, offset, field_type)
        values[index] = value

    if offset >= len(data):
        return values

    sparse_count = data[offset]
    offset += 1
    for _ in range(sparse_count):
        if offset >= len(data):
            raise FieldDecodeError("truncated sparse column index")
        column = data[offset]
        offset += 1
        if column >= schema.column_count:
            raise FieldDecodeError(
                f"sparse column index {column} outside schema arity {schema.column_count}"
            )
        value, offset = decode_field(data, offset, schema.field_types[column])
        values[column] = value

    return values


def record_to_dict(schema: Schema, key: Any, data: bytes) -> dict[str, Any]:
    """Decode a record into `{columnName: value}` with the key included."""

    values = decode_record(schema, data)
    row: dict[str, Any] = {schema.key_name: key}
    for name, value in zip(schema.field_names, values):
        row[name] = value
    return row
