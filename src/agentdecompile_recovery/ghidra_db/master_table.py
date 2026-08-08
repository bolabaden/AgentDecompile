"""DBParms and the master table -- the catalogue of every table in a database.

Mirrors Ghidra's ``db.DBParms`` and ``db.MasterTable`` (Apache-2.0).

Buffer 0 holds DBParms as a chained-buffer data node::

    | 9 (1) | dataLength (4) | version (1) | param0 (4) | param1 (4) | ... |

Parameter 0 is the master table's root buffer id. The master table is itself an
ordinary long-key B-tree whose key is the table number, so once the buffer and
B-tree layers work, the catalogue falls out of them.

Each master-table record describes one table, including the encoded schema
needed to decode that table's own records. Schema *version* is stored per table
and must be read rather than assumed: Ghidra keeps V0..Vn adapter classes
precisely because older databases carry older layouts.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any, Iterator

from .btree import iter_table_records
from .buffer_file import BufferFile, BufferFileError
from .fields import (
    BINARY_OBJ_TYPE,
    BYTE_TYPE,
    INT_TYPE,
    LONG_TYPE,
    STRING_TYPE,
    Schema,
    build_schema,
    decode_record,
)

# db.DBParms
MASTER_TABLE_ROOT_BUFFER_ID_PARM = 0
DATABASE_ID_HIGH_PARM = 1
DATABASE_ID_LOW_PARM = 2

_DBPARMS_BUFFER_INDEX = 0
_DBPARMS_NODE_TYPE = 9
_DBPARMS_VERSION_OFFSET = 5
_DBPARMS_FIRST_PARM_OFFSET = 6

# db.TableRecord.getTableRecordSchema() -- fixed, version 0, key "TableNum" (long).
MASTER_TABLE_SCHEMA = build_schema(
    key_type=LONG_TYPE,
    encoded_field_types=bytes(
        [
            STRING_TYPE,      # TableName
            INT_TYPE,         # SchemaVersion
            INT_TYPE,         # RootBufferId
            BYTE_TYPE,        # KeyType
            BINARY_OBJ_TYPE,  # FieldTypes
            STRING_TYPE,      # FieldNames
            INT_TYPE,         # IndexColumn
            LONG_TYPE,        # MaxKey
            INT_TYPE,         # RecordCount
        ]
    ),
    packed_field_names=(
        "TableNum;TableName;SchemaVersion;RootBufferId;KeyType;"
        "FieldTypes;FieldNames;IndexColumn;MaxKey;RecordCount"
    ),
)


class MasterTableError(Exception):
    """Raised when the database parameters or catalogue cannot be read."""


@dataclass(frozen=True)
class TableRecord:
    """One row of the master table: the description of a single table."""

    table_number: int
    name: str
    schema_version: int
    root_buffer_id: int
    key_type: int
    encoded_field_types: bytes
    packed_field_names: str
    index_column: int
    max_key: int
    record_count: int

    @property
    def is_index_table(self) -> bool:
        """Secondary index tables share a primary table's name.

        They are an implementation detail of key lookup and carry no rows a
        caller wants, so scans skip them by default.
        """

        return self.index_column >= 0

    @property
    def is_empty(self) -> bool:
        return self.root_buffer_id < 0

    def schema(self) -> Schema:
        return build_schema(
            key_type=self.key_type,
            encoded_field_types=self.encoded_field_types or b"",
            packed_field_names=self.packed_field_names or "",
            version=self.schema_version,
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "tableNumber": self.table_number,
            "name": self.name,
            "schemaVersion": self.schema_version,
            "recordCount": self.record_count,
            "isIndex": self.is_index_table,
            "isEmpty": self.is_empty,
            "columns": list(self.schema().field_names),
        }


def read_db_parms(buffer_file: BufferFile) -> list[int]:
    """Read the DBParms array out of buffer 0."""

    try:
        node = buffer_file.read_buffer(_DBPARMS_BUFFER_INDEX)
    except (BufferFileError, IndexError) as exc:
        raise MasterTableError(f"{buffer_file.path}: cannot read DBParms buffer") from exc

    if node[0] != _DBPARMS_NODE_TYPE:
        raise MasterTableError(
            f"{buffer_file.path}: buffer 0 has node type {node[0]}, expected "
            f"{_DBPARMS_NODE_TYPE} (chained-buffer data node holding DBParms)"
        )

    (data_length,) = struct.unpack_from(">i", node, 1)
    data_length &= 0x7FFFFFFF
    version = node[_DBPARMS_VERSION_OFFSET]
    if version != 1:
        raise MasterTableError(f"{buffer_file.path}: unsupported DBParms version {version}")

    available = min(data_length, len(node) - _DBPARMS_FIRST_PARM_OFFSET)
    count = max(0, available // 4)
    return [
        struct.unpack_from(">i", node, _DBPARMS_FIRST_PARM_OFFSET + index * 4)[0]
        for index in range(count)
    ]


def master_table_root_id(buffer_file: BufferFile) -> int:
    parms = read_db_parms(buffer_file)
    if not parms:
        raise MasterTableError(f"{buffer_file.path}: DBParms is empty")
    return parms[MASTER_TABLE_ROOT_BUFFER_ID_PARM]


def iter_master_table(buffer_file: BufferFile) -> Iterator[TableRecord]:
    """Yield a TableRecord for every table in the database, index tables included."""

    root_id = master_table_root_id(buffer_file)
    for key, record_bytes in iter_table_records(buffer_file, root_id, MASTER_TABLE_SCHEMA):
        values = decode_record(MASTER_TABLE_SCHEMA, record_bytes)
        yield TableRecord(
            table_number=key,
            name=values[0] or "",
            schema_version=values[1] or 0,
            root_buffer_id=values[2] if values[2] is not None else -1,
            key_type=values[3] if values[3] is not None else LONG_TYPE,
            encoded_field_types=values[4] or b"",
            packed_field_names=values[5] or "",
            index_column=values[6] if values[6] is not None else -1,
            max_key=values[7] or 0,
            record_count=values[8] or 0,
        )


def read_table_catalogue(buffer_file: BufferFile, *, include_index_tables: bool = False) -> list[TableRecord]:
    """All primary tables in the database, ordered by table number."""

    tables = list(iter_master_table(buffer_file))
    if not include_index_tables:
        tables = [table for table in tables if not table.is_index_table]
    return sorted(tables, key=lambda table: table.table_number)


def find_table(buffer_file: BufferFile, name: str) -> TableRecord | None:
    """Locate a primary table by exact name."""

    for table in iter_master_table(buffer_file):
        if table.name == name and not table.is_index_table:
            return table
    return None


def iter_rows(buffer_file: BufferFile, table: TableRecord) -> Iterator[dict[str, Any]]:
    """Yield decoded `{columnName: value}` rows for one table."""

    schema = table.schema()
    for key, record_bytes in iter_table_records(buffer_file, table.root_buffer_id, schema):
        values = decode_record(schema, record_bytes)
        row: dict[str, Any] = {schema.key_name: key}
        for name, value in zip(schema.field_names, values):
            row[name] = value
        yield row
