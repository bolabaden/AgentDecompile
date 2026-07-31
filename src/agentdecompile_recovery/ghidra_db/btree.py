"""B-tree traversal for Ghidra database tables.

Mirrors Ghidra's ``db.LongKeyInteriorNode``, ``db.VarRecNode``,
``db.FixedRecNode`` and ``db.NodeMgr`` (Apache-2.0).

Only long-key nodes (types 0-2) are implemented. That covers the master table
and every table this project reads from a program database -- Symbols, Comments,
Function Data, Memory Blocks -- all of which key on a long. Other node kinds
raise rather than guess, because a misread node yields records that decode
without error and are simply wrong.

A full table scan does not need key search: descend to the leftmost leaf once,
then follow the `nextLeafId` chain.

Long-key node layouts::

    type 0  interior   | type(1) | keyCount(4) | [key(8) childId(4)] * n |
    type 1  var rec    | type(1) | keyCount(4) | prev(4) | next(4) |
                         [key(8) recOffset(4) indirect(1)] * n | free | recN..rec0 |
    type 2  fixed rec  | type(1) | keyCount(4) | prev(4) | next(4) | [key(8) rec(L)] * n |

Variable-length records are packed backwards from the end of the buffer, so a
record's length is derived from the *previous* record's offset.
"""

from __future__ import annotations

import struct
from typing import Any, Iterator

from .buffer_file import BufferFile, BufferFileError
from .chained_buffer import read_chained_buffer
from .fields import Schema, is_variable_length

# db.NodeMgr
LONGKEY_INTERIOR_NODE = 0
LONGKEY_VAR_REC_NODE = 1
LONGKEY_FIXED_REC_NODE = 2
VARKEY_INTERIOR_NODE = 3
VARKEY_REC_NODE = 4
FIXEDKEY_INTERIOR_NODE = 5
FIXEDKEY_VAR_REC_NODE = 6
FIXEDKEY_FIXED_REC_NODE = 7

NODE_HEADER_SIZE = 1
KEY_COUNT_OFFSET = NODE_HEADER_SIZE
LONGKEY_NODE_HEADER_SIZE = NODE_HEADER_SIZE + 4

# db.LongKeyRecordNode
PREV_LEAF_ID_OFFSET = LONGKEY_NODE_HEADER_SIZE
NEXT_LEAF_ID_OFFSET = PREV_LEAF_ID_OFFSET + 4
RECORD_LEAF_HEADER_SIZE = LONGKEY_NODE_HEADER_SIZE + 8

# db.LongKeyInteriorNode
_INTERIOR_BASE = LONGKEY_NODE_HEADER_SIZE
_INTERIOR_ENTRY_SIZE = 12

# db.VarRecNode
_VAR_KEY_BASE = RECORD_LEAF_HEADER_SIZE
_VAR_ENTRY_SIZE = 13

# db.FixedRecNode
_FIXED_ENTRY_BASE = RECORD_LEAF_HEADER_SIZE

# db.VarKeyNode / db.VarKeyRecordNode / db.VarKeyInteriorNode
VARKEY_KEY_TYPE_OFFSET = NODE_HEADER_SIZE
VARKEY_COUNT_OFFSET = VARKEY_KEY_TYPE_OFFSET + 1
VARKEY_NODE_HEADER_SIZE = NODE_HEADER_SIZE + 1 + 4
_VARKEY_PREV_LEAF_OFFSET = VARKEY_NODE_HEADER_SIZE
_VARKEY_NEXT_LEAF_OFFSET = _VARKEY_PREV_LEAF_OFFSET + 4
_VARKEY_REC_HEADER_SIZE = VARKEY_NODE_HEADER_SIZE + 8
_VARKEY_REC_ENTRY_SIZE = 5
_VARKEY_INTERIOR_BASE = VARKEY_NODE_HEADER_SIZE
_VARKEY_INTERIOR_ENTRY_SIZE = 8

_MAX_DEPTH = 64
_MAX_LEAVES = 1 << 22


class BTreeError(Exception):
    """Raised when a node cannot be interpreted as the expected B-tree shape."""


def node_type(node: bytes) -> int:
    if not node:
        raise BTreeError("empty node buffer")
    return node[0]


def key_count(node: bytes) -> int:
    """Number of entries in a node.

    The count sits at a different offset for var-key nodes: they carry a
    key-type byte at offset 1, pushing the count to offset 2. Reading the
    long-key position on a var-key node yields a huge bogus count and a scan
    that walks off into arbitrary bytes.
    """

    kind = node_type(node)
    offset = VARKEY_COUNT_OFFSET if kind in (VARKEY_INTERIOR_NODE, VARKEY_REC_NODE) else KEY_COUNT_OFFSET
    (count,) = struct.unpack_from(">i", node, offset)
    return count


def fixed_record_length(schema: Schema) -> int:
    """Total byte width of a schema whose columns are all fixed-length."""

    widths = {0: 1, 1: 2, 2: 4, 3: 8, 6: 1, 7: 10}
    total = 0
    for field_type in schema.field_types:
        if is_variable_length(field_type):
            raise BTreeError("fixed-record node used with a variable-length schema")
        width = widths.get(field_type & 0x0F)
        if width is None:
            raise BTreeError(f"unsupported fixed field type {field_type}")
        total += width
    return total


def _leftmost_leaf(buffer_file: BufferFile, root_id: int) -> tuple[int, bytes]:
    """Descend interior nodes to the first leaf."""

    current_id = root_id
    for _ in range(_MAX_DEPTH):
        node = buffer_file.read_buffer(current_id)
        kind = node_type(node)
        if kind in (LONGKEY_VAR_REC_NODE, LONGKEY_FIXED_REC_NODE):
            return current_id, node
        if kind == VARKEY_REC_NODE:
            return current_id, node
        if kind == LONGKEY_INTERIOR_NODE:
            if key_count(node) <= 0:
                raise BTreeError(f"interior node {current_id} declares no children")
            (child_id,) = struct.unpack_from(">i", node, _INTERIOR_BASE + 8)
            current_id = child_id
            continue
        if kind == VARKEY_INTERIOR_NODE:
            (child_id,) = struct.unpack_from(">i", node, _VARKEY_INTERIOR_BASE + 4)
            current_id = child_id
            continue
        if kind in (FIXEDKEY_INTERIOR_NODE, FIXEDKEY_VAR_REC_NODE, FIXEDKEY_FIXED_REC_NODE):
            raise BTreeError(
                f"node {current_id} has type {kind}; fixed-key nodes (5-7) are not supported"
            )
        raise BTreeError(f"node {current_id} has unrecognized type {kind}")
    raise BTreeError(f"b-tree deeper than {_MAX_DEPTH}; refusing to descend further")


def _iter_var_rec_leaf(
    buffer_file: BufferFile, node: bytes
) -> Iterator[tuple[int, bytes]]:
    """Yield `(key, record_bytes)` from a variable-length-record leaf."""

    count = key_count(node)
    previous_offset = len(node)
    for index in range(count):
        entry = _VAR_KEY_BASE + index * _VAR_ENTRY_SIZE
        (key,) = struct.unpack_from(">q", node, entry)
        (rec_offset,) = struct.unpack_from(">i", node, entry + 8)
        indirect = node[entry + 12]

        if rec_offset < 0 or rec_offset > len(node):
            raise BTreeError(f"record offset {rec_offset} outside node")

        if indirect:
            (chained_id,) = struct.unpack_from(">i", node, rec_offset)
            yield key, read_chained_buffer(buffer_file, chained_id)
        else:
            # Records are packed backwards from the buffer end.
            length = previous_offset - rec_offset
            if length < 0:
                raise BTreeError("record offsets are not monotonically decreasing")
            yield key, node[rec_offset : rec_offset + length]
        previous_offset = rec_offset


def _iter_fixed_rec_leaf(node: bytes, record_length: int) -> Iterator[tuple[int, bytes]]:
    count = key_count(node)
    entry_size = 8 + record_length
    for index in range(count):
        entry = _FIXED_ENTRY_BASE + index * entry_size
        if entry + entry_size > len(node):
            raise BTreeError("fixed record entry runs past end of node")
        (key,) = struct.unpack_from(">q", node, entry)
        yield key, node[entry + 8 : entry + 8 + record_length]


def _iter_var_key_leaf(
    buffer_file: BufferFile, node: bytes, key_type: int
) -> Iterator[tuple[Any, bytes]]:
    """Yield `(key, record_bytes)` from a variable-key leaf.

    Key and record share one blob at `keyOffset`, packed backwards from the end
    of the buffer, so the key must be decoded first to find where the record
    starts.
    """

    from .fields import decode_field

    count = key_count(node)
    previous_offset = len(node)
    for index in range(count):
        entry = _VARKEY_REC_HEADER_SIZE + index * _VARKEY_REC_ENTRY_SIZE
        (key_offset,) = struct.unpack_from(">i", node, entry)
        indirect = node[entry + 4]
        if key_offset < 0 or key_offset > len(node):
            raise BTreeError(f"var-key offset {key_offset} outside node")

        key, after_key = decode_field(node, key_offset, key_type)
        if indirect:
            (chained_id,) = struct.unpack_from(">i", node, after_key)
            yield key, read_chained_buffer(buffer_file, chained_id)
        else:
            end = previous_offset
            if end < after_key:
                raise BTreeError("var-key entries are not monotonically decreasing")
            yield key, node[after_key:end]
        previous_offset = key_offset


def iter_table_records(
    buffer_file: BufferFile, root_buffer_id: int, schema: Schema
) -> Iterator[tuple[Any, bytes]]:
    """Yield every `(key, record_bytes)` in a table, in key order.

    An empty table is signalled by `root_buffer_id == -1` and yields nothing.
    """

    if root_buffer_id is None or root_buffer_id < 0:
        return

    leaf_id, node = _leftmost_leaf(buffer_file, root_buffer_id)

    record_length: int | None = None
    if node_type(node) == LONGKEY_FIXED_REC_NODE:
        record_length = fixed_record_length(schema)

    seen: set[int] = set()
    leaves = 0
    while True:
        if leaf_id in seen:
            raise BTreeError(f"leaf chain revisits buffer {leaf_id}; database is corrupt")
        seen.add(leaf_id)
        leaves += 1
        if leaves > _MAX_LEAVES:
            raise BTreeError("leaf chain exceeds sanity bound")

        kind = node_type(node)
        if kind == LONGKEY_VAR_REC_NODE:
            yield from _iter_var_rec_leaf(buffer_file, node)
        elif kind == LONGKEY_FIXED_REC_NODE:
            if record_length is None:
                record_length = fixed_record_length(schema)
            yield from _iter_fixed_rec_leaf(node, record_length)
        elif kind == VARKEY_REC_NODE:
            # Key type is stored in the node itself rather than taken from the
            # schema: legacy databases can disagree with the declared key type.
            yield from _iter_var_key_leaf(buffer_file, node, node[1])
        else:
            raise BTreeError(f"expected a record leaf node, found type {kind}")

        next_offset = (
            _VARKEY_NEXT_LEAF_OFFSET if kind == VARKEY_REC_NODE else NEXT_LEAF_ID_OFFSET
        )
        (next_leaf,) = struct.unpack_from(">i", node, next_offset)
        if next_leaf < 0:
            return
        try:
            node = buffer_file.read_buffer(next_leaf)
        except (BufferFileError, IndexError) as exc:
            raise BTreeError(f"leaf chain points at unreadable buffer {next_leaf}") from exc
        leaf_id = next_leaf
