"""Reader for Ghidra chained buffers -- records too large for a single buffer.

Mirrors the read path of Ghidra's ``db.ChainedBuffer`` (Apache-2.0).

A record that does not fit in one buffer is stored either as a single data node
or as an index node pointing at a chain of data buffers::

    data node, non-indexed:  | 9 (1) | obfuscation|dataLength (4) | data... |
    data node, indexed:      | 9 (1) | data...                              |
    index node:              | 8 (1) | obfuscation|dataLength (4) | nextIndexId (4) | dataBufId... |

The high bit of the length word marks *obfuscated* content: the payload is XORed
with a fixed 128-byte mask, indexed by the byte's offset **within its own data
buffer** -- `ChainedBuffer.xorMaskByte` takes a `bufferOffset` "in the range 0 to
(dataSpace-1)", and `ChainedBuffer.get` resets it to 0 at every buffer boundary.
The mask therefore restarts on each data buffer, not once per record. This is
deliberately not encryption -- it exists so that raw strings are not trivially
greppable out of a database file -- but it must be undone or every large string
comes back as noise.

A data-buffer id of -1 is a *sparse* node, not the end of the chain:
`ChainedBuffer.getBytes` reads it as `dataSpace` zero bytes (unmasked) and keeps
going. Index nodes are pre-filled with -1 by `createIndex`, so the number of
entries has to come from the declared length -- a scan that stopped at the first
-1 could not tell a hole from the end.

Those zeros are what a chained buffer holds on its own. Ghidra lets a *caller*
substitute an `uninitializedDataSource` for sparse nodes, and one caller does:
`FileBytes` pairs each layered buffer with its original buffer, so an unpatched
layered buffer is stored entirely sparse and reads back as the original file
bytes. That pairing lives in the layer above, so anything reading `FileBytes`
has to supply it; here a hole is zeros.
"""

from __future__ import annotations

import struct

from .buffer_file import BufferFile, BufferFileError

# db.NodeMgr
CHAINED_BUFFER_INDEX_NODE = 8
CHAINED_BUFFER_DATA_NODE = 9

_OBFUSCATION_BIT = 0x80000000
_LENGTH_MASK = 0x7FFFFFFF

# db.ChainedBuffer node offsets.
_ID_SIZE = 4
_DATA_LENGTH_OFFSET = 1
_NEXT_INDEX_ID_OFFSET = 5
_INDEX_BASE_OFFSET = 9
_DATA_BASE_OFFSET_NONINDEXED = 5
_DATA_BASE_OFFSET_INDEXED = 1

# db.ChainedBuffer.XOR_MASK_BYTES -- 128 bytes, applied by offset % 128.
XOR_MASK_BYTES = bytes(
    (
        0x59, 0xEA, 0x67, 0x23, 0xDA, 0xB8, 0x00, 0xB8,
        0xC3, 0x48, 0xDD, 0x8B, 0x21, 0xD6, 0x94, 0x78,
        0x35, 0xAB, 0x2B, 0x7E, 0xB2, 0x4F, 0x82, 0x4E,
        0x0E, 0x16, 0xC4, 0x57, 0x12, 0x8E, 0x7E, 0xE6,
        0xB6, 0xBD, 0x56, 0x91, 0x57, 0x72, 0xE6, 0x91,
        0xDC, 0x52, 0x2E, 0xF2, 0x1A, 0xB7, 0xD6, 0x6F,
        0xDA, 0xDE, 0xE8, 0x48, 0xB1, 0xBB, 0x50, 0x6F,
        0xF4, 0xDD, 0x11, 0xEE, 0xF2, 0x67, 0xFE, 0x48,
        0x8D, 0xAE, 0x69, 0x1A, 0xE0, 0x26, 0x8C, 0x24,
        0x8E, 0x17, 0x76, 0x51, 0xE2, 0x60, 0xD7, 0xE6,
        0x83, 0x65, 0xD5, 0xF0, 0x7F, 0xF2, 0xA0, 0xD6,
        0x4B, 0xBD, 0x24, 0xD8, 0xAB, 0xEA, 0x9E, 0xA6,
        0x48, 0x94, 0x3E, 0x7B, 0x2C, 0xF4, 0xCE, 0xDC,
        0x69, 0x11, 0xF8, 0x3C, 0xA7, 0x3F, 0x5D, 0x77,
        0x94, 0x3F, 0xE4, 0x8E, 0x48, 0x20, 0xDB, 0x56,
        0x32, 0xC1, 0x87, 0x01, 0x2E, 0xE3, 0x7F, 0x40,
    )
)

_MAX_CHAIN_BUFFERS = 1 << 20


def deobfuscate(data: bytes, start_offset: int = 0) -> bytes:
    """Undo the XOR mask.

    `start_offset` is the offset of `data[0]` **within its data buffer**, which
    is what `db.ChainedBuffer.xorMaskByte` indexes the mask by. Whole buffers
    therefore start at 0; the argument exists for partial reads.
    """

    mask = XOR_MASK_BYTES
    return bytes(byte ^ mask[(start_offset + index) % 128] for index, byte in enumerate(data))


def read_chained_buffer(buffer_file: BufferFile, buffer_id: int) -> bytes:
    """Read the full logical contents of the chained buffer rooted at `buffer_id`."""

    root = buffer_file.read_buffer(buffer_id)
    node_type = root[0]
    if node_type not in (CHAINED_BUFFER_DATA_NODE, CHAINED_BUFFER_INDEX_NODE):
        raise BufferFileError(
            f"buffer {buffer_id} is not a chained buffer (node type {node_type}, "
            f"expected {CHAINED_BUFFER_DATA_NODE} or {CHAINED_BUFFER_INDEX_NODE})"
        )

    (raw_length,) = struct.unpack(">I", root[_DATA_LENGTH_OFFSET : _DATA_LENGTH_OFFSET + 4])
    obfuscated = bool(raw_length & _OBFUSCATION_BIT)
    total_length = raw_length & _LENGTH_MASK

    if node_type == CHAINED_BUFFER_DATA_NODE:
        payload = root[_DATA_BASE_OFFSET_NONINDEXED : _DATA_BASE_OFFSET_NONINDEXED + total_length]
        if len(payload) < total_length:
            raise BufferFileError(
                f"chained buffer {buffer_id}: declared length {total_length} exceeds buffer payload"
            )
        return deobfuscate(payload) if obfuscated else payload

    # ChainedBuffer.allocateIndex: every data buffer holds `data_space` logical
    # bytes, so the chain is a fixed number of equal slices of the record.
    data_space = buffer_file.header.buffer_size - _DATA_BASE_OFFSET_INDEXED
    data_ids = _collect_data_buffer_ids(buffer_file, buffer_id, root, total_length, data_space)

    chunks: list[bytes] = []
    remaining = total_length
    for data_id in data_ids:
        chunk_length = min(data_space, remaining)
        if data_id < 0:
            # ChainedBuffer.getBytes: a never-written data node reads as zeros,
            # and the XOR mask is not applied to them.
            chunks.append(bytes(chunk_length))
            remaining -= chunk_length
            continue
        node = buffer_file.read_buffer(data_id)
        if node[0] != CHAINED_BUFFER_DATA_NODE:
            raise BufferFileError(
                f"chained buffer {buffer_id}: buffer {data_id} is node type {node[0]}, "
                f"expected a data node"
            )
        # Indexed data nodes carry no length word -- the index node owns the total.
        chunk = node[_DATA_BASE_OFFSET_INDEXED : _DATA_BASE_OFFSET_INDEXED + chunk_length]
        # The mask restarts here: this byte is at offset 0 of *its* data buffer.
        chunks.append(deobfuscate(chunk) if obfuscated else chunk)
        remaining -= len(chunk)

    # No short-read check: the slot count is derived from `total_length` rather
    # than discovered, so a chain that cannot supply it fails in the walk above.
    return b"".join(chunks)


def _collect_data_buffer_ids(
    buffer_file: BufferFile, root_id: int, root: bytes, total_length: int, data_space: int
) -> list[int]:
    """Walk index nodes, gathering data-buffer ids in order.

    Mirrors `db.ChainedBuffer.buildIndex`: the slot count comes from the declared
    length, and every slot is taken, negative ones included. Negative means a
    sparse (never-written) data node -- `createIndex` pre-fills the whole index
    with -1 -- so stopping at the first one would truncate the record at its
    first hole and could not tell that hole from the end of the chain.

    Bounded and cycle-guarded: a corrupt `nextIndexId` chain must not spin.
    """

    indexes_per_buffer = (buffer_file.header.buffer_size - _INDEX_BASE_OFFSET) // _ID_SIZE
    if indexes_per_buffer <= 0:
        raise BufferFileError(f"chained buffer {root_id}: buffers too small to hold an index")

    # allocateIndex: indexCount = ((size - 1) / dataSpace) + 1, i.e. one slot per
    # data buffer the declared length needs.
    index_count = (total_length + data_space - 1) // data_space
    if index_count > _MAX_CHAIN_BUFFERS:
        raise BufferFileError(f"chained buffer {root_id}: implausible chain length {index_count}")

    ids: list[int] = []
    seen_index_nodes = {root_id}
    node = root
    slot = 0
    offset = _INDEX_BASE_OFFSET
    while len(ids) < index_count:
        if slot == indexes_per_buffer:
            (next_index_id,) = struct.unpack(
                ">i", node[_NEXT_INDEX_ID_OFFSET : _NEXT_INDEX_ID_OFFSET + _ID_SIZE]
            )
            if next_index_id < 0:
                # buildIndex throws AssertException here: createIndex allocated
                # every index buffer the declared length needs, so running out
                # of them means the record is shorter than it claims.
                raise BufferFileError(
                    f"chained buffer {root_id}: index chain ends after {len(ids)} of "
                    f"{index_count} data buffers"
                )
            if next_index_id in seen_index_nodes:
                raise BufferFileError(
                    f"chained buffer {root_id}: index chain revisits buffer {next_index_id}"
                )
            seen_index_nodes.add(next_index_id)
            node = buffer_file.read_buffer(next_index_id)
            if node[0] != CHAINED_BUFFER_INDEX_NODE:
                raise BufferFileError(
                    f"chained buffer {root_id}: buffer {next_index_id} is not an index node"
                )
            slot = 0
            offset = _INDEX_BASE_OFFSET
        (data_id,) = struct.unpack(">i", node[offset : offset + _ID_SIZE])
        ids.append(data_id)
        offset += _ID_SIZE
        slot += 1
    return ids
