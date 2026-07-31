"""Reader for Ghidra chained buffers -- records too large for a single buffer.

Mirrors the read path of Ghidra's ``db.ChainedBuffer`` (Apache-2.0).

A record that does not fit in one buffer is stored either as a single data node
or as an index node pointing at a chain of data buffers::

    data node, non-indexed:  | 9 (1) | obfuscation|dataLength (4) | data... |
    data node, indexed:      | 9 (1) | data...                              |
    index node:              | 8 (1) | obfuscation|dataLength (4) | nextIndexId (4) | dataBufId... |

The high bit of the length word marks *obfuscated* content: the payload is XORed
with a fixed 128-byte mask, indexed by the byte's offset within the logical
record (not within its buffer). This is deliberately not encryption -- it exists
so that raw strings are not trivially greppable out of a database file -- but it
must be undone or every large string comes back as noise.
"""

from __future__ import annotations

import struct

from .buffer_file import BufferFile, BufferFileError

# db.NodeMgr
CHAINED_BUFFER_INDEX_NODE = 8
CHAINED_BUFFER_DATA_NODE = 9

_OBFUSCATION_BIT = 0x80000000
_LENGTH_MASK = 0x7FFFFFFF

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
    """Undo the XOR mask. `start_offset` is the offset of `data[0]` in the record."""

    mask = XOR_MASK_BYTES
    return bytes(byte ^ mask[(start_offset + index) % 128] for index, byte in enumerate(data))


def read_chained_buffer(buffer_file: BufferFile, buffer_id: int) -> bytes:
    """Read the full logical contents of the chained buffer rooted at `buffer_id`."""

    root = buffer_file.read_buffer(buffer_id)
    node_type = root[0]

    if node_type == CHAINED_BUFFER_DATA_NODE:
        (raw_length,) = struct.unpack(">I", root[1:5])
        obfuscated = bool(raw_length & _OBFUSCATION_BIT)
        length = raw_length & _LENGTH_MASK
        payload = root[5 : 5 + length]
        if len(payload) < length:
            raise BufferFileError(
                f"chained buffer {buffer_id}: declared length {length} exceeds buffer payload"
            )
        return deobfuscate(payload, 0) if obfuscated else payload

    if node_type != CHAINED_BUFFER_INDEX_NODE:
        raise BufferFileError(
            f"buffer {buffer_id} is not a chained buffer (node type {node_type}, "
            f"expected {CHAINED_BUFFER_DATA_NODE} or {CHAINED_BUFFER_INDEX_NODE})"
        )

    (raw_length,) = struct.unpack(">I", root[1:5])
    obfuscated = bool(raw_length & _OBFUSCATION_BIT)
    total_length = raw_length & _LENGTH_MASK

    data_ids = _collect_data_buffer_ids(buffer_file, buffer_id, root)

    chunks: list[bytes] = []
    remaining = total_length
    for data_id in data_ids:
        if remaining <= 0:
            break
        node = buffer_file.read_buffer(data_id)
        if node[0] != CHAINED_BUFFER_DATA_NODE:
            raise BufferFileError(
                f"chained buffer {buffer_id}: buffer {data_id} is node type {node[0]}, "
                f"expected a data node"
            )
        # Indexed data nodes carry no length word -- the index node owns the total.
        chunk = node[1:]
        chunks.append(chunk[:remaining])
        remaining -= len(chunks[-1])

    data = b"".join(chunks)
    if len(data) < total_length:
        raise BufferFileError(
            f"chained buffer {buffer_id}: recovered {len(data)} of {total_length} declared bytes"
        )
    return deobfuscate(data, 0) if obfuscated else data


def _collect_data_buffer_ids(buffer_file: BufferFile, root_id: int, root: bytes) -> list[int]:
    """Walk index nodes, gathering data-buffer ids in order.

    Bounded and cycle-guarded: a corrupt `nextIndexId` chain must not spin.
    """

    ids: list[int] = []
    seen_index_nodes = {root_id}
    node = root
    while True:
        (next_index_id,) = struct.unpack(">i", node[5:9])
        for offset in range(9, len(node) - 3, 4):
            (data_id,) = struct.unpack(">i", node[offset : offset + 4])
            if data_id < 0:
                break
            ids.append(data_id)
            if len(ids) > _MAX_CHAIN_BUFFERS:
                raise BufferFileError(f"chained buffer {root_id}: implausible chain length")
        if next_index_id < 0 or next_index_id in seen_index_nodes:
            return ids
        seen_index_nodes.add(next_index_id)
        node = buffer_file.read_buffer(next_index_id)
        if node[0] != CHAINED_BUFFER_INDEX_NODE:
            raise BufferFileError(
                f"chained buffer {root_id}: buffer {next_index_id} is not an index node"
            )
