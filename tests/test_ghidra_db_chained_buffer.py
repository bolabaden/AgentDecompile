"""Unit tests for chained-buffer reads and XOR de-obfuscation (U1).

Reference: Ghidra's db.ChainedBuffer. Records too large for one buffer are
stored as a single data node, or as an index node pointing at a chain of data
buffers. The high bit of the length word marks obfuscated payload.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from agentdecompile_recovery.ghidra_db.buffer_file import (
    BUFFER_PREFIX_SIZE,
    MAGIC_NUMBER,
    BufferFile,
    BufferFileError,
)
from agentdecompile_recovery.ghidra_db.chained_buffer import (
    CHAINED_BUFFER_DATA_NODE,
    CHAINED_BUFFER_INDEX_NODE,
    XOR_MASK_BYTES,
    deobfuscate,
    read_chained_buffer,
)

pytestmark = pytest.mark.unit

BLOCK = 64

# db.ChainedBuffer node offsets, restated so the fixtures do not borrow the
# reader's own constants to describe what the reader is supposed to read.
_INDEX_BASE_OFFSET = 9
_ID_SIZE = 4


def _buffer_size(block: int) -> int:
    return block - BUFFER_PREFIX_SIZE


def _data_space(block: int) -> int:
    """`allocateIndex`: an indexed data node holds `length - 1` logical bytes."""

    return _buffer_size(block) - 1


def _indexes_per_buffer(block: int) -> int:
    """`allocateIndex`: `(buffer.length() - INDEX_BASE_OFFSET) / ID_SIZE`."""

    return (_buffer_size(block) - _INDEX_BASE_OFFSET) // _ID_SIZE


def _file(tmp_path: Path, blocks: list[bytes], *, block: int = BLOCK) -> BufferFile:
    header = bytearray(block)
    struct.pack_into(">q", header, 0, MAGIC_NUMBER)
    struct.pack_into(">q", header, 8, 1)
    struct.pack_into(">i", header, 16, 1)
    struct.pack_into(">i", header, 20, block)
    struct.pack_into(">i", header, 24, -1)
    struct.pack_into(">i", header, 28, 0)

    out = bytearray(header)
    for index, payload in enumerate(blocks):
        buffer = bytearray(block)
        buffer[0] = 0
        struct.pack_into(">i", buffer, 1, index)
        buffer[BUFFER_PREFIX_SIZE : BUFFER_PREFIX_SIZE + len(payload)] = payload
        out.extend(buffer)
    path = tmp_path / "db.1.gbf"
    path.write_bytes(bytes(out))
    return BufferFile(path)


def _data_node(payload: bytes, *, obfuscated: bool = False) -> bytes:
    length = len(payload) | (0x80000000 if obfuscated else 0)
    return bytes([CHAINED_BUFFER_DATA_NODE]) + struct.pack(">I", length) + payload


def _indexed_data_node(payload: bytes) -> bytes:
    return bytes([CHAINED_BUFFER_DATA_NODE]) + payload


def _index_node(
    total_length: int,
    next_index_id: int,
    data_ids: list[int],
    *,
    obfuscated: bool = False,
    block: int = BLOCK,
) -> bytes:
    """Build an index node the way `ChainedBuffer.createIndex` writes one.

    The whole index area is pre-filled with -1 (`Arrays.fill(emptyIndexData,
    (byte) 0xff)`), so an unused slot is a sparse data node and *not* a
    terminator. Fixtures that stopped at the first -1 could not express a
    record with a hole in it.

    Pass `total_length=-1` for a continuation node: `appendIndexBuffer` writes
    -1 there because only the first index node carries the record length.
    """

    length_word = (total_length | (0x80000000 if obfuscated else 0)) & 0xFFFFFFFF
    head = (
        bytes([CHAINED_BUFFER_INDEX_NODE])
        + struct.pack(">I", length_word)
        + struct.pack(">i", next_index_id)
    )
    index_area = bytearray(b"\xff" * (_indexes_per_buffer(block) * _ID_SIZE))
    for slot, data_id in enumerate(data_ids):
        struct.pack_into(">i", index_area, slot * _ID_SIZE, data_id)
    return head + bytes(index_area)


def _stored_chunks(plain: bytes, block: int = BLOCK) -> list[bytes]:
    """Slice a record into data-node payloads, masked the way Ghidra stores it.

    `ChainedBuffer.getBytes` masks by the byte's offset *within its own buffer*,
    so each slice is masked from mask index 0. `deobfuscate` is an involution,
    so the same call both stores and loads.
    """

    space = _data_space(block)
    return [deobfuscate(plain[start : start + space]) for start in range(0, len(plain), space)]


def test_xor_table_is_128_bytes() -> None:
    assert len(XOR_MASK_BYTES) == 128


def test_deobfuscate_is_an_involution() -> None:
    payload = bytes(range(200))

    assert deobfuscate(deobfuscate(payload)) == payload


def test_deobfuscate_respects_start_offset() -> None:
    """`xorMaskByte` indexes the mask by the byte's offset within its buffer."""

    payload = b"\x00" * 4

    assert deobfuscate(payload, 0) == XOR_MASK_BYTES[:4]
    assert deobfuscate(payload, 2) == XOR_MASK_BYTES[2:6]


def test_reads_single_data_node(tmp_path: Path) -> None:
    with _file(tmp_path, [_data_node(b"payload")]) as bf:
        assert read_chained_buffer(bf, 0) == b"payload"


def test_reads_obfuscated_data_node(tmp_path: Path) -> None:
    plain = b"CatBoolean"
    with _file(tmp_path, [_data_node(deobfuscate(plain), obfuscated=True)]) as bf:
        assert read_chained_buffer(bf, 0) == plain


# An indexed data node holds up to (bufferSize - 1) bytes: one node-type byte,
# then payload. With BLOCK=64 the buffer is 59 bytes, so capacity is 58.
_CHUNK_CAPACITY = _data_space(BLOCK)


def test_reads_indexed_chain_in_order(tmp_path: Path) -> None:
    """A chain spills to the next buffer only once the current one is full."""

    first = b"a" * _CHUNK_CAPACITY
    second = b"bc"
    blocks = [
        _index_node(len(first) + len(second), -1, [1, 2]),
        _indexed_data_node(first),
        _indexed_data_node(second),
    ]
    with _file(tmp_path, blocks) as bf:
        assert read_chained_buffer(bf, 0) == first + second


def test_indexed_chain_truncates_to_declared_length(tmp_path: Path) -> None:
    """Data buffers are full blocks; only `total_length` bytes are real."""

    first = b"a" * _CHUNK_CAPACITY
    blocks = [
        _index_node(_CHUNK_CAPACITY + 1, -1, [1, 2]),
        _indexed_data_node(first),
        _indexed_data_node(b"bc"),
    ]
    with _file(tmp_path, blocks) as bf:
        assert read_chained_buffer(bf, 0) == first + b"b"


def test_rejects_non_chained_node(tmp_path: Path) -> None:
    with _file(tmp_path, [b"\x01rubbish"]) as bf:
        with pytest.raises(BufferFileError, match="not a chained buffer"):
            read_chained_buffer(bf, 0)


# One index node holds `(bufferSize - 9) / 4` slots; with BLOCK=64 that is 12,
# so a record needing more than 12 * 58 bytes must chain to a second index node.
_SLOTS_PER_INDEX = _indexes_per_buffer(BLOCK)
_TWO_INDEX_NODES = _SLOTS_PER_INDEX * _CHUNK_CAPACITY + 1


def test_rejects_short_chain(tmp_path: Path) -> None:
    """Declaring more bytes than the chain supplies must fail, not silently short-read.

    `createIndex` allocates every index node the declared length needs, so the
    only way a real chain can come up short is a missing index node -- which is
    where `buildIndex` throws. An unfilled *slot* is not a shortfall: it is a
    sparse data node, so the old "stop at the first -1" reading of a short chain
    described a record with a hole in it, not a corrupt one.
    """

    blocks = [_index_node(_TWO_INDEX_NODES, -1, list(range(1, _SLOTS_PER_INDEX + 1)))]
    blocks += [_indexed_data_node(b"a" * _CHUNK_CAPACITY)] * _SLOTS_PER_INDEX
    with _file(tmp_path, blocks) as bf:
        with pytest.raises(BufferFileError, match=r"index chain ends after 12 of 13"):
            read_chained_buffer(bf, 0)


def test_index_cycle_does_not_hang(tmp_path: Path) -> None:
    """A `nextIndexId` pointing back into the chain is reported, not followed."""

    blocks = [_index_node(_TWO_INDEX_NODES, 0, list(range(1, _SLOTS_PER_INDEX + 1)))]
    blocks += [_indexed_data_node(b"a" * _CHUNK_CAPACITY)] * _SLOTS_PER_INDEX
    with _file(tmp_path, blocks) as bf:
        with pytest.raises(BufferFileError, match="revisits buffer 0"):
            read_chained_buffer(bf, 0)


def test_reads_a_chain_that_spans_two_index_nodes(tmp_path: Path) -> None:
    """The 13th data buffer is listed in the second index node, not the first."""

    plain = bytes((index * 5 + 3) % 256 for index in range(_TWO_INDEX_NODES))
    chunks = [plain[start : start + _CHUNK_CAPACITY] for start in range(0, len(plain), _CHUNK_CAPACITY)]
    first_ids = list(range(2, 2 + _SLOTS_PER_INDEX))
    blocks = [
        _index_node(len(plain), 1, first_ids),
        _index_node(-1, -1, [2 + _SLOTS_PER_INDEX]),
    ]
    blocks += [_indexed_data_node(chunk) for chunk in chunks]
    with _file(tmp_path, blocks) as bf:
        assert read_chained_buffer(bf, 0) == plain


# -- defect 1: the XOR mask restarts in every data buffer ---------------------


@pytest.mark.parametrize("block", [BLOCK, 200])
def test_obfuscated_chain_restarts_the_mask_in_every_buffer(tmp_path: Path, block: int) -> None:
    """`ChainedBuffer.get` resets `bufferDataOffset` to 0 at each buffer boundary.

    Masking by the offset within the whole record instead decodes the first data
    buffer correctly and turns every later one into noise. That failure is
    silent -- no exception, just wrong bytes -- so this asserts on content.

    `block=200` makes `dataSpace` 194, larger than the 128-byte mask, so the
    mask also wraps *inside* a buffer; a per-record index would land on mask
    byte 194 % 128 = 66 at the start of buffer 1 rather than on byte 0.
    """

    space = _data_space(block)
    plain = bytes((index * 7 + 11) % 256 for index in range(3 * space - 5))
    stored = _stored_chunks(plain, block)
    blocks = [_index_node(len(plain), -1, [1, 2, 3], obfuscated=True, block=block)]
    blocks += [_indexed_data_node(chunk) for chunk in stored]

    with _file(tmp_path, blocks, block=block) as bf:
        assert read_chained_buffer(bf, 0) == plain

    # Why the defect stayed hidden: a record-wide mask index agrees for the
    # whole of buffer 0 and disagrees for everything after it.
    record_wide = deobfuscate(b"".join(stored))
    assert record_wide[:space] == plain[:space]
    assert record_wide[space:] != plain[space:]


# -- defect 2: a data-buffer id of -1 is a hole, not the end ------------------


def test_sparse_data_buffer_reads_as_zeros(tmp_path: Path) -> None:
    """`getBytes` fills an unallocated data node with zeros and keeps going."""

    head = b"H" * _CHUNK_CAPACITY
    tail = b"T" * _CHUNK_CAPACITY
    blocks = [
        _index_node(3 * _CHUNK_CAPACITY, -1, [1, -1, 2]),
        _indexed_data_node(head),
        _indexed_data_node(tail),
    ]
    with _file(tmp_path, blocks) as bf:
        assert read_chained_buffer(bf, 0) == head + bytes(_CHUNK_CAPACITY) + tail


def test_sparse_data_buffer_is_not_xor_masked(tmp_path: Path) -> None:
    """`getBytes` zero-fills an unallocated node without reaching the mask."""

    head = b"H" * _CHUNK_CAPACITY
    blocks = [
        _index_node(2 * _CHUNK_CAPACITY, -1, [1, -1], obfuscated=True),
        _indexed_data_node(deobfuscate(head)),
    ]
    with _file(tmp_path, blocks) as bf:
        assert read_chained_buffer(bf, 0) == head + bytes(_CHUNK_CAPACITY)


def test_leading_sparse_data_buffer_does_not_empty_the_record(tmp_path: Path) -> None:
    """A hole in slot 0 leaves the rest of the chain readable."""

    tail = b"T" * _CHUNK_CAPACITY
    blocks = [
        _index_node(2 * _CHUNK_CAPACITY, -1, [-1, 1]),
        _indexed_data_node(tail),
    ]
    with _file(tmp_path, blocks) as bf:
        assert read_chained_buffer(bf, 0) == bytes(_CHUNK_CAPACITY) + tail
