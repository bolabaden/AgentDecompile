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


def _file(tmp_path: Path, blocks: list[bytes]) -> BufferFile:
    header = bytearray(BLOCK)
    struct.pack_into(">q", header, 0, MAGIC_NUMBER)
    struct.pack_into(">q", header, 8, 1)
    struct.pack_into(">i", header, 16, 1)
    struct.pack_into(">i", header, 20, BLOCK)
    struct.pack_into(">i", header, 24, -1)
    struct.pack_into(">i", header, 28, 0)

    out = bytearray(header)
    for index, payload in enumerate(blocks):
        block = bytearray(BLOCK)
        block[0] = 0
        struct.pack_into(">i", block, 1, index)
        block[BUFFER_PREFIX_SIZE : BUFFER_PREFIX_SIZE + len(payload)] = payload
        out.extend(block)
    path = tmp_path / "db.1.gbf"
    path.write_bytes(bytes(out))
    return BufferFile(path)


def _data_node(payload: bytes, *, obfuscated: bool = False) -> bytes:
    length = len(payload) | (0x80000000 if obfuscated else 0)
    return bytes([CHAINED_BUFFER_DATA_NODE]) + struct.pack(">I", length) + payload


def _indexed_data_node(payload: bytes) -> bytes:
    return bytes([CHAINED_BUFFER_DATA_NODE]) + payload


def _index_node(total_length: int, next_index_id: int, data_ids: list[int], *, obfuscated: bool = False) -> bytes:
    head = (
        bytes([CHAINED_BUFFER_INDEX_NODE])
        + struct.pack(">I", total_length | (0x80000000 if obfuscated else 0))
        + struct.pack(">i", next_index_id)
    )
    body = b"".join(struct.pack(">i", i) for i in data_ids)
    return head + body + struct.pack(">i", -1)


def test_xor_table_is_128_bytes() -> None:
    assert len(XOR_MASK_BYTES) == 128


def test_deobfuscate_is_an_involution() -> None:
    payload = bytes(range(200))

    assert deobfuscate(deobfuscate(payload)) == payload


def test_deobfuscate_respects_start_offset() -> None:
    """Mask index follows the byte's offset in the record, not in its buffer."""

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
_CHUNK_CAPACITY = BLOCK - BUFFER_PREFIX_SIZE - 1


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


def test_rejects_short_chain(tmp_path: Path) -> None:
    """Declaring more bytes than the chain supplies must fail, not silently short-read."""

    blocks = [_index_node(500, -1, [1]), _indexed_data_node(b"abc")]
    with _file(tmp_path, blocks) as bf:
        with pytest.raises(BufferFileError, match="recovered"):
            read_chained_buffer(bf, 0)


def test_index_cycle_does_not_hang(tmp_path: Path) -> None:
    blocks = [
        _index_node(3, 2, [1]),
        _indexed_data_node(b"abc"),
        _index_node(3, 0, []),  # points back at the root
    ]
    with _file(tmp_path, blocks) as bf:
        assert read_chained_buffer(bf, 0) == b"abc"
