"""Unit tests for the pure-Python Ghidra buffer-file reader (U1).

Format reference: Ghidra's db/buffers/LocalBufferFile.java. Everything is
big-endian (Java RandomAccessFile.writeInt / BigEndianDataConverter).

Layout, verified against a real 17.7 MB db.1.gbf:
  block 0            = file header (occupies a full blockSize block)
  buffer index i     = file offset (i+1) * blockSize
  buffer prefix      = 1 byte flags + 4 byte id/next-free, then bufferSize bytes
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from agentdecompile_recovery.ghidra_db.buffer_file import (
    BUFFER_PREFIX_SIZE,
    EMPTY_BUFFER_FLAG,
    MAGIC_NUMBER,
    BufferFile,
    BufferFileError,
)

pytestmark = pytest.mark.unit


def _build(block_size: int = 64, buffers: list[bytes | None] | None = None, first_free: int = -1, parms: dict[str, int] | None = None) -> bytes:
    """Synthesize a minimal but structurally valid buffer file."""

    parms = parms or {}
    header = bytearray(block_size)
    struct.pack_into(">q", header, 0, MAGIC_NUMBER)
    struct.pack_into(">q", header, 8, 0x1122334455667788)
    struct.pack_into(">i", header, 16, 1)
    struct.pack_into(">i", header, 20, block_size)
    struct.pack_into(">i", header, 24, first_free)
    struct.pack_into(">i", header, 28, len(parms))
    offset = 32
    for name, value in parms.items():
        encoded = name.encode("utf-8")
        struct.pack_into(">i", header, offset, len(encoded))
        offset += 4
        header[offset : offset + len(encoded)] = encoded
        offset += len(encoded)
        struct.pack_into(">i", header, offset, value)
        offset += 4

    out = bytearray(header)
    for index, payload in enumerate(buffers or []):
        block = bytearray(block_size)
        if payload is None:
            block[0] = EMPTY_BUFFER_FLAG
            struct.pack_into(">i", block, 1, -1)
        else:
            block[0] = 0
            struct.pack_into(">i", block, 1, index)
            block[BUFFER_PREFIX_SIZE : BUFFER_PREFIX_SIZE + len(payload)] = payload
        out.extend(block)
    return bytes(out)


def _write(tmp_path: Path, data: bytes) -> Path:
    path = tmp_path / "db.1.gbf"
    path.write_bytes(data)
    return path


def test_reads_header_fields(tmp_path: Path) -> None:
    path = _write(tmp_path, _build(block_size=128, buffers=[b"a"]))

    with BufferFile(path) as bf:
        assert bf.header.block_size == 128
        assert bf.header.buffer_size == 128 - BUFFER_PREFIX_SIZE
        assert bf.header.header_version == 1
        assert bf.buffer_count == 1


def test_reads_buffer_payload(tmp_path: Path) -> None:
    path = _write(tmp_path, _build(buffers=[b"hello", b"world"]))

    with BufferFile(path) as bf:
        assert bf.read_buffer(0).startswith(b"hello")
        assert bf.read_buffer(1).startswith(b"world")
        assert len(bf.read_buffer(0)) == bf.header.buffer_size


def test_empty_buffer_is_reported_and_refused(tmp_path: Path) -> None:
    """An empty buffer holds a free-list link, not data -- returning its bytes
    as a record would silently corrupt every downstream decode."""

    path = _write(tmp_path, _build(buffers=[b"live", None]))

    with BufferFile(path) as bf:
        assert bf.is_empty(1) is True
        assert bf.is_empty(0) is False
        with pytest.raises(BufferFileError):
            bf.read_buffer(1)


def test_user_parameters_are_parsed(tmp_path: Path) -> None:
    path = _write(tmp_path, _build(block_size=128, buffers=[b"x"], parms={"~VF.a": 7, "~VF.b": 9}))

    with BufferFile(path) as bf:
        assert bf.header.parameters == {"~VF.a": 7, "~VF.b": 9}


def test_rejects_bad_magic(tmp_path: Path) -> None:
    data = bytearray(_build(buffers=[b"x"]))
    struct.pack_into(">q", data, 0, 0x1234)
    path = _write(tmp_path, bytes(data))

    with pytest.raises(BufferFileError, match="magic"):
        BufferFile(path).close()


def test_rejects_unknown_header_version(tmp_path: Path) -> None:
    data = bytearray(_build(buffers=[b"x"]))
    struct.pack_into(">i", data, 16, 99)
    path = _write(tmp_path, bytes(data))

    with pytest.raises(BufferFileError, match="version"):
        BufferFile(path).close()


def test_rejects_non_multiple_file_length(tmp_path: Path) -> None:
    """A truncated file must fail loudly rather than yield short final buffers."""

    path = _write(tmp_path, _build(buffers=[b"x"]) + b"\x00\x00\x00")

    with pytest.raises(BufferFileError, match="multiple"):
        BufferFile(path).close()


def test_out_of_range_index_raises(tmp_path: Path) -> None:
    path = _write(tmp_path, _build(buffers=[b"x"]))

    with BufferFile(path) as bf:
        with pytest.raises(IndexError):
            bf.read_buffer(5)
        with pytest.raises(IndexError):
            bf.read_buffer(-1)


def test_free_index_list_walks_the_chain(tmp_path: Path) -> None:
    data = bytearray(_build(block_size=64, buffers=[b"a", None, None], first_free=1))
    # buffer 1 -> next free 2, buffer 2 -> end of chain
    struct.pack_into(">i", data, 64 * 2 + 1, 2)
    struct.pack_into(">i", data, 64 * 3 + 1, -1)
    path = _write(tmp_path, bytes(data))

    with BufferFile(path) as bf:
        assert bf.free_indexes() == [1, 2]


def test_free_index_list_is_cycle_safe(tmp_path: Path) -> None:
    """A corrupt free list must not hang the reader."""

    data = bytearray(_build(block_size=64, buffers=[b"a", None, None], first_free=1))
    struct.pack_into(">i", data, 64 * 2 + 1, 2)
    struct.pack_into(">i", data, 64 * 3 + 1, 1)  # points back -> cycle
    path = _write(tmp_path, bytes(data))

    with BufferFile(path) as bf:
        assert bf.free_indexes() == [1, 2]


# -- real-fixture checks ----------------------------------------------------

FIXTURE = Path(
    "/home/brunner56/Downloads/biodecompwarehouse/projects/agentdecompile.rep"
    "/versioned/00/~00000000.db/db.1.gbf"
)


@pytest.mark.skipif(not FIXTURE.is_file(), reason="real Ghidra buffer-file fixture unavailable")
def test_real_ghidra_buffer_file_header() -> None:
    """Values confirmed by direct inspection of this exact file."""

    with BufferFile(FIXTURE) as bf:
        assert bf.header.block_size == 16384
        assert bf.header.buffer_size == 16379
        assert bf.header.header_version == 1
        assert bf.buffer_count == 1081
        assert bf.header.first_free_index == -1
        assert bf.header.parameters == {}


@pytest.mark.skipif(not FIXTURE.is_file(), reason="real Ghidra buffer-file fixture unavailable")
def test_real_buffer_zero_is_dbparms_node() -> None:
    """Buffer 0 carries DBParms as a chained-buffer data node (type 9)."""

    with BufferFile(FIXTURE) as bf:
        assert bf.read_buffer(0)[0] == 9
