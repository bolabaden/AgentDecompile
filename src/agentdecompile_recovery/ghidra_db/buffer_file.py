"""Reader for Ghidra `.gbf` buffer files.

Mirrors the read path of Ghidra's ``db.buffers.LocalBufferFile`` (Apache-2.0).
All integers are big-endian: Java's ``RandomAccessFile``/``BigEndianDataConverter``
write that way regardless of host byte order.

File layout::

    block 0                     file header, occupies a whole blockSize block
    buffer index i              file offset (i + 1) * blockSize

Each block after the header carries a 5-byte prefix::

    offset 0   1 byte   flags; bit 0 set = empty (free) buffer
    offset 1   4 bytes  buffer id when in use; next free index when empty (-1 ends)
    offset 5   ...      bufferSize bytes of payload

For a plain ``LocalBufferFile`` the buffer *id* equals its *index* -- see
``db.buffers.BufferMgr`` ("use source buffer id as index") -- so a read is a
single seek with no indirection.

Version chaining (``ver.N.gbf``) files are present alongside ``db.N.gbf`` in
the same item database directory and can be opened as standalone buffer files
by ``GhidraProgram`` -- listing and selecting a version is handled by
``project.ProgramEntry.list_versions`` and ``project.ProgramEntry.open``.
Reconstructing an older database by replaying the change chain
(``change.N.gbf``) against a base snapshot remains out of scope: opening a
historical ``ver.N.gbf`` directly gives the complete snapshot for that version.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any

# db.buffers.LocalBufferFile
MAGIC_NUMBER = 0x2F30312C34292C2A
HEADER_FORMAT_VERSION = 1
BUFFER_PREFIX_SIZE = 5
VER1_FIXED_HEADER_LENGTH = 32
EMPTY_BUFFER_FLAG = 0x01

_MAX_REASONABLE_BLOCK_SIZE = 1 << 24


class BufferFileError(Exception):
    """Raised when a file is not a readable Ghidra buffer file."""


@dataclass(frozen=True)
class BufferFileHeader:
    file_id: int
    header_version: int
    block_size: int
    first_free_index: int
    parameters: dict[str, int]

    @property
    def buffer_size(self) -> int:
        """Payload bytes per buffer, i.e. block size minus the 5-byte prefix."""

        return self.block_size - BUFFER_PREFIX_SIZE


class BufferFile:
    """Random-access reader over the buffers of a `.gbf` file.

    Opened lazily and held open; use as a context manager, or call `close()`.
    Reads only -- the file is opened in binary read mode and never written.
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self._handle = self.path.open("rb")
        try:
            self.header = self._read_header()
            self._file_size = self.path.stat().st_size
            if self._file_size % self.header.block_size:
                raise BufferFileError(
                    f"{self.path}: length {self._file_size} is not a multiple of "
                    f"block size {self.header.block_size}; file is truncated or not a buffer file"
                )
            self.buffer_count = self._file_size // self.header.block_size - 1
        except Exception:
            self._handle.close()
            raise

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        if not self._handle.closed:
            self._handle.close()

    def __enter__(self) -> "BufferFile":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # -- header ------------------------------------------------------------

    def _read_header(self) -> BufferFileHeader:
        self._handle.seek(0)
        fixed = self._handle.read(VER1_FIXED_HEADER_LENGTH)
        if len(fixed) < VER1_FIXED_HEADER_LENGTH:
            raise BufferFileError(f"{self.path}: too short to contain a buffer-file header")

        magic, file_id, version, block_size, first_free, parm_count = struct.unpack(
            ">qqiiii", fixed
        )
        if (magic & 0xFFFFFFFFFFFFFFFF) != MAGIC_NUMBER:
            raise BufferFileError(
                f"{self.path}: bad magic 0x{magic & 0xFFFFFFFFFFFFFFFF:016x} "
                f"(expected 0x{MAGIC_NUMBER:016x})"
            )
        if version != HEADER_FORMAT_VERSION:
            raise BufferFileError(
                f"{self.path}: unsupported header format version {version} "
                f"(expected {HEADER_FORMAT_VERSION})"
            )
        if block_size <= BUFFER_PREFIX_SIZE or block_size > _MAX_REASONABLE_BLOCK_SIZE:
            raise BufferFileError(f"{self.path}: implausible block size {block_size}")

        parameters = self._read_parameters(parm_count, block_size)
        return BufferFileHeader(
            file_id=file_id & 0xFFFFFFFFFFFFFFFF,
            header_version=version,
            block_size=block_size,
            first_free_index=first_free,
            parameters=parameters,
        )

    def _read_parameters(self, count: int, block_size: int) -> dict[str, int]:
        """Read the `int nameLen / name / int value` triples following the header.

        The count is attacker-controlled in the sense that a corrupt file can
        claim anything, so it is bounded by the header block itself.
        """

        if count <= 0:
            return {}
        budget = block_size - VER1_FIXED_HEADER_LENGTH
        if count * 8 > budget:
            raise BufferFileError(f"{self.path}: parameter count {count} exceeds header block")

        parameters: dict[str, int] = {}
        for _ in range(count):
            raw_len = self._handle.read(4)
            if len(raw_len) < 4:
                raise BufferFileError(f"{self.path}: truncated parameter name length")
            (name_len,) = struct.unpack(">i", raw_len)
            if name_len < 0 or name_len > budget:
                raise BufferFileError(f"{self.path}: implausible parameter name length {name_len}")
            name = self._handle.read(name_len).decode("utf-8", errors="replace")
            raw_value = self._handle.read(4)
            if len(raw_value) < 4:
                raise BufferFileError(f"{self.path}: truncated parameter value")
            (value,) = struct.unpack(">i", raw_value)
            parameters[name] = value
        return parameters

    # -- buffers -----------------------------------------------------------

    def _block_offset(self, index: int) -> int:
        if index < 0 or index >= self.buffer_count:
            raise IndexError(
                f"buffer index {index} out of range (0..{self.buffer_count - 1}) in {self.path}"
            )
        return (index + 1) * self.header.block_size

    def _read_prefix(self, index: int) -> tuple[int, int]:
        self._handle.seek(self._block_offset(index))
        prefix = self._handle.read(BUFFER_PREFIX_SIZE)
        if len(prefix) < BUFFER_PREFIX_SIZE:
            raise BufferFileError(f"{self.path}: truncated prefix for buffer {index}")
        flags = prefix[0]
        (ident,) = struct.unpack(">i", prefix[1:5])
        return flags, ident

    def is_empty(self, index: int) -> bool:
        """Whether this buffer is on the free list rather than holding data."""

        flags, _ = self._read_prefix(index)
        return bool(flags & EMPTY_BUFFER_FLAG)

    def buffer_id(self, index: int) -> int:
        """Stored id of a live buffer (equals `index` for a LocalBufferFile)."""

        flags, ident = self._read_prefix(index)
        if flags & EMPTY_BUFFER_FLAG:
            raise BufferFileError(f"{self.path}: buffer {index} is empty and has no id")
        return ident

    def read_buffer(self, index: int) -> bytes:
        """Payload of a live buffer.

        Refuses empty buffers: their 4 id bytes are a free-list link, so
        returning the block as data would feed the record decoder garbage that
        happens to parse.
        """

        flags, _ = self._read_prefix(index)
        if flags & EMPTY_BUFFER_FLAG:
            raise BufferFileError(f"{self.path}: buffer {index} is empty (on the free list)")
        data = self._handle.read(self.header.buffer_size)
        if len(data) < self.header.buffer_size:
            raise BufferFileError(f"{self.path}: truncated payload for buffer {index}")
        return data

    def free_indexes(self) -> list[int]:
        """Walk the free-buffer chain from the header.

        Guards against cycles and out-of-range links: a corrupt free list should
        surface as a short list, never as a hang.
        """

        indexes: list[int] = []
        seen: set[int] = set()
        current = self.header.first_free_index
        while current != -1 and 0 <= current < self.buffer_count and current not in seen:
            seen.add(current)
            indexes.append(current)
            flags, nxt = self._read_prefix(current)
            if not (flags & EMPTY_BUFFER_FLAG):
                break
            current = nxt
        return indexes

    def to_json(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "blockSize": self.header.block_size,
            "bufferSize": self.header.buffer_size,
            "bufferCount": self.buffer_count,
            "fileId": f"0x{self.header.file_id:016x}",
            "parameters": dict(self.header.parameters),
        }
