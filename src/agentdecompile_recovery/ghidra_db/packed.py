"""Reader for Ghidra `.gzf` packed database files.

Mirrors ``ghidra.framework.store.local.ItemSerializer`` (Apache-2.0), which is
the writer.

A `.gzf` is a Java `ObjectOutputStream` header followed by a ZIP::

    offset 0   AC ED 00 05          ObjectOutputStream stream header
    offset 4   77 <len:1>           block-data tag (or 7A <len:4> for long blocks)
    offset 6   long   0x2e30212634e92c20   magic; hence `is_packed_file` reads offset 6
               int    1                    format version
               utf    item name            2-byte length, then modified UTF-8
               utf    content type
               int    file type
               long   uncompressed length
    then       PK\\x03\\x04 ...             ZIP local file header for FOLDER_ITEM

`FOLDER_ITEM` inflates to a `.gbf` byte for byte, so extraction hands the result
straight to `BufferFile` -- there is no second database parser here.

Two traps, both confirmed against a real 28 MB `.gzf`:

*The ZIP has no central directory.* `ItemSerializer.outputItem` calls
`closeEntry()` and `flush()` but never `finish()` or `close()` on its
`ZipOutputStream`, so the archive ends after the entry's data descriptor.
`zipfile.ZipFile` looks for an end-of-central-directory record and raises
`BadZipFile`. The local file header is parsed directly instead.

*Sizes live after the data, not before.* The entry is written streaming, so the
local header carries zeros and general-purpose bit 3, with the real CRC and
sizes in a trailing data descriptor. The header's own `length` field -- read
before the ZIP even starts -- is the authoritative uncompressed size, and is
what extraction checks against.
"""

from __future__ import annotations

import struct
import zlib

from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, BinaryIO, Iterator

from .buffer_file import BufferFile

# java.io.ObjectStreamConstants
STREAM_MAGIC = 0xACED
STREAM_VERSION = 5
TC_BLOCKDATA = 0x77
TC_BLOCKDATALONG = 0x7A

# ItemSerializer
MAGIC_NUMBER = 0x2E30212634E92C20
MAGIC_NUMBER_POS = 6
FORMAT_VERSION = 1
ZIP_ENTRY_NAME = "FOLDER_ITEM"

# ZIP local file header (APPNOTE 4.3.7)
_LOCAL_FILE_SIGNATURE = b"PK\x03\x04"
_LOCAL_HEADER_SIZE = 30
_FLAG_DATA_DESCRIPTOR = 0x0008
_METHOD_DEFLATED = 8

_INFLATE_CHUNK = 1 << 20


class PackedFileError(Exception):
    """Raised when a file is not a readable packed Ghidra database."""


@dataclass(frozen=True)
class PackedItemHeader:
    """The metadata block that precedes the ZIP payload."""

    item_name: str
    content_type: str
    file_type: int
    content_length: int
    zip_offset: int

    @property
    def is_database(self) -> bool:
        """File type 0 is `FolderItem.DATABASE_FILE_TYPE`."""

        return self.file_type == 0

    def to_json(self) -> dict[str, Any]:
        return {
            "itemName": self.item_name,
            "contentType": self.content_type,
            "fileType": self.file_type,
            "contentLength": self.content_length,
        }


def is_packed_file(path: Path | str) -> bool:
    """Whether a file carries the packed-database magic at offset 6.

    Matches `ItemSerializer.isPackedFile`, which skips the ObjectOutputStream
    header and block tag and looks only at the magic.
    """

    try:
        with Path(path).open("rb") as handle:
            handle.seek(MAGIC_NUMBER_POS)
            raw = handle.read(8)
    except OSError:
        return False
    if len(raw) < 8:
        return False
    return struct.unpack(">Q", raw)[0] == MAGIC_NUMBER


def _read_exact(handle: BinaryIO, count: int, what: str) -> bytes:
    data = handle.read(count)
    if len(data) < count:
        raise PackedFileError(f"truncated {what}: wanted {count} bytes, got {len(data)}")
    return data


def _read_java_utf(handle: BinaryIO, what: str) -> str:
    """Read a `DataOutput.writeUTF` string: 2-byte length, then the bytes.

    Modified UTF-8 differs from UTF-8 only for NUL and supplementary-plane
    characters, neither of which appears in an item name or content type, so a
    plain decode is correct here and errors are replaced rather than raised.
    """

    (length,) = struct.unpack(">H", _read_exact(handle, 2, f"{what} length"))
    return _read_exact(handle, length, what).decode("utf-8", errors="replace")


def read_packed_header(path: Path | str) -> PackedItemHeader:
    """Parse the metadata block of a `.gzf` and locate the ZIP that follows."""

    source = Path(path)
    with source.open("rb") as handle:
        magic, version = struct.unpack(">HH", _read_exact(handle, 4, "stream header"))
        if magic != STREAM_MAGIC or version != STREAM_VERSION:
            raise PackedFileError(
                f"{source}: not a Java serialization stream "
                f"(header 0x{magic:04x}{version:04x}, expected 0x{STREAM_MAGIC:04x}{STREAM_VERSION:04x})"
            )

        (tag,) = struct.unpack(">B", _read_exact(handle, 1, "block tag"))
        if tag == TC_BLOCKDATA:
            (block_length,) = struct.unpack(">B", _read_exact(handle, 1, "block length"))
        elif tag == TC_BLOCKDATALONG:
            (block_length,) = struct.unpack(">i", _read_exact(handle, 4, "block length"))
        else:
            raise PackedFileError(f"{source}: expected a block-data tag, found 0x{tag:02x}")
        if block_length <= 0:
            raise PackedFileError(f"{source}: implausible block length {block_length}")
        block_start = handle.tell()

        (item_magic,) = struct.unpack(">Q", _read_exact(handle, 8, "magic"))
        if item_magic != MAGIC_NUMBER:
            raise PackedFileError(
                f"{source}: bad packed-file magic 0x{item_magic:016x} (expected 0x{MAGIC_NUMBER:016x})"
            )

        (format_version,) = struct.unpack(">i", _read_exact(handle, 4, "format version"))
        if format_version != FORMAT_VERSION:
            raise PackedFileError(
                f"{source}: unsupported packed format version {format_version} (expected {FORMAT_VERSION})"
            )

        item_name = _read_java_utf(handle, "item name")
        content_type = _read_java_utf(handle, "content type")
        (file_type,) = struct.unpack(">i", _read_exact(handle, 4, "file type"))
        (content_length,) = struct.unpack(">q", _read_exact(handle, 8, "content length"))

        consumed = handle.tell() - block_start
        if consumed != block_length:
            raise PackedFileError(
                f"{source}: metadata block declares {block_length} bytes but the "
                f"fields consume {consumed}; layout does not match ItemSerializer"
            )

    return PackedItemHeader(
        item_name=item_name,
        content_type=content_type,
        file_type=file_type,
        content_length=content_length,
        zip_offset=block_start + block_length,
    )


def extract_database(source: Path | str, destination: Path | str) -> Path:
    """Inflate the `FOLDER_ITEM` entry of a `.gzf` to `destination`.

    The result is a `.gbf` and can be opened directly with `BufferFile`. The
    inflate is streamed, so a 100 MB database costs a 1 MB buffer, not 100 MB
    of RAM.
    """

    packed = Path(source)
    target = Path(destination)
    header = read_packed_header(packed)

    with packed.open("rb") as handle:
        handle.seek(header.zip_offset)
        local = _read_exact(handle, _LOCAL_HEADER_SIZE, "zip local file header")
        if local[:4] != _LOCAL_FILE_SIGNATURE:
            raise PackedFileError(f"{packed}: no ZIP local file header at offset {header.zip_offset}")

        flags, method = struct.unpack_from("<HH", local, 6)
        name_length, extra_length = struct.unpack_from("<HH", local, 26)
        entry_name = _read_exact(handle, name_length, "zip entry name").decode("utf-8", errors="replace")
        if extra_length:
            _read_exact(handle, extra_length, "zip extra field")

        if entry_name != ZIP_ENTRY_NAME:
            raise PackedFileError(
                f"{packed}: first ZIP entry is {entry_name!r}, expected {ZIP_ENTRY_NAME!r}"
            )
        if method != _METHOD_DEFLATED:
            # ItemSerializer always sets ZipEntry.DEFLATED. Anything else means
            # the file was not written by Ghidra, so guessing is worse than
            # saying so.
            raise PackedFileError(
                f"{packed}: ZIP compression method {method}, expected {_METHOD_DEFLATED} (deflate)"
            )

        written = _inflate_entry(handle, target)

    # The trailing data descriptor is not consulted: it is only present when
    # flag bit 3 is set, and the header length is authoritative either way.
    if written != header.content_length:
        target.unlink(missing_ok=True)
        raise PackedFileError(
            f"{packed}: extracted {written} bytes but the header declares "
            f"{header.content_length} (data descriptor present: {bool(flags & _FLAG_DATA_DESCRIPTOR)})"
        )
    return target


def _inflate_entry(handle: BinaryIO, target: Path) -> int:
    """Stream one deflated ZIP entry's payload to `target`, returning bytes written."""

    written = 0
    # Raw DEFLATE: the ZIP wrapper carries no zlib header, hence -MAX_WBITS.
    decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
    with target.open("wb") as output:
        while not decompressor.eof:
            chunk = handle.read(_INFLATE_CHUNK)
            if not chunk:
                break
            data = decompressor.decompress(chunk)
            if data:
                output.write(data)
                written += len(data)
        tail = decompressor.flush()
        if tail:
            output.write(tail)
            written += len(tail)
    return written


@contextmanager
def open_packed_database(source: Path | str, workdir: Path | str | None = None) -> Iterator[BufferFile]:
    """Open the database inside a `.gzf` as a `BufferFile`.

    `BufferFile` seeks within a real file, so the entry is extracted first. When
    `workdir` is given the extracted `.gbf` is left there for reuse; otherwise a
    temporary directory holds it for the life of the context.
    """

    packed = Path(source)
    if workdir is not None:
        target = Path(workdir) / f"{packed.stem}.gbf"
        if not target.exists():
            extract_database(packed, target)
        with BufferFile(target) as buffer_file:
            yield buffer_file
        return

    with TemporaryDirectory(prefix="ghidra-gzf-") as temporary:
        target = extract_database(packed, Path(temporary) / f"{packed.stem}.gbf")
        with BufferFile(target) as buffer_file:
            yield buffer_file
