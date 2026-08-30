from __future__ import annotations

import struct
from pathlib import Path

import pytest

from agentdecompile_recovery.frontdoor import target_compiler_hint
from agentdecompile_recovery.inventory import BinaryView, build_binary_inventory, decode_pe_rich_header
from agentdecompile_recovery.targets import identify_binary

pytestmark = pytest.mark.unit


def _build_minimal_pe(
    tmp_path: Path,
    *,
    rich_entries: list[tuple[int, int, int]] | None = None,
    destroy_rich: str | None = None,
    truncate_rich: bool = False,
) -> Path:
    pe_offset = 0x100
    section_alignment = 0x1000
    file_alignment = 0x200
    raw_pointer = 0x200
    raw_size = 0x200
    image_size = 0x2000
    size_of_headers = 0x200
    optional_size = 0xE0
    data = bytearray(raw_pointer + raw_size)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, pe_offset)
    rich_start = 0x80
    xor_key = 0xA5A5A5A5
    if rich_entries:
        cursor = rich_start
        for value in (0x536E6144, 0, 0, 0):
            struct.pack_into("<I", data, cursor, value ^ xor_key)
            cursor += 4
        for prodid, build, count in rich_entries:
            struct.pack_into("<I", data, cursor, ((prodid << 16) | build) ^ xor_key)
            struct.pack_into("<I", data, cursor + 4, count ^ xor_key)
            cursor += 8
        if not truncate_rich:
            rich_offset = cursor
            data[rich_offset : rich_offset + 4] = b"Rich"
            struct.pack_into("<I", data, rich_offset + 4, xor_key)
    elif destroy_rich == "zeroed":
        data[0x40:pe_offset] = b"\x00" * (pe_offset - 0x40)
    elif destroy_rich == "entropy":
        pattern = bytes((index * 37) & 0xFF for index in range(pe_offset - 0x40))
        data[0x40:pe_offset] = pattern
    else:
        stub = b"This program cannot be run in DOS mode.\r\r\n$"
        data[0x40 : 0x40 + len(stub)] = stub
    if truncate_rich:
        rich_offset = pe_offset - 4
        data[rich_offset : rich_offset + 4] = b"Rich"
    data[pe_offset : pe_offset + 4] = b"PE\0\0"
    coff = pe_offset + 4
    struct.pack_into("<H", data, coff, 0x014C)
    struct.pack_into("<H", data, coff + 2, 1)
    struct.pack_into("<I", data, coff + 4, 0)
    struct.pack_into("<H", data, coff + 16, optional_size)
    struct.pack_into("<H", data, coff + 18, 0x010F)
    optional = coff + 20
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<I", data, optional + 28, 0x400000)
    struct.pack_into("<I", data, optional + 32, section_alignment)
    struct.pack_into("<I", data, optional + 36, file_alignment)
    struct.pack_into("<I", data, optional + 56, image_size)
    struct.pack_into("<I", data, optional + 60, size_of_headers)
    struct.pack_into("<H", data, optional + 68, 3)
    struct.pack_into("<H", data, optional + 70, 0)
    struct.pack_into("<I", data, optional + 92, 16)
    section = optional + optional_size
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<I", data, section + 8, raw_size)
    struct.pack_into("<I", data, section + 12, 0x1000)
    struct.pack_into("<I", data, section + 16, raw_size)
    struct.pack_into("<I", data, section + 20, raw_pointer)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    path = tmp_path / "fixture.exe"
    path.write_bytes(bytes(data))
    return path


def test_decode_pe_rich_header_returns_entries_and_inventory_hint(tmp_path: Path) -> None:
    binary = _build_minimal_pe(tmp_path, rich_entries=[(0x0102, 9466, 4), (0x0103, 9466, 9)])
    view = BinaryView(binary, binary.read_bytes())
    rich = decode_pe_rich_header(view)
    assert rich["status"] == "present"
    assert rich["entries"] == [(0x0102, 9466, 4), (0x0103, 9466, 9)]
    assert rich["bestCompiler"]["family"] == "msvc"
    assert rich["bestCompiler"]["version"] == "7.0"
    assert rich["bestCompiler"]["profile"] == "vc71"
    inventory = build_binary_inventory(identify_binary(binary))
    assert inventory["richHeader"]["entries"] == [(0x0102, 9466, 4), (0x0103, 9466, 9)]
    assert inventory["richHeader"]["bestCompiler"]["compilerVersion"] == "13.00.9466"
    assert inventory["summary"]["richHeaderStatus"] == "present"
    assert target_compiler_hint(binary)["profile"] == "vc71"


def test_decode_pe_rich_header_reports_absent_without_raising(tmp_path: Path) -> None:
    binary = _build_minimal_pe(tmp_path)
    rich = decode_pe_rich_header(BinaryView(binary, binary.read_bytes()))
    assert rich["status"] == "absent"
    assert rich["entries"] == []
    inventory = build_binary_inventory(identify_binary(binary))
    assert inventory["richHeader"]["status"] == "absent"


def test_decode_pe_rich_header_reports_destroyed_zeroed_region(tmp_path: Path) -> None:
    binary = _build_minimal_pe(tmp_path, destroy_rich="zeroed")
    rich = decode_pe_rich_header(BinaryView(binary, binary.read_bytes()))
    assert rich["status"] == "destroyed"
    assert rich["entries"] == []


def test_decode_pe_rich_header_reports_truncated_marker(tmp_path: Path) -> None:
    binary = _build_minimal_pe(tmp_path, rich_entries=[(0x0102, 3052, 3)], truncate_rich=True)
    rich = decode_pe_rich_header(BinaryView(binary, binary.read_bytes()))
    assert rich["status"] == "truncated"
    assert rich["entries"] == []
