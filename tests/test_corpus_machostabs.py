from __future__ import annotations

import struct

import pytest

from agentdecompile_recovery.corpus.machostabs import FAT_CIGAM, MH_MAGIC, MachO, parse_stabs, slices

pytestmark = pytest.mark.unit


class _FakeMachO:
    def __init__(self, symbols):
        self._symbols = symbols

    def symbols(self):
        yield from self._symbols


def test_big_endian_header_uses_big_endian_fields() -> None:
    data = struct.pack(">IiiIIII", MH_MAGIC, 18, 0, 2, 0, 0, 0)
    macho = MachO(data)
    assert macho.endian == ">"
    assert macho.arch == "ppc"
    assert macho.filetype == 2


def test_swapped_fat_header_uses_little_endian_arch_entries() -> None:
    data = struct.pack(">I", FAT_CIGAM) + struct.pack("<I", 1) + struct.pack("<IIIII", 7, 0, 0x40, 0x100, 0)
    assert slices(data) == [("i386", 0x40)]


def test_cpp_scope_is_not_truncated_from_stabs_function_name() -> None:
    symbols = [
        {"is_stab": True, "stab": "N_SO", "name": "creature.cpp", "value": 0},
        {"is_stab": True, "stab": "N_OSO", "name": "creature.o", "value": 0},
        {
            "is_stab": True,
            "stab": "N_FUN",
            "name": "Foo::bar(Baz::Qux):F(0,1)",
            "value": 0x1234,
        },
    ]
    result = parse_stabs(_FakeMachO(symbols))
    assert result["functions"][0]["name"] == "Foo::bar(Baz::Qux)"
    assert result["functions"][0]["stabs_type"] == "F(0,1)"
