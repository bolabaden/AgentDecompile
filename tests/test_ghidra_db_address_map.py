"""Tests for encoded-address decoding (U5).

Reference: ghidra.program.database.map.AddressMapDB. Getting this wrong is not
a crash, it is silent mis-attribution: a curated name lands on the wrong
function and nothing complains.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery.ghidra_db.address_map import (
    TYPE_ABSOLUTE,
    TYPE_EXTERNAL,
    TYPE_NONE,
    TYPE_RELOCATABLE,
    TYPE_STACK,
    AddressMap,
    decode_address,
)
from agentdecompile_recovery.ghidra_db.buffer_file import BufferFile
from agentdecompile_recovery.ghidra_db.master_table import find_table, iter_rows

pytestmark = pytest.mark.unit

ODYSSEY_FIXTURE = Path("/home/brunner56/Odyssey.rep/idata/00/~00000000.db/db.1.gbf")
_needs_odyssey = pytest.mark.skipif(
    not ODYSSEY_FIXTURE.is_file(), reason="Odyssey project fixture unavailable"
)


def _encode(address_type: int, base_index: int, offset: int) -> int:
    return (address_type << 60) | (base_index << 32) | offset


def test_splits_type_base_and_offset() -> None:
    decoded = decode_address(_encode(TYPE_RELOCATABLE, 0, 0x449DE0))

    assert decoded is not None
    assert decoded.address_type == TYPE_RELOCATABLE
    assert decoded.base_index == 0
    assert decoded.offset == 0x449DE0


def test_relocatable_is_image_relative() -> None:
    """`.text` at offset 0x1000 with base 0x400000 is VA 0x401000."""

    decoded = decode_address(_encode(TYPE_RELOCATABLE, 0, 0x1000))

    assert decoded is not None
    assert decoded.is_image_relative
    assert decoded.absolute(0x400000) == 0x401000


def test_absolute_ignores_image_base() -> None:
    decoded = decode_address(_encode(TYPE_ABSOLUTE, 0, 0x1000))

    assert decoded is not None
    assert not decoded.is_image_relative
    assert decoded.absolute(0x400000) == 0x1000


def test_external_is_not_memory() -> None:
    """Imports encode tiny ordinals; read as RAM they look like valid addresses
    just above the image base and silently mis-name functions."""

    decoded = decode_address(_encode(TYPE_EXTERNAL, 0, 0x4))

    assert decoded is not None
    assert not decoded.is_memory
    assert decoded.absolute(0x400000) is None


def test_stack_and_register_are_not_memory() -> None:
    decoded = decode_address(_encode(TYPE_STACK, 0, 0x8))

    assert decoded is not None
    assert not decoded.is_memory


def test_no_address_decodes_to_none() -> None:
    assert decode_address(_encode(TYPE_NONE, 0, 0)) is None


def test_null_input_decodes_to_none() -> None:
    assert decode_address(None) is None


def test_base_index_is_extracted() -> None:
    decoded = decode_address(_encode(TYPE_RELOCATABLE, 5, 0x20))

    assert decoded is not None
    assert decoded.base_index == 5


def test_address_map_resolves_space_names() -> None:
    amap = AddressMap.from_rows(
        [
            {"Key": 0, "Space Name": "ram", "Segment": 0, "Deleted": False},
            {"Key": 1, "Space Name": "stale", "Segment": 0, "Deleted": True},
        ]
    )

    decoded = amap.decode(_encode(TYPE_RELOCATABLE, 0, 0x1000))
    assert decoded is not None and decoded.space_name == "ram"
    assert amap.decode(_encode(TYPE_RELOCATABLE, 1, 0x1000)).space_name is None


def test_offset_of_filters_non_memory() -> None:
    amap = AddressMap({0: "ram"})

    assert amap.offset_of(_encode(TYPE_RELOCATABLE, 0, 0x1234)) == 0x1234
    assert amap.offset_of(_encode(TYPE_EXTERNAL, 0, 0x4)) is None


@_needs_odyssey
def test_real_project_joins_names_to_addresses() -> None:
    """The whole point: curated names resolved onto real virtual addresses."""

    function_symbol_type = 5
    with BufferFile(ODYSSEY_FIXTURE) as bf:
        amap = AddressMap.from_rows(iter_rows(bf, find_table(bf, "ADDRESS MAP")))
        metadata = {row["Key"]: row["Value"] for row in iter_rows(bf, find_table(bf, "Program"))}
        image_base = int(metadata["Image Offset"], 16)

        named: dict[int, str] = {}
        for row in iter_rows(bf, find_table(bf, "Symbols")):
            if row.get("Symbol Type") != function_symbol_type:
                continue
            va = amap.absolute_of(row.get("Address"), image_base)
            name = row.get("Name") or ""
            if va and name and not name.startswith(("FUN_", "Rsrc_")):
                named[va] = name

    assert image_base == 0x400000
    assert metadata["Program Name"] == "swkotor2.exe"
    assert len(named) > 25000
    # Every VA must land at or above the image base -- externals excluded.
    assert min(named) >= image_base


@_needs_odyssey
def test_program_metadata_is_readable_via_var_key_nodes() -> None:
    """The Program table keys on strings, so it exercises the var-key path."""

    with BufferFile(ODYSSEY_FIXTURE) as bf:
        metadata = {row["Key"]: row["Value"] for row in iter_rows(bf, find_table(bf, "Program"))}

    assert metadata["Language ID"] == "x86:LE:32:default"
    assert metadata["DB Version"] == "32"
