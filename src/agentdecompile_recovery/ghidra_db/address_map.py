"""Decoding of Ghidra's encoded address longs.

Mirrors ``ghidra.program.database.map.AddressMapDB`` (Apache-2.0). Every
`Address` column in a program database stores a packed long, not a raw address::

    bits 63..60   address type (4 bits)
    bits 59..32   base index (28 bits) -- key into the ADDRESS MAP table
    bits 31..0    offset (32 bits)

Address types, per AddressMapDB's own documentation:

    0   original  legacy encoding, kept for backwards compatibility
    1   absolute  ignores the image base; used by the memory map
    2   relocatable  most common; moves with the image base
    3   register
    4   stack     includes namespace info so frames stay unique per function
    5   external  an address in another program (imports)
    6   variable
    7   hash
    15  none      null or meaningless address

Only types 1 and 2 denote real memory. Treating type 5 as a memory offset is a
concrete hazard: in the curated Odyssey project 343 of 27,318 function symbols
are external imports whose "offsets" are small ordinals (0x4, 0xa, ...) that
would otherwise look like valid addresses near the image base.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

ADDR_TYPE_SIZE = 4
ADDR_TYPE_SHIFT = 64 - ADDR_TYPE_SIZE
ADDR_TYPE_MASK = (1 << ADDR_TYPE_SIZE) - 1

ADDR_OFFSET_SIZE = 32
ADDR_OFFSET_MASK = (1 << ADDR_OFFSET_SIZE) - 1
BASE_INDEX_MASK = (1 << (64 - ADDR_TYPE_SIZE - ADDR_OFFSET_SIZE)) - 1

TYPE_ORIGINAL = 0
TYPE_ABSOLUTE = 1
TYPE_RELOCATABLE = 2
TYPE_REGISTER = 3
TYPE_STACK = 4
TYPE_EXTERNAL = 5
TYPE_VARIABLE = 6
TYPE_HASH = 7
TYPE_NONE = 15

_TYPE_NAMES = {
    TYPE_ORIGINAL: "original",
    TYPE_ABSOLUTE: "absolute",
    TYPE_RELOCATABLE: "relocatable",
    TYPE_REGISTER: "register",
    TYPE_STACK: "stack",
    TYPE_EXTERNAL: "external",
    TYPE_VARIABLE: "variable",
    TYPE_HASH: "hash",
    TYPE_NONE: "none",
}

_MEMORY_TYPES = frozenset({TYPE_ORIGINAL, TYPE_ABSOLUTE, TYPE_RELOCATABLE})


@dataclass(frozen=True)
class DecodedAddress:
    """One decoded address long."""

    raw: int
    address_type: int
    base_index: int
    offset: int
    space_name: str | None = None

    @property
    def type_name(self) -> str:
        return _TYPE_NAMES.get(self.address_type, f"unknown({self.address_type})")

    @property
    def is_memory(self) -> bool:
        """Whether this denotes a real memory location.

        Registers, stack slots, externals, variables and hashes do not.
        """

        return self.address_type in _MEMORY_TYPES

    @property
    def is_image_relative(self) -> bool:
        """Relocatable offsets are relative to the image base; absolute are not."""

        return self.address_type == TYPE_RELOCATABLE

    def absolute(self, image_base: int = 0) -> int | None:
        """Resolve to a virtual address, or None when this is not memory."""

        if not self.is_memory:
            return None
        return self.offset + image_base if self.is_image_relative else self.offset

    def to_json(self) -> dict[str, Any]:
        return {
            "raw": f"0x{self.raw:016x}",
            "type": self.type_name,
            "baseIndex": self.base_index,
            "offset": f"0x{self.offset:x}",
            "spaceName": self.space_name,
            "isMemory": self.is_memory,
        }


def decode_address(value: int | None, space_names: dict[int, str] | None = None) -> DecodedAddress | None:
    """Split an encoded address long into its parts.

    Returns None for a null value or the explicit "no address" encoding, so
    callers can skip rather than fabricate address 0.
    """

    if value is None:
        return None
    raw = value & 0xFFFFFFFFFFFFFFFF
    address_type = (raw >> ADDR_TYPE_SHIFT) & ADDR_TYPE_MASK
    if address_type == TYPE_NONE:
        return None
    base_index = (raw >> ADDR_OFFSET_SIZE) & BASE_INDEX_MASK
    offset = raw & ADDR_OFFSET_MASK
    return DecodedAddress(
        raw=raw,
        address_type=address_type,
        base_index=base_index,
        offset=offset,
        space_name=(space_names or {}).get(base_index),
    )


class AddressMap:
    """The ADDRESS MAP table: base index -> address space."""

    def __init__(self, space_names: dict[int, str] | None = None) -> None:
        self.space_names = dict(space_names or {})

    @classmethod
    def from_rows(cls, rows: Iterable[dict[str, Any]]) -> "AddressMap":
        """Build from decoded ADDRESS MAP rows, skipping deleted entries."""

        names: dict[int, str] = {}
        for row in rows:
            if row.get("Deleted"):
                continue
            key = row.get("Key")
            name = row.get("Space Name")
            if key is not None and name:
                names[int(key)] = str(name)
        return cls(names)

    def decode(self, value: int | None) -> DecodedAddress | None:
        return decode_address(value, self.space_names)

    def offset_of(self, value: int | None) -> int | None:
        """Memory offset for `value`, or None when it is not a memory address."""

        decoded = self.decode(value)
        if decoded is None or not decoded.is_memory:
            return None
        return decoded.offset

    def absolute_of(self, value: int | None, image_base: int = 0) -> int | None:
        decoded = self.decode(value)
        return None if decoded is None else decoded.absolute(image_base)
