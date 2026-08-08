"""Tests for PE header inventory fields (linker version, magic, timestampUtc)."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery.inventory import build_binary_inventory
from agentdecompile_recovery.targets import identify_binary

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "pe"
MINIMAL_PE = FIXTURES / "minimal_pe32.bin"

pytestmark = pytest.mark.unit


@pytest.fixture(scope="module")
def minimal_pe_inventory() -> dict:
    identity = identify_binary(MINIMAL_PE)
    return build_binary_inventory(identity)


def test_pe_inventory_linker_version(minimal_pe_inventory: dict) -> None:
    assert minimal_pe_inventory["majorLinkerVersion"] == 7
    assert minimal_pe_inventory["minorLinkerVersion"] == 10


def test_pe_inventory_optional_header_magic(minimal_pe_inventory: dict) -> None:
    assert minimal_pe_inventory["optionalHeaderMagic"] == "0x010b"


def test_pe_inventory_timestamp_utc(minimal_pe_inventory: dict) -> None:
    ts_utc = minimal_pe_inventory["timestampUtc"]
    assert ts_utc is not None
    # Raw timestamp 0x5F000000 = 1593828320 -> 2020-07-04T04:05:20+00:00
    assert ts_utc.startswith("2020-07-04")
    assert ts_utc.endswith("+00:00")


def test_pe_inventory_schema_unchanged(minimal_pe_inventory: dict) -> None:
    assert minimal_pe_inventory["schema"] == "agentdecompile.binary-inventory.v1"
    assert minimal_pe_inventory["format"] == "pe"
    assert minimal_pe_inventory["status"] == "complete"
    # Original fields still present
    assert "timestamp" in minimal_pe_inventory
    assert "machine" in minimal_pe_inventory
    assert "sections" in minimal_pe_inventory
