"""Unit tests for unprefixed hex address resolution and inspect-memory error paths."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from agentdecompile_cli.mcp_server.providers.memory import MemoryToolProvider
from agentdecompile_cli.mcp_utils.address_util import AddressUtil


class _FakeAddr:
    __slots__ = ("offset",)

    def __init__(self, offset: int) -> None:
        self.offset = offset

    def __repr__(self) -> str:
        return f"_FakeAddr(0x{self.offset:x})"


class _FakeAddressSpace:
    def getAddress(self, offset: int) -> _FakeAddr:
        return _FakeAddr(int(offset))


class _FakeAddressFactory:
    def getDefaultAddressSpace(self) -> _FakeAddressSpace:
        return _FakeAddressSpace()


class _FakeSymbolTable:
    def getLabelOrFunctionSymbols(self, name: object, ns: object) -> list[object]:
        return []

    def getSymbols(self, name: object) -> list[object]:
        return []


class _FakeProgramForAddr:
    def getAddressFactory(self) -> _FakeAddressFactory:
        return _FakeAddressFactory()

    def getSymbolTable(self) -> _FakeSymbolTable:
        return _FakeSymbolTable()


@pytest.mark.unit
def test_resolve_address_or_symbol_unprefixed_hex_with_alpha() -> None:
    prog = _FakeProgramForAddr()
    addr = AddressUtil.resolve_address_or_symbol(prog, "007b5000")
    assert addr is not None
    assert addr.offset == 0x007B5000
    prefixed = AddressUtil.resolve_address_or_symbol(prog, "0x007b5000")
    assert prefixed is not None
    assert prefixed.offset == addr.offset


@pytest.mark.unit
def test_resolve_address_or_symbol_decimal_without_alpha() -> None:
    prog = _FakeProgramForAddr()
    addr = AddressUtil.resolve_address_or_symbol(prog, "100")
    assert addr is not None
    assert addr.offset == 100


@pytest.mark.asyncio
@pytest.mark.unit
async def test_handle_read_returns_error_json_when_resolve_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    prog = object()
    fake_memory = SimpleNamespace()

    provider = MemoryToolProvider(program_info=SimpleNamespace(program=prog, decompiler=None))  # pyright: ignore[reportArgumentType]

    monkeypatch.setattr(provider, "_require_address_or_symbol", lambda args: "not_resolvable___")
    monkeypatch.setattr(provider, "_resolve_address", lambda addr_str, program=None: None)

    out = await provider._handle_read({"address": "not_resolvable___"}, prog, fake_memory)  # type: ignore[arg-type]
    assert len(out) == 1
    payload = json.loads(out[0].text)
    assert payload.get("success") is False
    assert "error" in payload
    assert payload.get("context", {}).get("state") == "address-resolution-failed"
