from __future__ import annotations

from types import SimpleNamespace

import pytest

from agentdecompile_cli.mcp_server.providers.symbols import (
    SymbolToolProvider,
    select_label_symbol_for_delete,
)


def _mock_label(name: str, *, user_defined: bool = True, symbol_type: str = "label") -> SimpleNamespace:
    source = "USER_DEFINED" if user_defined else "ANALYSIS"
    return SimpleNamespace(
        getName=lambda: name,
        getSource=lambda: source,
        getSymbolType=lambda: symbol_type,
    )


@pytest.mark.unit
def test_manage_symbols_schema_includes_delete_label_mode() -> None:
    provider = SymbolToolProvider()
    tools = provider.list_tools()
    manage = next(tool for tool in tools if tool.name == "manage-symbols")
    mode_enum = manage.inputSchema["properties"]["mode"]["enum"]
    assert "delete_label" in mode_enum


@pytest.mark.unit
def test_select_label_symbol_for_delete_by_name() -> None:
    target = _mock_label("myLabel")
    other = _mock_label("otherLabel")
    selected = select_label_symbol_for_delete(
        [other, target],
        label_name="myLabel",
        primary_symbol=other,
    )
    assert selected is target


@pytest.mark.unit
def test_select_label_symbol_for_delete_uses_primary_when_unique() -> None:
    primary = _mock_label("primaryLabel")
    selected = select_label_symbol_for_delete([], label_name=None, primary_symbol=primary)
    assert selected is primary


@pytest.mark.unit
def test_select_label_symbol_for_delete_requires_label_name_when_ambiguous() -> None:
    first = _mock_label("labelA")
    second = _mock_label("labelB")
    with pytest.raises(ValueError, match="Multiple deletable labels"):
        select_label_symbol_for_delete([first, second], label_name=None, primary_symbol=None)


@pytest.mark.unit
def test_select_label_symbol_for_delete_skips_default_auto_names() -> None:
    auto = _mock_label("LAB_00401000", user_defined=False)
    selected = select_label_symbol_for_delete([auto], label_name=None, primary_symbol=auto)
    assert selected is None


@pytest.mark.unit
def test_deletelabel_handler_is_registered() -> None:
    provider = SymbolToolProvider()
    assert "deletelabel" in provider.HANDLERS
