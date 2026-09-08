from __future__ import annotations

from html import unescape
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import pytest

from agentdecompile_recovery.corpus.dashboard import pages as dashboard
from agentdecompile_recovery.corpus.dashboard.common import format_address, parse_address
from agentdecompile_recovery.corpus.dashboard.panels.callgraph import _graph_href
from agentdecompile_recovery.corpus.dashboard.panels.entities import _function_href

pytestmark = pytest.mark.unit


def test_canonical_function_links_are_prefixed_hex() -> None:
    assert _function_href("K1__example.exe", 0x00401080, 32) == "/function/K1__example.exe/0x00401080"
    assert _function_href("arm64", 0x100001234, 64) == "/function/arm64/0x0000000100001234"


def test_legacy_padded_digit_only_hex_remains_valid() -> None:
    assert parse_address("00401080") == 0x00401080
    assert parse_address("0000000100001234") == 0x100001234


def test_short_digit_only_query_values_remain_decimal() -> None:
    assert parse_address("401080") == 401080


def test_invalid_and_negative_addresses_are_rejected() -> None:
    for value in (None, "", "0x", "not-an-address", "-1"):
        assert parse_address(value) is None


def test_formatter_never_emits_an_ambiguous_route_value() -> None:
    assert format_address(0x401080, 32) == "0x00401080"
    assert format_address(0x100001234, 64) == "0x0000000100001234"


def test_graph_producer_consumer_round_trip() -> None:
    href = unescape(_graph_href("K1__example.exe", 0x00401080, 2, 32))
    assert href.startswith("/function/K1__example.exe/0x00401080")
    query = parse_qs(urlparse(href).query)
    assert query["depth"] == ["2"]
    wide = unescape(_graph_href("arm64", 0x100001234, 1, 64))
    assert "/function/arm64/0x0000000100001234" in wide
    assert "depth=1" in wide


def test_graph_parser_keeps_ids_decimal_and_accepts_legacy_addresses() -> None:
    params = dashboard._graph_params({
        "binary_id": ["12345678"],
        "logical_id": ["87654321"],
        "addr": ["00401080"],
    })
    assert params["binary_id"] == 12345678
    assert params["logical_id"] == 87654321
    assert params["addr"] == 0x00401080


def test_graph_parser_rejects_invalid_and_negative_addresses() -> None:
    for value in ("", "0x", "not-an-address", "-1"):
        assert dashboard._graph_params({"addr": [value]})["addr"] is None


def test_function_page_graph_link_uses_explicit_hex() -> None:
    binary = {"id": 7, "slug": "K1__example.exe"}
    with patch.object(dashboard, "_binary", return_value=binary), \
         patch.object(dashboard, "query_db", return_value=([(1,)], None)), \
         patch.object(dashboard, "_entity_call", return_value=("function", True)) as render, \
         patch.object(dashboard, "render_graph_embed", return_value="<div>graph</div>"):
        body, status = dashboard.render_function_page("K1__example.exe", "00401080")
    assert status == 200
    render.assert_called_once_with("render_function", "K1__example.exe", 0x00401080)
    assert 'id="graph"' in body
    assert "fn-workspace" in body
    assert 'data-copy="0x00401080"' in body


def test_missing_function_is_a_real_404() -> None:
    binary = {"id": 7, "slug": "K1__example.exe"}
    with patch.object(dashboard, "_binary", return_value=binary), \
         patch.object(dashboard, "query_db", return_value=([], None)), \
         patch.object(dashboard, "_entity_call") as render:
        body, status = dashboard.render_function_page("K1__example.exe", "0xdeadbeef")
    assert status == 404
    assert "no function at 0xdeadbeef" in body
    render.assert_not_called()
