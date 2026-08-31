"""Focused call-graph UX and query-boundary tests."""

from __future__ import annotations

from unittest.mock import patch

import pytest

pytestmark = pytest.mark.unit

from agentdecompile_recovery.corpus.dashboard.panels import callgraph


BINARIES = {
    2: ("beta", "game-b", "linux", "arm64", 64),
    1: ("alpha", "game-a", "windows", "x86", 32),
}


def test_search_form_is_binary_agnostic_and_exact_address_only():
    with patch.object(callgraph, "_function_options", return_value='<option value="0x00401000">main — 0x00401000</option>'):
        html = callgraph._search_form(BINARIES)
    assert 'name="slug"' in html
    assert 'name="binary_id"' not in html
    assert 'name="addr"' in html
    assert 'id="fn-combo-list"' in html
    assert 'role="search" aria-label="Open a function"' in html
    assert "alpha — game-a/windows/x86, 32-bit" in html
    assert "beta — game-b/linux/arm64, 64-bit" in html
    assert "Open function" in html
    assert "does not dump the whole build" in html
    assert html.count("<option") >= 2
    assert "GOG" not in html and "reconstruction target" not in html


def test_graph_links_keep_explicit_hexadecimal_addresses():
    href = callgraph._graph_href("build three", 0x401080, 2)
    assert href.startswith("/function/")
    assert "0x00401080" in href
    assert "depth=2" in href
    assert "addr=401080" not in href
    assert "binary_id=" not in href
    assert "&amp;" not in href


def test_invalid_address_has_clear_error_without_querying_database():
    with patch.object(callgraph, "query_db") as query, \
         patch.object(callgraph, "_function_options", return_value=""):
        html = callgraph.render_fragment({"binary_id": "1", "addr": "not-an-address"})
    assert "address is not valid" in html
    assert html.count("<h1") == 1
    # render_picker may query after the error to offer recovery; no func query is allowed.
    assert all("FROM func " not in call.args[0] for call in query.call_args_list)


def test_selected_graph_svg_is_accessible_responsive_and_has_list_fallback():
    focus = {"label": "Entry", "addr": 0x1000, "name_state": "canonical-name",
             "reach": 2, "label_tier": "symbol", "name_why": "canonical symbol-tier name",
             "binding_label": "cross-build identity ×2 · confidence 0.95",
             "binding_why": "recorded method exact", "source_file": None,
             "local_name": "Entry", "logical_id": 4, "conf": .95,
             "method": "exact"}
    levels = {0: [0x1000]}
    nodes = {0x1000: focus}
    svg = callgraph._svg(levels, [], {}, nodes, 0x1000, "alpha", 32, 1, "test")
    fallback = callgraph._list_fallback(levels, nodes, "alpha", 32, 1)
    assert 'role="img"' in svg
    assert 'aria-labelledby="kg-title-test kg-desc-test"' in svg
    assert '<title id="kg-title-test">' in svg
    assert '<desc id="kg-desc-test">' in svg
    assert 'style="display:block;width:100%;height:auto;' in svg
    assert 'aria-label="Entry, address 0x00001000, this function;' in svg
    assert "/function/alpha/" in svg
    assert "0x00001000" in svg
    assert "Read this graph as a list" in fallback
    assert "Entry" in fallback and "0x00001000" in fallback
    assert "proven" not in (svg + fallback).lower()


def test_picker_chooses_strongest_binding_not_architecture():
    def fake_query(sql, params=(), db=None):
        if "FROM binary" in sql:
            return [(1, "alpha", "a", "win", "x86", 32),
                    (2, "beta", "b", "linux", "arm64", 64)], None
        if "FROM logical_name" in sql:
            return [(9, "Named", "symbol", 2)], None
        if "FROM identity" in sql:
            return [(9, 1, 0x1000, .7), (9, 2, 0x2000, .95)], None
        if "FROM logical_function" in sql:
            return [(9, "Class")], None
        raise AssertionError(sql)

    with patch.object(callgraph, "query_db", side_effect=fake_query), \
         patch.object(callgraph, "_function_options", return_value=""):
        html = callgraph.render_picker()
    assert "/function/beta/" in html
    assert "0x00002000" in html
    assert "strongest available binding" in html


def test_neighbour_query_is_bounded_and_forces_expected_index():
    with patch.object(callgraph, "query_db", return_value=([], None)) as query:
        callgraph._neighbours(1, 0x1000, "callers", limit=7)
    sql, params = query.call_args.args[:2]
    assert "INDEXED BY ix_edge_callee" in sql
    assert "binary_id=? AND callee_addr=? LIMIT ?" in sql
    assert params == (1, 0x1000, 7)
    assert "FROM func" not in sql


def test_slug_is_canonical_but_binary_id_still_loads_old_links():
    with patch.object(callgraph, "query_db", return_value=([(7,)], None)) as query, \
         patch.object(callgraph, "render_graph", return_value="slug graph") as render:
        assert callgraph.render_fragment({"slug": "alpha", "addr": "0x1000"}) == "slug graph"
    query.assert_called_once_with("SELECT id FROM binary WHERE slug=?", ("alpha",))
    render.assert_called_once_with(
        7, 0x1000, 2, direction="both", density="comfortable", labels="both",
        edges="curved", ink="default", heading=True
    )

    with patch.object(callgraph, "render_graph", return_value="compat graph") as render:
        assert callgraph.render_fragment({"binary_id": "7", "addr": "0x1000"}) == "compat graph"
    render.assert_called_once_with(
        7, 0x1000, 2, direction="both", density="comfortable", labels="both",
        edges="curved", ink="default", heading=True
    )


def test_empty_fragment_has_one_page_heading_and_canonical_instructions():
    with patch.object(callgraph, "render_picker", return_value="picker"):
        html = callgraph.render_fragment({})
    assert html.count("<h1") == 1
    assert "needs slug and addr" in html


def test_name_fill_binding_evidence_and_call_edges_are_separate_claims():
    node = {
        "addr": 0x1000, "logical_id": 8, "conf": 0.81, "method": "match:v1:auto",
        "reach": 3, "name": "Named", "tier": 2, "tier_name": "stabs",
        "canon_class": "Thing", "source_file": None, "local_name": None,
        "unchecked": False,
    }
    callgraph._label(node, 32)
    assert node["name_state"] == "canonical-name"
    assert node["name_why"] == "canonical stabs-tier name"
    assert node["binding_label"] == "cross-build identity ×3 · confidence 0.81"
    assert node["binding_why"] == "recorded method match:v1:auto"

    legend = callgraph._legend({0x1000: node}, {}, False)
    assert "name selected by the cross-build precedence resolver" in legend
    assert "An arrow means <code>calledge</code> records that call relation" in legend
    assert "None of those values changes the node fill" in legend
    assert "proven" not in legend.lower()


def test_selected_fragment_owns_exactly_one_h1():
    focus = {
        "label": "Entry", "addr": 0x1000, "name_state": "canonical-name",
        "reach": 2, "label_tier": "symbol", "name_why": "canonical symbol-tier name",
        "binding_label": "cross-build identity ×2 · confidence 0.95",
        "binding_why": "recorded method exact", "source_file": None,
        "local_name": "Entry", "logical_id": 4, "conf": .95, "method": "exact",
    }
    with patch.object(callgraph, "_binaries", return_value=(BINARIES, None)), \
         patch.object(callgraph, "_collect", return_value=({0: [0x1000]}, [], {}, False)), \
         patch.object(callgraph, "_resolve", return_value=({0x1000: focus}, 0)), \
         patch.object(callgraph, "_siblings", return_value=""), \
         patch.object(callgraph, "_svg", return_value="<svg></svg>"), \
         patch.object(callgraph, "_list_fallback", return_value=""), \
         patch.object(callgraph, "_legend", return_value=""):
        html = callgraph.render_graph(1, 0x1000, 2)
    assert html.count("<h1") == 1
    assert "Call graph: Entry" in html
