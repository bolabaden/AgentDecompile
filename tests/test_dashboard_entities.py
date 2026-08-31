from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit

from agentdecompile_recovery.corpus.dashboard.panels import entities


BINARIES = {
    1: {
        "id": 1,
        "slug": "build_one",
        "repo_path": "/K1/one.exe",
        "game": "K1",
        "platform": "win",
        "arch": "x86",
        "bits": 32,
        "func_count": 10,
        "named_count": 8,
    },
    2: {
        "id": 2,
        "slug": "build_two",
        "repo_path": "/K2/two.exe",
        "game": "K2",
        "platform": "win",
        "arch": "x86",
        "bits": 32,
        "func_count": 12,
        "named_count": 9,
    },
}


def test_global_real_c_filter_renders_actual_corpus_rows(monkeypatch):
    monkeypatch.setattr(entities, "_binaries", lambda: (BINARIES, None))

    def fake_query(sql, params=(), **_kwargs):
        assert "FROM recovered_function WHERE real_c=?" in sql
        assert params == (1, entities.PAGE + 1)
        return [(1, 0x401000, "RecoveredThing", 90, 1, 31324)], None

    monkeypatch.setattr(entities, "query_db", fake_query)
    html = entities.render_functions({"real_c": ["1"]})

    assert "Functions across every build" in html
    assert "active filters: <b>real_c</b>" in html
    assert "RecoveredThing" in html
    assert "/function/build_one/0x00401000" in html
    assert "real C" in html
    assert "pick a build" not in html


def test_global_address_search_uses_one_indexed_point_lookup_per_build(monkeypatch):
    monkeypatch.setattr(entities, "_binaries", lambda: (BINARIES, None))
    calls = []

    def fake_query(sql, params=(), **_kwargs):
        calls.append((sql, params))
        assert sql == "SELECT name, size FROM func WHERE binary_id=? AND addr=?"
        if params[0] == 1:
            return [("OnlyInOne", 32)], None
        return [], None

    monkeypatch.setattr(entities, "query_db", fake_query)
    html = entities.render_functions({"q": ["0x00401000"]})

    assert len(calls) == len(BINARIES)
    assert all(params[1] == 0x401000 for _sql, params in calls)
    assert "OnlyInOne" in html
    assert "/function/build_one/0x00401000" in html
    assert "Exact address search uses one indexed point lookup per build" in html


def test_non_global_filter_preserves_state_when_choosing_build(monkeypatch):
    monkeypatch.setattr(entities, "_binaries", lambda: (BINARIES, None))
    html = entities.render_functions({"bound": ["1"], "size_band": ["small"]})

    assert "active filters: <b>bound, size_band=small</b>" in html
    assert "/functions?binary=build_one&amp;bound=1&amp;size_band=small" in html
    assert "Choose a build; the filter state is preserved" in html


def test_graph_links_emit_unambiguous_hex_addresses():
    href = entities._graph_href(8, 0x401000)
    assert href == "/graph?binary_id=8&amp;addr=0x401000&amp;depth=2"
    page = entities._graph_href("build_one", 0x401000)
    assert page.startswith("/function/build_one/")
    assert "0x00401000" in page


def test_corpus_recovery_results_use_a_stable_keyset_cursor(monkeypatch):
    monkeypatch.setattr(entities, "_binaries", lambda: (BINARIES, None))
    rows = [(1, 0x401000 + i, f"Fn{i}", 8, 1, i) for i in range(entities.PAGE + 1)]
    calls = []

    def fake_query(sql, params=(), **_kwargs):
        calls.append((sql, params))
        return rows, None

    monkeypatch.setattr(entities, "query_db", fake_query)
    first = entities.render_functions({"real_c": ["1"]})
    assert "after=1%3A0x401063" in first

    entities.render_functions({"real_c": ["1"], "after": ["1:0x401063"]})
    sql, params = calls[-1]
    assert "binary_id&gt;" not in first  # SQL never leaks into the page.
    assert "binary_id>? OR (binary_id=? AND addr>?)" in sql
    assert params[-4:-1] == (1, 1, 0x401063)


def test_page_size_defaults_to_page_and_accepts_all(monkeypatch):
    assert entities._page_size({}) == (entities.PAGE, False)
    assert entities._page_size({"page_size": ["25"]}) == (25, False)
    assert entities._page_size({"page_size": ["all"]}) == (entities.ALL_CAP, True)
    assert entities._page_size({"page_size": ["99999"]}) == (entities.ALL_CAP, True)
    assert entities._page_size({"page_size": ["nope"]}) == (entities.PAGE, False)

    monkeypatch.setattr(entities, "_binaries", lambda: (BINARIES, None))
    calls = []

    def fake_query(sql, params=(), **_kwargs):
        calls.append((sql, params))
        if "COUNT(DISTINCT addr)" in sql:
            return [(0,)], None
        if "FROM func f" in sql:
            return [(0x401000, "Foo", 12, None, 0)], None
        return [], None

    monkeypatch.setattr(entities, "query_db", fake_query)
    html = entities.render_functions({"binary": ["build_one"], "page_size": ["25"]})
    func = [params for sql, params in calls if "FROM func f" in sql][-1]
    assert func[-1] == 26
    assert 'id="page-size"' in html
    assert 'name="page_size"' in html
    assert 'value="25" selected' in html
    assert "All (up to 5,000)" in html
    assert 'id="function-results"' in html
    assert 'data-live-search="functions"' in html

    calls.clear()
    partial = entities.render_functions({
        "binary": ["build_one"],
        "page_size": ["all"],
        "partial": ["1"],
    })
    func = [params for sql, params in calls if "FROM func f" in sql][-1]
    assert func[-1] == entities.ALL_CAP + 1
    assert partial.startswith('<div id="function-results">')
    assert "function-search-form" not in partial
