from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit

from agentdecompile_recovery.corpus.dashboard import function_choices


def test_list_function_choices_is_bounded_and_indexed(monkeypatch):
    calls = []

    def fake_query(sql, params=(), **_kwargs):
        calls.append((sql, params))
        if "FROM binary WHERE slug" in sql:
            return [(1, "build_one", 32)], None
        if "f.addr=?" in sql:
            return [(0x401000, "Main", 12)], None
        if "LIKE" in sql:
            return [(0x401000, "Main", 12), (0x401080, "MainMenu", 24)], None
        if "addr>=?" in sql:
            return [(0x401000, "Main", 12)], None
        if "addr<?" in sql:
            return [], None
        if "addr>?" in sql:
            return [(0x401000, "Main", 12)], None
        return [], None

    monkeypatch.setattr(function_choices, "query_db", fake_query)

    point = function_choices.list_function_choices("build_one", q="0x401000")
    assert point["ok"] is True
    assert point["results"][0]["addr"] == "0x00401000"
    assert "LIMIT 1" in calls[1][0]

    named = function_choices.list_function_choices("build_one", q="Main")
    assert [row["name"] for row in named["results"]] == ["Main", "MainMenu"]
    assert named["results"][0]["addr"].startswith("0x")

    window = function_choices.list_function_choices("build_one", around="0x401000")
    assert window["ok"] is True
    assert any(row["address"] == 0x401000 for row in window["results"])
    assert all("OFFSET" not in sql for sql, _params in calls)
