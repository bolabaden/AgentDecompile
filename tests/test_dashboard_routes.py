from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest

from agentdecompile_recovery.corpus.dashboard.app.models import (
    BinaryRef,
    ConcreteFunctionRef,
    EntityKind,
    LogicalFunctionRef,
    MetricScope,
    MetricUniverse,
)
from agentdecompile_recovery.corpus.dashboard.app.responses import PageResult
from agentdecompile_recovery.corpus.dashboard.app.routes import (
    RouteValueError,
    binary_url,
    function_url,
    functions_url,
    graph_url,
    logical_url,
    parse_graph_query,
)

pytestmark = pytest.mark.unit


def test_builders_emit_raw_urls_and_quote_slugs() -> None:
    slug = "K1/example build.exe"
    assert binary_url(slug) == "/binary/K1%2Fexample%20build.exe"
    assert functions_url(slug, named=True, after="0x401000") == (
        "/functions?binary=K1%2Fexample+build.exe&named=1&after=0x401000"
    )
    assert "&amp;" not in functions_url(slug, named=True, after="0x401000")


def test_function_url_uses_unambiguous_address_width() -> None:
    assert function_url("K1__game.exe", 0x401080, bits=32) == "/function/K1__game.exe/0x00401080"
    assert function_url("arm64", 0x100001234, bits=64) == "/function/arm64/0x0000000100001234"


def test_graph_url_is_slug_canonical() -> None:
    href = graph_url(
        ConcreteFunctionRef(BinaryRef(slug="K1__game.exe", binary_id=8), 0x401080),
        depth=2,
    )
    query = parse_qs(urlparse(href).query)
    assert query == {
        "slug": ["K1__game.exe"],
        "addr": ["0x401080"],
        "depth": ["2"],
    }
    assert "binary_id" not in href
    assert "&amp;" not in href


def test_logical_urls_are_canonical() -> None:
    logical = LogicalFunctionRef(10664)
    assert logical_url(logical) == "/logical/10664"
    assert graph_url(logical, depth=1) == "/graph?logical_id=10664&depth=1"


def test_parse_canonical_slug_graph_query() -> None:
    route = parse_graph_query({
        "slug": ["K1__game.exe"],
        "addr": ["0x00401080"],
        "depth": ["2"],
    })
    assert route.focus.binary.slug == "K1__game.exe"
    assert route.focus.binary.binary_id is None
    assert route.focus.address == 0x401080
    assert route.uses_legacy_binary_id is False


def test_parse_legacy_binary_id_graph_query() -> None:
    route = parse_graph_query({"binary_id": "8", "addr": "00401080"})
    assert route.focus.binary.slug is None
    assert route.focus.binary.binary_id == 8
    assert route.focus.address == 0x401080
    assert route.uses_legacy_binary_id is True


def test_slug_remains_canonical_when_compatibility_id_is_also_present() -> None:
    route = parse_graph_query({
        "slug": "K1__game.exe",
        "binary_id": "8",
        "addr": "0x401080",
    })
    assert route.focus.binary == BinaryRef("K1__game.exe", 8)
    assert route.uses_legacy_binary_id is False


def test_parse_logical_graph_query() -> None:
    route = parse_graph_query({"logical_id": "10664", "depth": "1"})
    assert route.focus == LogicalFunctionRef(10664)
    assert route.depth == 1


def test_parser_rejects_ambiguous_or_invalid_focus() -> None:
    invalid = (
        {},
        {"slug": "build", "addr": "nope"},
        {"binary_id": "-1", "addr": "0x401000"},
        {"logical_id": "3", "slug": "build", "addr": "0x401000"},
        {"slug": "a", "binary": "b", "addr": "0x401000"},
        {"slug": "a", "addr": "0x401000", "addr_hex": "0x402000"},
    )
    for query in invalid:
        with pytest.raises(RouteValueError):
            parse_graph_query(query)


def test_metric_scope_names_entity_universe_snapshot_and_evidence() -> None:
    scope = MetricScope(
        entity=EntityKind.CONCRETE_FUNCTION,
        universe=MetricUniverse.UNIQUE_NON_DRM,
        snapshot="db:corpus.sqlite@2026-08-24T01:00:36-05:00",
        evidence=("db/corpus.sqlite:identity",),
    )
    assert scope.entity.value == "concrete_function"
    assert scope.universe.value == "unique_non_drm"
    assert scope.snapshot.startswith("db:")
    with pytest.raises(AttributeError):
        scope.snapshot = "changed"


def test_page_result_carries_status_headers_and_body() -> None:
    result = PageResult.redirect("/binary/K1__game.exe", permanent=True)
    assert result.status == 308
    assert result.header("Location") == "/binary/K1__game.exe"
    assert result.body == ""
