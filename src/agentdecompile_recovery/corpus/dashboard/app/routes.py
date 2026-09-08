"""Canonical raw URL builders and compatibility parsers for the dashboard."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import quote, urlencode

from agentdecompile_recovery.corpus.dashboard.app.models import (
    BinaryRef,
    ConcreteFunctionRef,
    GraphFocus,
    GraphRoute,
    LogicalFunctionRef,
)
from agentdecompile_recovery.corpus.dashboard.panels.common import format_address, parse_address


class RouteValueError(ValueError):
    """A route cannot identify exactly one valid dashboard entity."""


def _slug(value: str) -> str:
    try:
        return BinaryRef(slug=value).slug or ""
    except (TypeError, ValueError) as exc:
        raise RouteValueError(str(exc)) from exc


def _path_segment(value: str) -> str:
    return quote(_slug(value), safe="")


def _query_value(value: Any) -> Any:
    if isinstance(value, bool):
        return "1" if value else "0"
    return value


def binary_url(slug: str) -> str:
    return f"/binary/{_path_segment(slug)}"


def functions_url(slug: str | None = None, **params: Any) -> str:
    pairs: list[tuple[str, Any]] = []
    if slug is not None:
        pairs.append(("binary", _slug(slug)))
    for key, value in params.items():
        if value is None:
            continue
        if isinstance(value, (list, tuple)):
            pairs.extend((key, _query_value(item)) for item in value)
        else:
            pairs.append((key, _query_value(value)))
    return "/functions" + (f"?{urlencode(pairs, doseq=True)}" if pairs else "")


def function_url(slug: str, address: int, *, bits: int = 32) -> str:
    try:
        ref = ConcreteFunctionRef(BinaryRef(slug=slug), address, bits)
    except (TypeError, ValueError) as exc:
        raise RouteValueError(str(exc)) from exc
    return f"/function/{_path_segment(ref.binary.slug or '')}/{format_address(ref.address, bits)}"


def logical_url(logical: LogicalFunctionRef | int) -> str:
    try:
        ref = logical if isinstance(logical, LogicalFunctionRef) else LogicalFunctionRef(logical)
    except (TypeError, ValueError) as exc:
        raise RouteValueError(str(exc)) from exc
    return f"/logical/{ref.logical_id}"


def graph_url(focus: GraphFocus, *, depth: int = 2) -> str:
    try:
        route = GraphRoute(focus, depth)
    except (TypeError, ValueError) as exc:
        raise RouteValueError(str(exc)) from exc
    if isinstance(route.focus, LogicalFunctionRef):
        pairs = (("logical_id", route.focus.logical_id), ("depth", route.depth))
    else:
        if route.focus.binary.slug is None:
            raise RouteValueError("canonical graph URLs require a binary slug")
        pairs = (
            ("slug", route.focus.binary.slug),
            ("addr", f"0x{route.focus.address:x}"),
            ("depth", route.depth),
        )
    return f"/graph?{urlencode(pairs)}"


def _one(query: Mapping[str, Any], key: str) -> str | None:
    raw = query.get(key)
    if raw is None:
        return None
    if isinstance(raw, str):
        values = [raw]
    elif isinstance(raw, Sequence) and not isinstance(raw, (bytes, bytearray)):
        values = [str(item) for item in raw]
    else:
        values = [str(raw)]
    values = [value.strip() for value in values if value.strip()]
    if not values:
        return None
    if any(value != values[0] for value in values[1:]):
        raise RouteValueError(f"route has conflicting {key} values")
    return values[0]


def _decimal(query: Mapping[str, Any], key: str) -> int | None:
    raw = _one(query, key)
    if raw is None:
        return None
    try:
        value = int(raw, 10)
    except ValueError as exc:
        raise RouteValueError(f"{key} must be a decimal integer") from exc
    if value <= 0:
        raise RouteValueError(f"{key} must be positive")
    return value


def _alias(query: Mapping[str, Any], primary: str, compatibility: str) -> str | None:
    current = _one(query, primary)
    legacy = _one(query, compatibility)
    if current is not None and legacy is not None and current != legacy:
        raise RouteValueError(f"route has conflicting {primary} and {compatibility} values")
    return current or legacy


def parse_graph_query(query: Mapping[str, Any]) -> GraphRoute:
    """Parse canonical slug routes and old ``binary_id`` graph links.

    A slug remains authoritative when both identifiers are present.  The
    numeric id is retained as a compatibility hint so the caller can detect a
    stale id while resolving the slug against the current binary table.
    """

    slug = _alias(query, "slug", "binary")
    binary_id = _decimal(query, "binary_id")
    logical_id = _decimal(query, "logical_id")
    raw_addr = _alias(query, "addr", "addr_hex")
    depth = _decimal(query, "depth") or 2
    if depth not in (1, 2):
        raise RouteValueError("depth must be 1 or 2")

    has_concrete = slug is not None or binary_id is not None or raw_addr is not None
    if logical_id is not None and has_concrete:
        raise RouteValueError("graph route cannot mix logical and concrete focus")
    if logical_id is not None:
        return GraphRoute(LogicalFunctionRef(logical_id), depth)
    if (slug is None and binary_id is None) or raw_addr is None:
        raise RouteValueError("graph route needs a binary slug (or binary_id) and address")

    address = parse_address(raw_addr)
    if address is None:
        raise RouteValueError("addr is not a valid non-negative address")
    try:
        binary = BinaryRef(slug=slug, binary_id=binary_id)
        return GraphRoute(ConcreteFunctionRef(binary, address), depth)
    except (TypeError, ValueError) as exc:
        raise RouteValueError(str(exc)) from exc
