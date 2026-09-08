"""Focused contracts for the dashboard's dependency-free SVG primitives."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

import pytest

pytestmark = pytest.mark.unit

from agentdecompile_recovery.corpus.dashboard.panels import viz


def _svg_markup(markup: str) -> str:
    start = markup.index("<svg")
    end = markup.index("</svg>", start) + len("</svg>")
    return markup[start:end]


def _root(markup: str) -> ET.Element:
    return ET.fromstring(_svg_markup(markup))


def _assert_accessible_svg(markup: str) -> ET.Element:
    root = _root(markup)
    assert root.attrib["role"] == "img"
    assert root.attrib["focusable"] == "false"
    labelled = root.attrib["aria-labelledby"].split()
    assert len(labelled) == 2
    ids = {node.attrib.get("id") for node in root}
    assert set(labelled) <= ids
    assert root.find("{http://www.w3.org/2000/svg}title").text
    assert root.find("{http://www.w3.org/2000/svg}desc").text
    width, height = map(float, root.attrib["viewBox"].split()[2:])
    assert width > 0 and height > 0
    assert f"aspect-ratio:{viz._n(width)} / {viz._n(height)}" in root.attrib["style"]
    return root


def test_all_svg_chart_types_have_accessible_responsive_roots():
    charts = [
        viz.placeholder(),
        viz.donut([("done", 2, "proven")]),
        viz.bars([("alpha", 2, "partial")]),
        viz.stacked_bar([("done", 2, "proven")]),
        viz.histogram([1, 2, 3]),
        viz.heatmap([[0, 2], [3, 0]], ["a", "b"], ["a", "b"]),
        viz.rail([("read", .5, "partial", None)]),
        viz.sparkline([1, 2]),
    ]
    for chart in charts:
        _assert_accessible_svg(chart)


def test_empty_and_degenerate_inputs_return_valid_placeholders():
    for chart in (
        viz.donut([]),
        viz.bars([]),
        viz.stacked_bar([]),
        viz.histogram([]),
        viz.heatmap([], [], []),
        viz.rail([]),
        viz.sparkline([1]),
    ):
        root = _assert_accessible_svg(chart)
        assert "viz-empty" in root.attrib["class"]


def test_svg_ids_are_unique_when_multiple_charts_share_a_document():
    markup = viz.bars([("a", 1, "proven")]) + viz.bars([("b", 2, "failed")])
    ids = re.findall(r'\bid="([^"]+)"', markup)
    assert len(ids) == len(set(ids))


def test_heatmap_accessible_name_is_domain_neutral():
    markup = viz.heatmap([[1]], ["source"], ["target"])
    title = _root(markup).find("{http://www.w3.org/2000/svg}title").text
    assert title.startswith("Matrix density")
    assert "build" not in title.lower()
    assert "match" not in title.lower()


def test_svg_wrapper_clamps_invalid_geometry():
    root = _assert_accessible_svg(viz._svg(0, -4, "empty geometry", ""))
    assert root.attrib["viewBox"] == "0 0 1 1"

