"""Unit tests for LFG strict verification (no Ghidra required)."""

from __future__ import annotations

import json

import pytest

from scripts.lfg_validation import verify_lfg_track_a_tool_seq_json, verify_lfg_track_b_tool_seq_json


def _step(name: str, text: str) -> dict:
    return {
        "name": name,
        "success": True,
        "result": {"content": [{"type": "text", "text": text}], "isError": False},
    }


def _envelope(steps: list[dict]) -> str:
    return json.dumps({"success": True, "steps": steps})


def _sym_block(run_id: str, shared: bool = True) -> str:
    p = f"sh_{run_id}" if shared else f"loc_{run_id}"
    return (
        f"## Symbol Listing\n\nShowing **3** of **3** results (offset 0).\n\n"
        f"| Name | Address | Type | Namespace |\n| --- | --- | --- | --- |\n"
        f"| {p}_cycle1_fn | 140001010 | Function | Global |\n"
    )


def test_verify_track_a_markdown_sync_ok() -> None:
    rid = "testrun"
    steps = [
        _step("checkin-program", "{}"),
        _step("checkin-program", "{}"),
        _step("checkin-program", "{}"),
        _step("search-symbols", _sym_block(rid, True)),
        _step(
            "sync-project",
            "## Syncproject (pull)\n**direction:** pull\n**errors:** []\n**dryRun:** True\n",
        ),
        _step(
            "sync-project",
            "## Syncproject (pull)\n**direction:** pull\n**errors:** []\n**dryRun:** False\n",
        ),
        _step("search-symbols", _sym_block(rid, True)),
        _step(
            "sync-project",
            "## Syncproject (push)\n**direction:** push\n**errors:** []\n**dryRun:** True\n",
        ),
        _step(
            "sync-project",
            "## Syncproject (push)\n**direction:** push\n**errors:** []\n**dryRun:** False\n",
        ),
        _step("search-symbols", _sym_block(rid, True)),
    ]
    verify_lfg_track_a_tool_seq_json(_envelope(steps), rid)


def test_verify_track_a_sync_errors_fail() -> None:
    rid = "x"
    sh = f"sh_{rid}"
    steps = [
        _step("checkin-program", "{}"),
        _step("checkin-program", "{}"),
        _step("checkin-program", "{}"),
        _step("search-symbols", _sym_block(rid, True)),
        _step(
            "sync-project",
            "## Syncproject (pull)\n**direction:** pull\n**errors:** []\n**dryRun:** False\n",
        ),
        _step(
            "sync-project",
            "## Syncproject (push)\n**direction:** push\n**errors:** [{'e':1}]\n**dryRun:** False\n",
        ),
    ]
    with pytest.raises(AssertionError, match="sync-project reported errors"):
        verify_lfg_track_a_tool_seq_json(_envelope(steps), rid)


def test_verify_track_b_local_ok() -> None:
    rid = "y"
    loc = f"loc_{rid}"
    st = "## X\n**action:** checkout_status\n**is_versioned:** False\n"
    steps = [
        _step("checkout-status", st),
        _step("checkout-status", st),
        _step("checkout-status", st),
        _step("search-symbols", _sym_block(rid, False)),
    ]
    verify_lfg_track_b_tool_seq_json(_envelope(steps), rid)


def test_verify_track_b_rejects_versioned() -> None:
    rid = "z"
    loc = f"loc_{rid}"
    bad = "## X\n**action:** checkout_status\n**is_versioned:** True\n"
    steps = [
        _step("checkout-status", bad),
        _step("checkout-status", bad),
        _step("checkout-status", bad),
        _step("search-symbols", _sym_block(rid, False)),
    ]
    with pytest.raises(AssertionError, match="is_versioned=True"):
        verify_lfg_track_b_tool_seq_json(_envelope(steps), rid)
