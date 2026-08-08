"""Tests for in-process rewrite fulfillment wiring in the plugin pipeline.

Covers the two changes that let a campaign close mechanism 3 by itself: the
queue entry now carries the aligned diff, and fulfillment can run in-process
instead of waiting for a separately-launched operator session.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery import rewrite_queue
from agentdecompile_recovery.plugin_pipeline import PluginPipeline

pytestmark = pytest.mark.unit


ALIGNED = [
    {"index": 0, "target": "inc dword ptr [0x830540]", "candidate": "mov eax, [0x830540]", "differs": True, "diffKind": "DIFF_REPLACE"},
]


def test_queue_entry_carries_aligned_diff(tmp_path: Path) -> None:
    request_id = rewrite_queue.write_rewrite_request(
        tmp_path,
        function_name="FUN_004a23b0",
        entry="0x4a23b0",
        candidate_source="void f(void){}",
        mismatch_class="opcode-replacement",
        mismatch_histogram={"REPLACEMENT": 2},
        aligned_diff=ALIGNED,
        compiler_profile="msvc /O2",
    )

    entry = rewrite_queue.find_entry(tmp_path, request_id)

    assert entry is not None
    assert entry["alignedDiff"] == ALIGNED
    assert entry["compilerProfile"] == "msvc /O2"


def test_aligned_diff_is_optional_for_existing_callers(tmp_path: Path) -> None:
    request_id = rewrite_queue.write_rewrite_request(
        tmp_path,
        function_name="f",
        entry="0x1",
        candidate_source="void f(void){}",
        mismatch_class=None,
        mismatch_histogram=None,
    )

    entry = rewrite_queue.find_entry(tmp_path, request_id)

    assert entry is not None
    assert entry["alignedDiff"] == []


def test_histogram_is_stored_as_json_not_python_repr(tmp_path: Path) -> None:
    """A live entry held the string "{'REPLACEMENT': 2}" -- Python repr, which no
    JSON consumer can parse."""

    request_id = rewrite_queue.write_rewrite_request(
        tmp_path,
        function_name="f",
        entry="0x1",
        candidate_source="void f(void){}",
        mismatch_class="opcode-replacement",
        mismatch_histogram={"REPLACEMENT": 2},
    )

    entry = rewrite_queue.find_entry(tmp_path, request_id)

    assert entry is not None
    assert entry["mismatchHistogram"] == {"REPLACEMENT": 2}


def test_string_histogram_is_coerced(tmp_path: Path) -> None:
    request_id = rewrite_queue.write_rewrite_request(
        tmp_path,
        function_name="f",
        entry="0x1",
        candidate_source="void f(void){}",
        mismatch_class=None,
        mismatch_histogram="{'REPLACEMENT': 2}",  # type: ignore[arg-type]
    )

    entry = rewrite_queue.find_entry(tmp_path, request_id)

    assert entry is not None
    assert entry["mismatchHistogram"] == {"REPLACEMENT": 2}


class _Verifier:
    def __init__(self, output: str) -> None:
        self.status = "success"
        self.error = ""
        self.data = {"output": output, "differences": 1}


def _objdiff_output() -> str:
    import json

    def side(rows):
        return {"symbols": [{"name": "f", "kind": "SYMBOL_FUNCTION", "match_percent": 50.0, "instructions": rows}]}

    return json.dumps(
        {
            "left": side([{"instruction": {"formatted": "inc dword ptr [0x830540]"}, "diff_kind": "DIFF_REPLACE"}]),
            "right": side([{"instruction": {"formatted": "mov eax, [0x830540]"}, "diff_kind": "DIFF_REPLACE"}]),
        }
    )


def test_pipeline_writes_aligned_diff_from_verifier_output(tmp_path: Path) -> None:
    pipeline = PluginPipeline()
    context = {
        "workDir": str(tmp_path),
        "sourceParityRow": {"name": "FUN_004a23b0", "entry": "0x4a23b0"},
        "selectedSourceCandidate": type("C", (), {"source": "void f(void){}"})(),
        "rewriteFulfillment": "queue",
    }
    attempts = [{"source-candidate-objdiff": _Verifier(_objdiff_output())}]

    pipeline._write_rewrite_request(context, {"mismatchClass": "opcode-replacement"}, attempts)

    queue = rewrite_queue.read_rewrite_queue(tmp_path)
    entry = next(iter(queue["entries"].values()))
    assert entry["alignedDiff"][0]["target"] == "inc dword ptr [0x830540]"


def test_inprocess_fulfillment_resolves_the_entry(tmp_path: Path) -> None:
    """With fulfillment enabled, the entry is completed in the same pass rather
    than left pending for an operator session that may never run."""

    calls: list[dict] = []

    def provider(pack, **kwargs):
        calls.append(pack)
        return {"status": "completed", "source": "void f(void){ ++gCounter; }", "reason": None}

    pipeline = PluginPipeline(rewrite_provider=provider)
    context = {
        "workDir": str(tmp_path),
        "sourceParityRow": {"name": "FUN_004a23b0", "entry": "0x4a23b0"},
        "selectedSourceCandidate": type("C", (), {"source": "void f(void){}"})(),
        "rewriteFulfillment": "cli",
    }
    attempts = [{"source-candidate-objdiff": _Verifier(_objdiff_output())}]

    pipeline._write_rewrite_request(context, {"mismatchClass": "opcode-replacement"}, attempts)

    queue = rewrite_queue.read_rewrite_queue(tmp_path)
    entry = next(iter(queue["entries"].values()))
    assert entry["status"] == "completed"
    assert entry["source"] == "void f(void){ ++gCounter; }"
    assert calls and calls[0]["alignedDiff"][0]["target"] == "inc dword ptr [0x830540]"


def test_inprocess_fulfillment_failure_marks_entry_failed(tmp_path: Path) -> None:
    def provider(pack, **kwargs):
        return {"status": "failed", "source": None, "reason": "no fenced code block"}

    pipeline = PluginPipeline(rewrite_provider=provider)
    context = {
        "workDir": str(tmp_path),
        "sourceParityRow": {"name": "f", "entry": "0x1"},
        "selectedSourceCandidate": type("C", (), {"source": "void f(void){}"})(),
        "rewriteFulfillment": "cli",
    }

    pipeline._write_rewrite_request(context, {}, [{"source-candidate-objdiff": _Verifier(_objdiff_output())}])

    queue = rewrite_queue.read_rewrite_queue(tmp_path)
    entry = next(iter(queue["entries"].values()))
    assert entry["status"] == "failed"
    assert "fenced" in entry["reason"]


def test_provider_exception_leaves_entry_pending(tmp_path: Path) -> None:
    """A provider crash must not lose the request -- an operator session can
    still pick it up."""

    def provider(pack, **kwargs):
        raise RuntimeError("boom")

    pipeline = PluginPipeline(rewrite_provider=provider)
    context = {
        "workDir": str(tmp_path),
        "sourceParityRow": {"name": "f", "entry": "0x1"},
        "selectedSourceCandidate": type("C", (), {"source": "void f(void){}"})(),
        "rewriteFulfillment": "cli",
    }

    pipeline._write_rewrite_request(context, {}, [{"source-candidate-objdiff": _Verifier(_objdiff_output())}])

    queue = rewrite_queue.read_rewrite_queue(tmp_path)
    entry = next(iter(queue["entries"].values()))
    assert entry["status"] == "pending"
