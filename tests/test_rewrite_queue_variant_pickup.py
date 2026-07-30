"""Unit tests for challenger-lane mechanism 3's policy gating, pipeline wiring,
and result pickup into shape-search variants -- the async, subagent-fulfilled
replacement for the removed direct-Anthropic-API mechanism.
"""

from __future__ import annotations

from typing import Any

import pytest

from agentdecompile_recovery import rewrite_queue
from agentdecompile_recovery.autonomy_budget import AutonomyBudget
from agentdecompile_recovery.autonomous_policy import choose_next_action
from agentdecompile_recovery.mismatch_classify import CLASS_OPERAND
from agentdecompile_recovery.plugin_pipeline import AUTONOMY_STOP_ACTIONS
from agentdecompile_recovery.source_parity_synthesize import (
    GeneratedCandidate,
    pending_rewrite_variant,
    semantic_equivalent_variants,
)
from agentdecompile_recovery.source_plugins import SourceCandidateGeneratorPlugin

pytestmark = pytest.mark.unit


class _Step:
    def __init__(self, *, status: str = "success", error: str = "", data: dict | None = None) -> None:
        self.status = status
        self.error = error
        self.data = data or {}


def _candidate(source: str = "int x(void) { return 0; }\n") -> GeneratedCandidate:
    return GeneratedCandidate(
        rule="packaged-source",
        variant="packaged-source",
        c_name="sub_1000",
        symbol="sub_1000",
        source=source,
        callconv="fastcall",
        return_type="int",
        source_suffix=".c",
        semantic_source=True,
    )


def _near_miss_attempt() -> dict[str, Any]:
    return {
        "source-candidate-generator": _Step(),
        "source-candidate-objdiff": _Step(
            data={
                "differenceCount": 3,
                "status": "mismatched",
                "mismatchClass": CLASS_OPERAND,
                "mismatchHistogram": {"ARGUMENT_MISMATCH": 2},
            }
        ),
        "mismatchClass": CLASS_OPERAND,
    }


# -- policy gating -----------------------------------------------------------


def test_try_rewrite_request_is_a_stop_action() -> None:
    """The load-bearing fix from feasibility review: without this, the pipeline
    would retry synchronously in-process instead of handing off to the queue."""
    assert "try-rewrite-request" in AUTONOMY_STOP_ACTIONS


def test_policy_does_not_request_rewrite_before_shape_search_exhausted() -> None:
    decision = choose_next_action(
        {},  # sourceShapeSearch not yet set on context
        [_near_miss_attempt()],
        budget=AutonomyBudget(max_rewrite_requests_per_function=3),
    )
    assert decision["action"] == "try-nearby-source-shape-or-permuter"


def test_policy_requests_rewrite_after_shape_search_exhausted(tmp_path) -> None:
    decision = choose_next_action(
        {"sourceShapeSearch": True, "workDir": str(tmp_path), "sourceParityRow": {"name": "sub_1000"}},
        [_near_miss_attempt()],
        budget=AutonomyBudget(max_rewrite_requests_per_function=2),
    )
    assert decision["action"] == "try-rewrite-request"
    assert "request(s) remaining" in decision["reason"]


def test_policy_does_not_request_rewrite_when_budget_is_zero(tmp_path) -> None:
    decision = choose_next_action(
        {"sourceShapeSearch": True, "workDir": str(tmp_path), "sourceParityRow": {"name": "sub_1000"}},
        [_near_miss_attempt()],
        budget=AutonomyBudget(max_rewrite_requests_per_function=0),
    )
    assert decision["action"] != "try-rewrite-request"


def test_policy_never_requests_rewrite_without_real_mismatch_evidence(tmp_path) -> None:
    attempt = {
        "source-candidate-generator": _Step(),
        "source-candidate-objdiff": _Step(data={"differenceCount": 4, "status": "mismatched"}),
        "mismatchClass": "boundary-suspect",
    }
    decision = choose_next_action(
        {"sourceShapeSearch": True, "workDir": str(tmp_path), "sourceParityRow": {"name": "sub_1000"}},
        [attempt],
        budget=AutonomyBudget(max_rewrite_requests_per_function=3),
    )
    assert decision["action"] != "try-rewrite-request"


def test_policy_respects_existing_request_count_from_queue(tmp_path) -> None:
    """Budget is bounded by requests already written to the queue for this
    function, not by in-process attempt counting (which resets every
    --autonomous invocation)."""
    rewrite_queue.write_rewrite_request(
        tmp_path,
        function_name="sub_1000",
        entry="0x1000",
        candidate_source="int already_requested(void) { return 9; }",
        mismatch_class=CLASS_OPERAND,
        mismatch_histogram=None,
    )
    decision = choose_next_action(
        {"sourceShapeSearch": True, "workDir": str(tmp_path), "sourceParityRow": {"name": "sub_1000"}},
        [_near_miss_attempt()],
        budget=AutonomyBudget(max_rewrite_requests_per_function=1),
    )
    assert decision["action"] != "try-rewrite-request"


# -- prepare_retry context wiring --------------------------------------------


def test_prepare_retry_does_not_bump_index_for_try_rewrite_request() -> None:
    """try-rewrite-request is a stop action handled centrally in
    plugin_pipeline.py -- SourceCandidateGeneratorPlugin.prepare_retry never
    even runs for it (the central prepare_retry returns before iterating
    plugins), so this is a defense-in-depth check that no stray wiring for the
    old synchronous mechanism remains."""
    plugin = SourceCandidateGeneratorPlugin()
    context = {"autonomousPolicy": {"action": "try-rewrite-request"}}
    updated = plugin.prepare_retry(context, [])
    assert "sourceCandidateIndex" not in updated
    assert "llmRewriteRequested" not in updated


# -- pending_rewrite_variant / semantic_equivalent_variants insertion -------


def test_pending_rewrite_variant_returns_none_when_no_result() -> None:
    assert pending_rewrite_variant({"name": "sub_1000"}, _candidate(), None) is None


def test_pending_rewrite_variant_returns_none_for_pending_or_claimed() -> None:
    row = {"name": "sub_1000"}
    for status in ("pending", "claimed"):
        result = {"status": status}
        assert pending_rewrite_variant(row, _candidate(), result) is None


def test_pending_rewrite_variant_returns_none_for_failed() -> None:
    result = {"status": "failed", "reason": "no usable rewrite"}
    assert pending_rewrite_variant({"name": "sub_1000"}, _candidate(), result) is None


def test_pending_rewrite_variant_returns_variant_for_completed() -> None:
    result = {"status": "completed", "source": "int x(void) { return 1; }"}
    variant = pending_rewrite_variant({"name": "sub_1000"}, _candidate(), result)
    assert variant == {"name": "rewrite-request", "source": "int x(void) { return 1; }", "semanticEquivalent": True}


def test_pending_rewrite_variant_rejects_pragma_content() -> None:
    result = {"status": "completed", "source": '#pragma comment(lib, "evil.lib")\nint x(void) { return 1; }'}
    assert pending_rewrite_variant({"name": "sub_1000"}, _candidate(), result) is None


def test_pending_rewrite_variant_rejects_include_content() -> None:
    result = {"status": "completed", "source": '#include <stdio.h>\nint x(void) { return 1; }'}
    assert pending_rewrite_variant({"name": "sub_1000"}, _candidate(), result) is None


def test_pending_rewrite_variant_rejects_empty_source() -> None:
    result = {"status": "completed", "source": "   "}
    assert pending_rewrite_variant({"name": "sub_1000"}, _candidate(), result) is None


# -- readable-source constraint --------------------------------------------
#
# Inline assembly reproduces the target bytes exactly, so it passes the objdiff
# gate while defeating the readable-C deliverable. An unconstrained rewrite lane
# converges on it: the only completed mechanism-3 result before this gate existed
# was `__asm { inc dword ptr [DAT_00830540] }`.


@pytest.mark.parametrize(
    "body",
    [
        "int x(void) { __asm { nop } return 1; }",
        "int x(void) { _asm nop; return 1; }",
        "__declspec(naked) int x(void) { return 1; }",
        "int x(void) { __emit(0x90); return 1; }",
    ],
)
def test_pending_rewrite_variant_rejects_inline_assembly(body: str) -> None:
    result = {"status": "completed", "source": body}
    assert pending_rewrite_variant({"name": "sub_1000"}, _candidate(), result) is None


def test_pending_rewrite_variant_rejects_inline_assembly_split_by_line_continuation() -> None:
    """Line continuations are removed before the check, so `__\\<nl>asm` rejoins
    into the keyword and is caught -- unlike a block comment, which the C
    translation phases replace with a space (`__ asm`, two tokens, not the
    keyword) and which therefore needs no special handling here."""

    source = "int x(void) { __\\\nasm { nop } return 1; }"
    assert pending_rewrite_variant({"name": "sub_1000"}, _candidate(), {"status": "completed", "source": source}) is None


def test_pending_rewrite_variant_allows_identifier_containing_asm() -> None:
    """`asm` inside an ordinary identifier is not inline assembly."""

    source = "int x(void) { int plasmaCount = 1; return plasmaCount; }"
    variant = pending_rewrite_variant({"name": "sub_1000"}, _candidate(), {"status": "completed", "source": source})
    assert variant is not None


# -- content-check obfuscation bypasses (security review) -------------------


def test_pending_rewrite_variant_rejects_directive_split_by_line_continuation() -> None:
    source = "#\\\npragma comment(lib, \"evil.lib\")\nint x(void) { return 1; }"
    assert pending_rewrite_variant({"name": "sub_1000"}, _candidate(), {"status": "completed", "source": source}) is None


def test_pending_rewrite_variant_rejects_directive_hidden_by_block_comment() -> None:
    source = "#/**/pragma comment(lib, \"evil.lib\")\nint x(void) { return 1; }"
    assert pending_rewrite_variant({"name": "sub_1000"}, _candidate(), {"status": "completed", "source": source}) is None


def test_pending_rewrite_variant_rejects_underscore_pragma() -> None:
    source = 'int x(void) { _Pragma("comment(lib, \\"evil.lib\\")") return 1; }'
    assert pending_rewrite_variant({"name": "sub_1000"}, _candidate(), {"status": "completed", "source": source}) is None


def test_pending_rewrite_variant_rejects_define_directive() -> None:
    source = "#define EVIL 1\nint x(void) { return EVIL; }"
    assert pending_rewrite_variant({"name": "sub_1000"}, _candidate(), {"status": "completed", "source": source}) is None


def test_pending_rewrite_variant_allows_line_comment_not_containing_directive() -> None:
    source = "// a plain comment, not a directive\nint x(void) { return 1; }"
    variant = pending_rewrite_variant({"name": "sub_1000"}, _candidate(), {"status": "completed", "source": source})
    assert variant is not None


def test_semantic_equivalent_variants_reaches_pending_rewrite_for_packaged_source() -> None:
    """Packaged-source candidates with no matching template (mechanism 1) and no
    idiom-permutable shape (mechanism 2) must still reach the rewrite-queue
    fallback when a completed result is present -- this is exactly the gap
    mechanism 3 closes."""
    result = {"status": "completed", "source": "int rewritten(void) { return 2; }"}
    variants = semantic_equivalent_variants(
        {"name": "sub_1000"},
        _candidate("int unrelated_shape(void) { return 2; }\n"),
        pending_rewrite_result=result,
    )
    assert variants == [{"name": "rewrite-request", "source": "int rewritten(void) { return 2; }", "semanticEquivalent": True}]


def test_semantic_equivalent_variants_no_result_when_not_requested() -> None:
    variants = semantic_equivalent_variants(
        {"name": "sub_1000"},
        _candidate("int unrelated_shape(void) { return 2; }\n"),
    )
    assert variants == []


def test_byte_field_guard_fallback_still_wins_over_pending_rewrite() -> None:
    """Mechanism 2's narrow, evidence-grounded rule must be tried before
    mechanism 3's general rewrite-queue fallback."""
    result = {"status": "completed", "source": "should not be used"}
    byte_field_guard_source = (
        "void *__fastcall sub_78650(void *self) {\n"
        "    if (*(unsigned char *)((char *)self + 0x55) == 0x01) {\n"
        "        return self;\n"
        "    }\n"
        "    return 0;\n"
        "}\n"
    )
    variants = semantic_equivalent_variants(
        {"name": "sub_78650"},
        _candidate(byte_field_guard_source),
        pending_rewrite_result=result,
    )
    assert len(variants) == 3
    assert variants[0]["name"] == "byte-field-guard-mask-arithmetic-ternary"


def test_stdcall_mechanical_fallback_not_shadowed_by_pending_but_unresolved_rewrite() -> None:
    """Correctness review: a pending_rewrite_result that hasn't resolved to a
    usable variant (still pending/claimed/failed) must fall through to the
    stdcall mechanical fallback rather than short-circuiting to []."""
    candidate = GeneratedCandidate(
        rule="stdcall-store-two-stack-args-to-globals",
        variant="stdcall-store-two-stack-args-to-globals",
        c_name="sub_4000",
        symbol="sub_4000",
        source="void __stdcall sub_4000(int a, int b) { g_first = a; g_second = b; }\n",
        callconv="stdcall",
        return_type="void",
        source_suffix=".c",
        semantic_source=True,
        evidence={"firstAddress": "0x00500000", "secondAddress": "0x00500004"},
    )
    variants = semantic_equivalent_variants(
        {"name": "sub_4000"},
        candidate,
        pending_rewrite_result={"status": "pending"},
    )
    assert variants, "stdcall mechanical fallback must still fire when the rewrite hasn't resolved"
    assert variants[0]["name"] == "direct-volatile-stores"
