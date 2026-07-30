"""Unit tests for challenger-lane mechanism 3 (LLM rewrite) policy gating and
its insertion into semantic_equivalent_variants / run_msvc_source_shape_search.

The Anthropic client is mocked at the request_llm_rewrite boundary -- no real
network calls, no ANTHROPIC_API_KEY required.
"""

from __future__ import annotations

from typing import Any

import pytest

from agentdecompile_recovery.autonomy_budget import AutonomyBudget
from agentdecompile_recovery.autonomous_policy import choose_next_action
from agentdecompile_recovery.llm_rewrite_client import LlmRewriteResult
from agentdecompile_recovery.mismatch_classify import CLASS_OPERAND
from agentdecompile_recovery.source_parity_synthesize import (
    GeneratedCandidate,
    llm_rewrite_variant,
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


def _near_miss_attempt(*, llm_rewrite_status: str | None = None) -> dict[str, Any]:
    data: dict[str, Any] = {
        "differenceCount": 3,
        "status": "mismatched",
        "mismatchClass": CLASS_OPERAND,
        "mismatchHistogram": {"ARGUMENT_MISMATCH": 2},
    }
    if llm_rewrite_status is not None:
        data["llmRewriteStatus"] = llm_rewrite_status
    return {
        "source-candidate-generator": _Step(),
        "source-candidate-objdiff": _Step(data=data),
        "mismatchClass": CLASS_OPERAND,
    }


# -- policy gating -----------------------------------------------------------


def test_policy_does_not_request_llm_before_shape_search_exhausted() -> None:
    decision = choose_next_action(
        {},  # sourceShapeSearch not yet set on context
        [_near_miss_attempt()],
        budget=AutonomyBudget(max_llm_calls_per_function=3),
    )
    assert decision["action"] == "try-nearby-source-shape-or-permuter"


def test_policy_requests_llm_rewrite_after_shape_search_exhausted() -> None:
    decision = choose_next_action(
        {"sourceShapeSearch": True},
        [_near_miss_attempt()],
        budget=AutonomyBudget(max_llm_calls_per_function=2),
    )
    assert decision["action"] == "try-llm-rewrite"
    assert "2 call(s) remaining" in decision["reason"] or "call(s) remaining" in decision["reason"]


def test_policy_does_not_request_llm_when_budget_is_zero() -> None:
    decision = choose_next_action(
        {"sourceShapeSearch": True},
        [_near_miss_attempt()],
        budget=AutonomyBudget(max_llm_calls_per_function=0),
    )
    assert decision["action"] != "try-llm-rewrite"


def test_policy_never_requests_llm_without_real_mismatch_evidence() -> None:
    attempt = {
        "source-candidate-generator": _Step(),
        "source-candidate-objdiff": _Step(data={"differenceCount": 4, "status": "mismatched"}),
        "mismatchClass": "boundary-suspect",
    }
    decision = choose_next_action(
        {"sourceShapeSearch": True},
        [attempt],
        budget=AutonomyBudget(max_llm_calls_per_function=3),
    )
    assert decision["action"] != "try-llm-rewrite"


def test_policy_stops_campaign_on_llm_fatal_status() -> None:
    decision = choose_next_action(
        {"sourceShapeSearch": True},
        [_near_miss_attempt(llm_rewrite_status="llm-fatal")],
        budget=AutonomyBudget(max_llm_calls_per_function=3),
    )
    assert decision["action"] == "llm-unavailable"


def test_policy_continues_after_transient_llm_unavailable() -> None:
    """A transient failure exhausts that call but must not stop the whole campaign."""
    decision = choose_next_action(
        {"sourceShapeSearch": True},
        [_near_miss_attempt(llm_rewrite_status="llm-unavailable")],
        budget=AutonomyBudget(max_llm_calls_per_function=3),
    )
    assert decision["action"] != "llm-unavailable"


# -- prepare_retry context wiring --------------------------------------------


def test_prepare_retry_sets_llm_rewrite_requested_flag() -> None:
    plugin = SourceCandidateGeneratorPlugin()
    context = {
        "autonomousPolicy": {
            "action": "try-llm-rewrite",
            "mismatchClass": CLASS_OPERAND,
            "mismatchHistogram": {"ARGUMENT_MISMATCH": 2},
        }
    }
    updated = plugin.prepare_retry(context, [])
    assert updated["llmRewriteRequested"] is True
    assert updated["llmRewriteMismatchData"]["mismatchClass"] == CLASS_OPERAND
    assert updated["sourceCandidateIndex"] == 1


def test_prepare_retry_skips_llm_flags_for_other_actions() -> None:
    plugin = SourceCandidateGeneratorPlugin()
    context = {"autonomousPolicy": {"action": "try-next-generated-candidate"}}
    updated = plugin.prepare_retry(context, [])
    assert "llmRewriteRequested" not in updated


# -- llm_rewrite_variant / semantic_equivalent_variants insertion -----------


def test_llm_rewrite_variant_returns_variant_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_request(*_args: Any, **_kwargs: Any) -> LlmRewriteResult:
        return LlmRewriteResult(
            status="ok",
            source="int x(void) { return 1; }",
            stop_reason="end_turn",
            model="claude-sonnet-4-5-20250929",
            input_tokens=100,
            output_tokens=50,
        )

    monkeypatch.setattr("agentdecompile_recovery.source_parity_synthesize.request_llm_rewrite", fake_request)
    outcome = llm_rewrite_variant({"name": "sub_1000"}, _candidate(), {"mismatchClass": CLASS_OPERAND})
    assert outcome.variant == {
        "name": "llm-rewrite",
        "source": "int x(void) { return 1; }",
        "semanticEquivalent": True,
    }
    assert outcome.status_fields["status"] == "ok"


def test_llm_rewrite_variant_returns_none_on_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_request(*_args: Any, **_kwargs: Any) -> LlmRewriteResult:
        return LlmRewriteResult(status="llm-unavailable", error="rate limited")

    monkeypatch.setattr("agentdecompile_recovery.source_parity_synthesize.request_llm_rewrite", fake_request)
    outcome = llm_rewrite_variant({"name": "sub_1000"}, _candidate(), {})
    assert outcome.variant is None
    assert outcome.status_fields["status"] == "llm-unavailable"


def test_semantic_equivalent_variants_reaches_llm_path_for_packaged_source(monkeypatch: pytest.MonkeyPatch) -> None:
    """Packaged-source candidates with no matching template (mechanism 1) and no
    idiom-permutable shape (mechanism 2) must still reach the LLM fallback when
    requested -- this is exactly the gap mechanism 3 closes."""

    def fake_request(*_args: Any, **_kwargs: Any) -> LlmRewriteResult:
        return LlmRewriteResult(status="ok", source="int rewritten(void) { return 2; }")

    monkeypatch.setattr("agentdecompile_recovery.source_parity_synthesize.request_llm_rewrite", fake_request)
    variants = semantic_equivalent_variants(
        {"name": "sub_1000"},
        _candidate("int unrelated_shape(void) { return 2; }\n"),
        llm_rewrite_requested=True,
        llm_mismatch_data={"mismatchClass": CLASS_OPERAND},
    )
    assert variants == [{"name": "llm-rewrite", "source": "int rewritten(void) { return 2; }", "semanticEquivalent": True}]


def test_semantic_equivalent_variants_llm_status_out_captures_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_request(*_args: Any, **_kwargs: Any) -> LlmRewriteResult:
        return LlmRewriteResult(status="llm-fatal", error="invalid api key")

    monkeypatch.setattr("agentdecompile_recovery.source_parity_synthesize.request_llm_rewrite", fake_request)
    status_out: dict[str, Any] = {}
    variants = semantic_equivalent_variants(
        {"name": "sub_1000"},
        _candidate("int unrelated_shape(void) { return 2; }\n"),
        llm_rewrite_requested=True,
        llm_mismatch_data={},
        llm_status_out=status_out,
    )
    assert variants == []
    assert status_out["status"] == "llm-fatal"


def test_semantic_equivalent_variants_no_llm_call_when_not_requested(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[Any] = []

    def fake_request(*args: Any, **kwargs: Any) -> LlmRewriteResult:
        calls.append((args, kwargs))
        return LlmRewriteResult(status="ok", source="unused")

    monkeypatch.setattr("agentdecompile_recovery.source_parity_synthesize.request_llm_rewrite", fake_request)
    variants = semantic_equivalent_variants(
        {"name": "sub_1000"},
        _candidate("int unrelated_shape(void) { return 2; }\n"),
    )
    assert variants == []
    assert calls == []


def test_byte_field_guard_fallback_still_wins_over_llm(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mechanism 2's narrow, evidence-grounded rule must be tried before
    mechanism 3's general (and costly) LLM fallback."""

    def fake_request(*_args: Any, **_kwargs: Any) -> LlmRewriteResult:
        raise AssertionError("LLM should not be called when mechanism 2 matches")

    monkeypatch.setattr("agentdecompile_recovery.source_parity_synthesize.request_llm_rewrite", fake_request)
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
        llm_rewrite_requested=True,
        llm_mismatch_data={},
    )
    assert len(variants) == 3
    assert variants[0]["name"] == "byte-field-guard-mask-arithmetic-ternary"
