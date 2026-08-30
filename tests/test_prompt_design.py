from __future__ import annotations

import pytest

from agentdecompile_recovery.prompt_design import PROMPT_RATIONALE, validate_prompt_rationale

pytestmark = pytest.mark.unit


def test_every_production_prompt_surface_has_complete_rationale() -> None:
    assert set(PROMPT_RATIONALE) == {
        "craft_prompt",
        "rewrite_context",
        "integrator_build_fix",
        "matcher_prompt",
        "one_shot_source",
        "llm_cleanup",
        "mcp_workflows",
    }

    validate_prompt_rationale()


def test_rationale_records_prior_reason_and_intended_result() -> None:
    for changes in PROMPT_RATIONALE.values():
        for change in changes:
            assert change.prior
            assert change.reason
            assert change.intended_result
