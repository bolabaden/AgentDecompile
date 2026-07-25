"""Unit tests for mismatch playbook → run-config mapping."""

from __future__ import annotations

import pytest

from agentdecompile_recovery.mismatch_classify import (
    PLAYBOOK_BOUNDARY,
    PLAYBOOK_OPERAND,
    PLAYBOOK_SCALAR,
)
from agentdecompile_recovery.playbook_config import apply_playbook_to_run_config, playbook_receipt
from agentdecompile_recovery.source_plugin_runner import SourcePluginRunConfig

pytestmark = pytest.mark.unit


def test_playbook_receipt_operand_differs_from_scalar() -> None:
    operand = playbook_receipt(PLAYBOOK_OPERAND)
    scalar = playbook_receipt(PLAYBOOK_SCALAR)
    assert operand["sourceShapeSearch"] is True
    assert scalar["sourceShapeSearch"] is False
    assert operand["maxVariantsPerFunction"] > scalar["maxVariantsPerFunction"]


def test_apply_playbook_to_run_config_tunes_retries() -> None:
    base = SourcePluginRunConfig(
        queue=None,
        source_tasks=[],
        out_dir=None,
        max_variants_per_function=1,
        max_retries=1,
    )
    tuned = apply_playbook_to_run_config(base, PLAYBOOK_BOUNDARY)
    assert tuned.skip_boundary_suspect is False
    assert tuned.max_variants_per_function >= 4
    assert tuned.routed_playbook == PLAYBOOK_BOUNDARY
