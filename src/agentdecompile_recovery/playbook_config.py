"""Map mismatch playbooks to distinct source-plugin run configurations."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from .mismatch_classify import (
    PLAYBOOK_BOUNDARY,
    PLAYBOOK_INSERT_DELETE,
    PLAYBOOK_OPCODE,
    PLAYBOOK_OPERAND,
    PLAYBOOK_SCALAR,
)
from .source_plugin_runner import SourcePluginRunConfig

CLAIM_BOUNDARY = (
    "playbook config selects advisory repair strategy only; "
    "objdiff-zero under verified/ remains the proof gate"
)


def playbook_receipt(playbook: str | None) -> dict[str, Any]:
    """Serializable playbook tuning for repair run receipts."""

    playbook = str(playbook or PLAYBOOK_SCALAR)
    if playbook == PLAYBOOK_BOUNDARY:
        return {
            "playbook": playbook,
            "sourceShapeSearch": False,
            "skipBoundarySuspect": False,
            "maxVariantsPerFunction": 4,
            "repairLane": "boundary-repair",
            "claimBoundary": CLAIM_BOUNDARY,
        }
    if playbook == PLAYBOOK_OPERAND:
        return {
            "playbook": playbook,
            "sourceShapeSearch": True,
            "skipBoundarySuspect": True,
            "maxVariantsPerFunction": 12,
            "repairLane": "permuter-operand",
            "claimBoundary": CLAIM_BOUNDARY,
        }
    if playbook == PLAYBOOK_OPCODE:
        return {
            "playbook": playbook,
            "sourceShapeSearch": True,
            "skipBoundarySuspect": True,
            "maxVariantsPerFunction": 8,
            "repairLane": "shape-search-opcode",
            "claimBoundary": CLAIM_BOUNDARY,
        }
    if playbook == PLAYBOOK_INSERT_DELETE:
        return {
            "playbook": playbook,
            "sourceShapeSearch": True,
            "skipBoundarySuspect": True,
            "maxVariantsPerFunction": 10,
            "repairLane": "branch-shape",
            "claimBoundary": CLAIM_BOUNDARY,
        }
    return {
        "playbook": PLAYBOOK_SCALAR,
        "sourceShapeSearch": False,
        "skipBoundarySuspect": True,
        "maxVariantsPerFunction": 6,
        "repairLane": "scalar-default",
        "claimBoundary": CLAIM_BOUNDARY,
    }


def apply_playbook_to_run_config(
    config: SourcePluginRunConfig,
    playbook: str | None,
    *,
    force_shape_search: bool = False,
) -> SourcePluginRunConfig:
    """Return a copy of ``config`` tuned for the routed playbook."""

    spec = playbook_receipt(playbook)
    shape = bool(spec["sourceShapeSearch"] or force_shape_search)
    qualities = set(config.source_qualities or {"high-level-c"})
    if shape:
        qualities.add("high-level-c")
    if spec["repairLane"] == "branch-shape":
        qualities.add("inline-asm-c")
    return replace(
        config,
        source_shape_search=shape,
        skip_boundary_suspect=bool(spec["skipBoundarySuspect"]),
        max_variants_per_function=max(int(spec["maxVariantsPerFunction"]), config.max_variants_per_function),
        max_retries=max(int(spec["maxVariantsPerFunction"]), config.max_retries),
        source_qualities=qualities,
        routed_playbook=str(spec["playbook"]),
    )
