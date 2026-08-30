"""Authoritative corpus pipeline contract.

This file is the code form of the operator contract. Dashboard labels and old
JSON snapshots are not sources of truth. Receipts written by a run of this
pipeline, plus the corpus file and any `.mission/queue.md` the operator keeps,
are.
"""

from __future__ import annotations

SCHEMA = "agentdecompile.corpus-pipeline.v1"

# Two different "cross-match" jobs. Mixing them copies trash.
#
#   identify          — which function is which (names, features, STABS).
#                       Safe before any C exists.
#   apply-cross-build — copy compiling real C onto bound functions.
#                       Only after compile. Never copy a body that failed
#                       helpers unless an LLM cleanup of *that* Ghidra C
#                       later compiles.
#
# Operator path: STABS folders → Ghidra into those files → preparse →
# compile → (if ok) apply-cross-build → (if still failing) llm-cleanup
# of that Ghidra C → compile again → apply-cross-build → byte-accuracy.
PIPELINE_STAGES = (
    "extract",
    "identify",
    "merge-knowledge",
    "generate-projects",
    "recover-source",
    "preparse",
    "compile",
    "apply-cross-build",
    "llm-cleanup",
    "verify-byte-accuracy",
)

# Operator priority. Compile-to-complete-executable is first even though
# verify-byte-accuracy is last in the stage list.
PRIORITIES = (
    "compile-complete-executable",
    "cross-match",
    "byte-accuracy",
    "call-graphs-docs-ui",
)

CLAIM_BOUNDARY = (
    "A stage is complete only when that run wrote a receipt whose files exist "
    "on disk. Dashboard text, Atlas tiles, and leftover work-dir files from "
    "an earlier run are not completion. Real C and byte-accuracy are separate "
    "properties. Machine-code wrappers are not recovered source."
)

DEFAULT_DASHBOARD_PORT = 8791
DEFAULT_ATLAS_PORT = 5173
DEFAULT_REPORT_PORT = 3000


def stage_index(name: str) -> int:
    try:
        return PIPELINE_STAGES.index(name)
    except ValueError as exc:
        raise ValueError(f"unknown corpus stage {name!r}; valid: {PIPELINE_STAGES}") from exc


def stages_through(stop_after: str | None) -> tuple[str, ...]:
    if not stop_after:
        return PIPELINE_STAGES
    return PIPELINE_STAGES[: stage_index(stop_after) + 1]
