"""Classify objdiff instruction mismatches for autonomous repair routing."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .objdiff_verification import extract_mismatch_histogram
from .state import atomic_write_json, now

CLAIM_BOUNDARY = (
    "mismatch class is advisory metadata; only objdiff-zero under verified/ moves the proof ladder"
)
LAST_SCHEMA = "agentdecompile.mismatch-class-last.v1"

CLASS_BOUNDARY_SUSPECT = "boundary-suspect"
CLASS_OPERAND = "operand"
CLASS_OPCODE = "opcode"
CLASS_INSERT_DELETE = "insert-delete"
CLASS_UNCLASSIFIED = "unclassified"

PLAYBOOK_BOUNDARY = "boundary-repair"
PLAYBOOK_OPERAND = "permuter-operand"
PLAYBOOK_OPCODE = "permuter-opcode"
PLAYBOOK_INSERT_DELETE = "permuter-insert-delete"
PLAYBOOK_SCALAR = "scalar-default"


def routed_playbook_for_class(mismatch_class: str | None) -> str:
    mapping = {
        CLASS_BOUNDARY_SUSPECT: PLAYBOOK_BOUNDARY,
        CLASS_OPERAND: PLAYBOOK_OPERAND,
        CLASS_OPCODE: PLAYBOOK_OPCODE,
        CLASS_INSERT_DELETE: PLAYBOOK_INSERT_DELETE,
        CLASS_UNCLASSIFIED: PLAYBOOK_SCALAR,
    }
    return mapping.get(str(mismatch_class or ""), PLAYBOOK_SCALAR)


def classify_mismatch(
    *,
    histogram: dict[str, int] | None,
    boundary_quality: dict[str, Any] | None = None,
    detail_level: str | None = None,
    fallback: str | None = None,
) -> dict[str, Any]:
    """Assign a primary mismatch class from histogram and boundary context.

    A coherent instruction-level histogram is direct evidence the target
    slice compiled to something comparable, which outranks the
    boundary-suspect heuristic (a static guess about the slice's extent
    that has no false-negative signal to weigh against it). boundary-suspect
    is only the fallback classification when there's no usable histogram to
    classify from -- e.g. a compile failure, or an objdiff report that never
    reached instruction-level detail.
    """

    classification = _classify_from_histogram(histogram, detail_level=detail_level, fallback=fallback)
    if classification["mismatchClass"] != CLASS_UNCLASSIFIED:
        return classification

    boundary = boundary_quality if isinstance(boundary_quality, dict) else {}
    if boundary.get("status") == "suspect":
        return _classification(
            CLASS_BOUNDARY_SUSPECT,
            primary_kind=None,
            histogram=histogram or {},
            detail_level=detail_level,
        )
    return classification


def _classify_from_histogram(
    histogram: dict[str, int] | None,
    *,
    detail_level: str | None,
    fallback: str | None,
) -> dict[str, Any]:
    if fallback or detail_level == "scalar-only" or not histogram:
        return _classification(CLASS_UNCLASSIFIED, primary_kind=None, histogram={}, detail_level=detail_level)

    total = sum(int(value) for value in histogram.values())
    if total <= 0:
        return _classification(CLASS_UNCLASSIFIED, primary_kind=None, histogram={}, detail_level=detail_level)

    non_zero_kinds = {kind for kind, count in histogram.items() if int(count) > 0}
    if non_zero_kinds.issubset({"INSERTION", "DELETION"}):
        primary_kind = "INSERTION" if int(histogram.get("INSERTION", 0)) >= int(histogram.get("DELETION", 0)) else "DELETION"
        return _classification(
            CLASS_INSERT_DELETE,
            primary_kind=primary_kind,
            histogram=dict(histogram),
            detail_level=detail_level,
        )

    dominant_kind, dominant_count = _dominant_bucket(histogram, total=total)
    if dominant_kind is None:
        return _classification(CLASS_UNCLASSIFIED, primary_kind=None, histogram=dict(histogram), detail_level=detail_level)

    primary_class = _class_for_kind(dominant_kind, histogram)
    return _classification(primary_class, primary_kind=dominant_kind, histogram=dict(histogram), detail_level=detail_level)


def classify_verify_report(
    report: dict[str, Any],
    *,
    boundary_quality: dict[str, Any] | None = None,
) -> dict[str, Any]:
    histogram = report.get("mismatchHistogram")
    if not isinstance(histogram, dict):
        histogram = extract_mismatch_histogram(report.get("output"))
    detail_level = str(report.get("detailLevel") or ("instruction" if histogram else "scalar-only"))
    return classify_mismatch(
        histogram=histogram,
        boundary_quality=boundary_quality,
        detail_level=detail_level,
        fallback=report.get("fallback"),
    )


def enrich_attempt_record(
    record: dict[str, Any],
    *,
    boundary_quality: dict[str, Any] | None = None,
    verify_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Attach mismatch metadata to a synthesis attempt record in place."""

    report = verify_report
    if report is None:
        report = _load_verify_report(record)
    if report is None:
        classification = classify_mismatch(histogram=None, boundary_quality=boundary_quality, detail_level="scalar-only")
    else:
        classification = classify_verify_report(report, boundary_quality=boundary_quality)

    record.update(classification)
    return record


def enrich_attempt_records(
    records: list[dict[str, Any]],
    row: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    boundary = _boundary_quality_from_row(row)
    for record in records:
        enrich_attempt_record(record, boundary_quality=boundary)
    return records


def write_mismatch_class_last(
    work_dir: Path,
    *,
    function_name: str,
    classification: dict[str, Any],
    routed_playbook: str | None = None,
) -> Path:
    work_dir = work_dir.resolve()
    payload = {
        "schema": LAST_SCHEMA,
        "writtenAt": now(),
        "functionName": function_name,
        "mismatchClass": classification.get("mismatchClass"),
        "primaryMismatchKind": classification.get("primaryMismatchKind"),
        "histogram": classification.get("mismatchHistogram") or {},
        "detailLevel": classification.get("detailLevel"),
        "routedPlaybook": routed_playbook or routed_playbook_for_class(classification.get("mismatchClass")),
        "claimBoundary": CLAIM_BOUNDARY,
    }
    path = work_dir / "state" / "mismatch-class-last.json"
    atomic_write_json(path, payload)
    return path


def near_miss_class_score_bonus(mismatch_class: str | None) -> int:
    if mismatch_class in {CLASS_OPERAND, CLASS_INSERT_DELETE}:
        return 20
    return 0


def _classification(
    mismatch_class: str,
    *,
    primary_kind: str | None,
    histogram: dict[str, int],
    detail_level: str | None,
) -> dict[str, Any]:
    return {
        "mismatchClass": mismatch_class,
        "primaryMismatchKind": primary_kind,
        "mismatchHistogram": histogram,
        "detailLevel": detail_level or ("instruction" if histogram else "scalar-only"),
    }


def _dominant_bucket(histogram: dict[str, int], *, total: int | None = None) -> tuple[str | None, int]:
    """Pick the plurality mismatch kind to route from.

    A strict >50% majority requirement here means any genuinely mixed diff --
    common for real near-misses with several small differences of different
    kinds -- falls through to unclassified regardless of how much real
    instruction-level evidence exists, and from there to boundary-repair or
    scalar-default, neither of which enables shape search. The routed
    playbooks for every real class (operand/opcode/insert-delete) all enable
    shape search; they differ mainly in variant budget and repair lane, so
    picking the plurality kind (deterministic tie-break: highest count, then
    alphabetical) is enough signal to route productively without requiring an
    outright majority.
    """
    if total is None:
        total = sum(int(value) for value in histogram.values())
    if total <= 0:
        return None, 0
    ranked = sorted(((kind, int(count)) for kind, count in histogram.items() if int(count) > 0), key=lambda item: (-item[1], item[0]))
    if not ranked:
        return None, 0
    return ranked[0]


def _class_for_kind(kind: str, histogram: dict[str, int]) -> str:
    if kind == "ARGUMENT_MISMATCH":
        return CLASS_OPERAND
    if kind in {"OPCODE_MISMATCH", "REPLACEMENT"}:
        return CLASS_OPCODE
    if kind in {"INSERTION", "DELETION"}:
        insert_delete_total = int(histogram.get("INSERTION", 0)) + int(histogram.get("DELETION", 0))
        if insert_delete_total * 2 > sum(int(value) for value in histogram.values()):
            return CLASS_INSERT_DELETE
        return CLASS_INSERT_DELETE
    return CLASS_UNCLASSIFIED


def _boundary_quality_from_row(row: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(row, dict):
        return {}
    target_slice = row.get("targetSlice")
    if not isinstance(target_slice, dict):
        return {}
    boundary = target_slice.get("boundaryQuality")
    return boundary if isinstance(boundary, dict) else {}


def _load_verify_report(record: dict[str, Any]) -> dict[str, Any] | None:
    path_value = record.get("verifyReport")
    if not path_value:
        return None
    path = Path(str(path_value))
    if not path.is_file():
        return None
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None
    return loaded if isinstance(loaded, dict) else None
