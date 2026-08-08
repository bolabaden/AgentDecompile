"""Fail-closed objdiff report parsing for recovery proof gates.

Empty or unparseable objdiff output is never treated as a match. Objdump
byte-compare fallbacks may still be recorded for diagnostics, but they must
not satisfy ``is_proven_zero`` / ``verified/`` promotion.
"""

from __future__ import annotations

import json
from typing import Any, Iterable


SCHEMA = "agentdecompile.verify-objdiff.v1"

# objdiff tags each instruction with "diff_kind" using these DIFF_-prefixed
# values (not the bare category names, and not the "kind" field, which
# earlier code mistakenly matched against).
DIFF_KIND_TO_CATEGORY = {
    "DIFF_INSERT": "INSERTION",
    "DIFF_DELETE": "DELETION",
    "DIFF_REPLACE": "REPLACEMENT",
    "DIFF_OP_MISMATCH": "OPCODE_MISMATCH",
    "DIFF_ARG_MISMATCH": "ARGUMENT_MISMATCH",
}


def iter_json_objects(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from iter_json_objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_json_objects(child)


def parse_objdiff_report(returncode: int, output: str) -> dict[str, Any]:
    """Parse objdiff JSON stdout. Fail closed on empty or unusable output."""

    text = output if isinstance(output, str) else ""
    if not text.strip():
        return {
            "schema": SCHEMA,
            "status": "error",
            "differences": -1,
            "message": "objdiff produced empty output",
            "objdiffExit": returncode,
            "output": text,
        }

    if returncode != 0:
        return {
            "schema": SCHEMA,
            "status": "error",
            "differences": -1,
            "message": "objdiff exited with error",
            "objdiffExit": returncode,
            "output": text,
        }

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return {
            "schema": SCHEMA,
            "status": "error",
            "differences": -1,
            "message": "objdiff output is not valid JSON",
            "objdiffExit": returncode,
            "output": text,
        }

    match_percents: list[float] = []
    for item in iter_json_objects(parsed):
        if "match_percent" in item and (
            item.get("kind") in {"SECTION_CODE", "SYMBOL_FUNCTION"} or "instructions" in item
        ):
            try:
                match_percents.append(float(item["match_percent"]))
            except (TypeError, ValueError):
                # Malformed percentages provide no proof; keep parsing other sections.
                continue

    histogram = extract_mismatch_histogram(parsed)
    detail_level = "instruction" if histogram else "scalar-only"

    if match_percents and all(value == 100 for value in match_percents):
        differences = 0
        status = "matched"
        message = "Object files match"
    elif match_percents:
        differences = 1
        status = "mismatched"
        message = "Object files do not match"
    else:
        differences = -1
        status = "error"
        message = "objdiff JSON lacked match_percent sections"

    report: dict[str, Any] = {
        "schema": SCHEMA,
        "status": status,
        "differences": differences,
        "message": message,
        "objdiffExit": returncode,
        "output": text,
        "detailLevel": detail_level,
    }
    if histogram:
        report["mismatchHistogram"] = histogram
        report["instructionMismatchCount"] = sum(int(value) for value in histogram.values())
    aligned = extract_aligned_diff(parsed)
    if aligned:
        report["alignedDiff"] = aligned
    return report


def _function_instructions(side: Any) -> list[dict[str, Any]]:
    """Instruction rows for the first function symbol on one side of a report."""

    if not isinstance(side, dict):
        return []
    for symbol in side.get("symbols") or []:
        if not isinstance(symbol, dict):
            continue
        instructions = symbol.get("instructions")
        if isinstance(instructions, list) and instructions:
            return [row for row in instructions if isinstance(row, dict)]
    return []


def _formatted(row: dict[str, Any] | None) -> str | None:
    if not isinstance(row, dict):
        return None
    instruction = row.get("instruction")
    if not isinstance(instruction, dict):
        return None
    text = instruction.get("formatted")
    return text.strip() if isinstance(text, str) else None


def _select_rows(rows: list[dict[str, Any]], limit: int | None) -> list[dict[str, Any]]:
    """Trim to `limit` rows without ever dropping a differing instruction.

    Differing rows are the entire signal; neighbouring rows are context. Budget
    goes to differences first, then one line of context either side, then
    leading context -- always re-sorted into original order so the listing
    still reads as an instruction sequence.
    """

    if limit is None or limit <= 0 or len(rows) <= limit:
        return rows
    differing = [index for index, row in enumerate(rows) if row["differs"]]
    context = [neighbour for index in differing for neighbour in (index - 1, index + 1)]
    keep: set[int] = set()
    for group in (differing, context, range(len(rows))):
        for index in group:
            if len(keep) >= limit:
                break
            if 0 <= index < len(rows):
                keep.add(index)
    return [rows[index] for index in sorted(keep)]


def extract_aligned_diff(parsed: Any, *, limit: int | None = 200) -> list[dict[str, Any]]:
    """Instruction-aligned target-vs-candidate rows from an objdiff report.

    objdiff runs as ``-1 <target> -2 <candidate>`` (see
    ``scripts/lib/verify-objdiff.sh``), so ``left`` is the target and ``right``
    is the candidate. Both sides emit one row per aligned slot -- an insertion
    on one side is a gap on the other -- so pairing by index reproduces
    objdiff's own alignment instead of re-deriving it.

    This is the evidence a rewrite prompt needs: which instruction differs and
    what the target holds there. ``extract_mismatch_histogram`` counts these
    same rows by kind and discards the rest.
    """

    if isinstance(parsed, str):
        try:
            parsed = json.loads(parsed)
        except json.JSONDecodeError:
            return []
    if not isinstance(parsed, dict):
        return []
    target = _function_instructions(parsed.get("left"))
    candidate = _function_instructions(parsed.get("right"))
    if not target and not candidate:
        return []

    rows: list[dict[str, Any]] = []
    for index in range(max(len(target), len(candidate))):
        target_row = target[index] if index < len(target) else None
        candidate_row = candidate[index] if index < len(candidate) else None
        diff_kind: str | None = None
        for row in (target_row, candidate_row):
            kind = row.get("diff_kind") if isinstance(row, dict) else None
            if kind and kind != "DIFF_NONE":
                diff_kind = str(kind)
                break
        target_text = _formatted(target_row)
        candidate_text = _formatted(candidate_row)
        rows.append(
            {
                "index": index,
                "target": target_text,
                "candidate": candidate_text,
                "diffKind": diff_kind,
                "differs": bool(diff_kind) or target_text != candidate_text,
            }
        )
    return _select_rows(rows, limit)


def render_aligned_diff(rows: list[dict[str, Any]]) -> str:
    """Render aligned rows as a two-column listing; ``!`` marks a difference."""

    lines: list[str] = []
    for row in rows:
        marker = "!" if row.get("differs") else " "
        target = row.get("target") or "<none>"
        candidate = row.get("candidate") or "<none>"
        lines.append(f"{marker} {target:<38} | {candidate}")
    return "\n".join(lines)


def extract_mismatch_histogram(parsed: Any) -> dict[str, int]:
    """Count objdiff instruction mismatch kinds from parsed JSON or raw output."""

    if isinstance(parsed, str):
        text = parsed.strip()
        if not text:
            return {}
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return {}

    histogram: dict[str, int] = {}
    for item in iter_json_objects(parsed):
        diff_kind = item.get("diff_kind")
        category = DIFF_KIND_TO_CATEGORY.get(str(diff_kind))
        if category is None:
            continue
        histogram[category] = histogram.get(category, 0) + 1
    return histogram
