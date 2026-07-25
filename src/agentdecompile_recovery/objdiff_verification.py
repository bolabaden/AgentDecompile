"""Fail-closed objdiff report parsing for recovery proof gates.

Empty or unparseable objdiff output is never treated as a match. Objdump
byte-compare fallbacks may still be recorded for diagnostics, but they must
not satisfy ``is_proven_zero`` / ``verified/`` promotion.
"""

from __future__ import annotations

import json
from typing import Any, Iterable


SCHEMA = "agentdecompile.verify-objdiff.v1"

INSTRUCTION_MISMATCH_KINDS = frozenset(
    {
        "INSERTION",
        "DELETION",
        "REPLACEMENT",
        "OPCODE_MISMATCH",
        "ARGUMENT_MISMATCH",
    }
)


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
    return report


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
        kind = item.get("kind")
        if kind not in INSTRUCTION_MISMATCH_KINDS:
            continue
        histogram[str(kind)] = histogram.get(str(kind), 0) + 1
    return histogram
