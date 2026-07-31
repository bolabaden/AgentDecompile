"""Curated parameter names and comments, read from a Ghidra program database.

Ghidra curates two disjoint kinds of per-function knowledge that never reach
the source_cleanup/source_dump pipeline today: curated parameter names
(stored as `Symbols` rows parented to the function) and Plate/EOL/Pre
comments (stored in the `Comments` table). Both are read here directly from
the `.gbf` database via `GhidraProgram` -- this module never opens a
PyGhidra/live-Ghidra session and never re-parses the database itself; it is
a thin join on top of `GhidraProgram.locals_by_function()` and
`GhidraProgram.comments()`.

Scope: PARAMETER names only, not local variables. Measured on the curated
Odyssey project, curated names cover 2,232 of 16,981 parameter symbols but
only 4 of 147,543 local-variable symbols -- a local-variable rename pass
fed from this data source would touch a handful of functions project-wide,
so it is deliberately left out. Callers that want the honest picture should
report coverage as "curated names applied to N of M parameters", not as a
general local-variable naming feature.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .ghidra_db.program import GhidraProgram, LocalVariable, SymbolType

# Preferred order when combining multiple stored comment kinds into one header.
_HEADER_COMMENT_KINDS = ("Plate", "EOL", "Pre")
# EOL/Pre comments are per-line and often long or code-shaped; only short ones
# read sanely as a one-line function header note.
_SHORT_COMMENT_MAX_LEN = 120


@dataclass(frozen=True)
class CuratedFunctionHints:
    """Curated knowledge for one function, keyed by its entry VA by the caller."""

    entry: int
    header_comment: str | None
    params: list[dict[str, str]]

    def to_locals_fact(self) -> list[dict[str, str]]:
        """The exact `fact['locals']` shape `clean_source_text` substitutes."""

        return list(self.params)


def normalize_entry_key(value: Any) -> str | None:
    """Bare lowercase 8-hex-digit entry key, matching `source_dump.normalize_entry_hex`.

    Duplicated rather than imported: `source_dump` imports from
    `source_cleanup`, and `source_cleanup` needs this same normalization, so
    importing `source_dump` here would create a cycle. Both must keep
    producing identical keys for the same address for hint lookups to match.
    """

    if value is None:
        return None
    if isinstance(value, int):
        return f"{value:08x}"
    text = str(value).strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    if text and all(c in "0123456789abcdef" for c in text):
        return text
    try:
        return f"{int(text):08x}"
    except (TypeError, ValueError):
        return text or None


def param_slot_name(ordinal: int | None) -> str | None:
    """Ghidra's decompiler-emitted identifier for a parameter ordinal.

    Ghidra numbers parameters 1-based in emitted C (`param_1` is the first
    parameter, stored ordinal 0). Returns None for ordinals it cannot place,
    so callers skip rather than guess a slot name.
    """

    if ordinal is None or ordinal < 0:
        return None
    return f"param_{ordinal + 1}"


def curated_params_for_function(variables: list[LocalVariable]) -> list[dict[str, str]]:
    """Curated parameter name/slot pairs, in declaration order.

    Only `SymbolType.PARAMETER` entries are used -- see module docstring for
    why local variables are excluded. Entries whose ordinal cannot be mapped
    to a `param_N` slot, or whose name is empty, are skipped.
    """

    pairs: list[dict[str, str]] = []
    for variable in variables:
        if variable.symbol_type != SymbolType.PARAMETER or not variable.name:
            continue
        slot = param_slot_name(variable.ordinal)
        if slot is None:
            continue
        pairs.append({"name": variable.name, "slot": slot})
    return pairs


def sanitize_header_comment_text(text: str) -> str:
    """Flatten a curated comment so it is safe to embed in a `/* ... */` header.

    A curated comment containing a literal `*/` would otherwise close the
    surrounding C block comment early and corrupt the emitted file; a
    multi-line comment would break the `" * "`-per-line header convention.
    Both are neutralised rather than rejected, so real content still shows.
    """

    flattened = " ".join(text.split())
    return flattened.replace("*/", "* /")


def header_comment_for_function(comments: dict[str, str]) -> str | None:
    """Pick one stored comment to surface in a generated header, preferring Plate.

    Plate comments are Ghidra's per-function annotation and are used
    whichever length. EOL/Pre are per-line and often long or code-shaped;
    they are used only when short enough to read as a one-line header note.
    """

    plate = comments.get("Plate")
    if plate and plate.strip():
        return sanitize_header_comment_text(plate)
    for kind in ("EOL", "Pre"):
        text = comments.get(kind)
        if text and text.strip() and len(text.strip()) <= _SHORT_COMMENT_MAX_LEN:
            return sanitize_header_comment_text(text)
    return None


def build_curated_hints(program: GhidraProgram) -> dict[int, CuratedFunctionHints]:
    """Curated per-function hints keyed by function entry VA.

    Joins `program.locals_by_function()` (parameter names) and
    `program.comments()` (Plate/EOL/Pre) onto function entry addresses via
    `program.functions()`. Functions with neither curated parameters nor a
    usable comment are omitted -- callers should treat a missing key as
    "nothing curated for this function", not as an error.
    """

    locals_by_symbol = program.locals_by_function()
    comments_by_entry: dict[int, dict[str, str]] = {}
    for comment_set in program.comments():
        comments_by_entry[comment_set.entry] = comment_set.comments

    hints: dict[int, CuratedFunctionHints] = {}
    for function in program.functions():
        if function.entry is None:
            continue
        params = curated_params_for_function(locals_by_symbol.get(function.symbol_id, []))
        header_comment = header_comment_for_function(comments_by_entry.get(function.entry, {}))
        if not params and not header_comment:
            continue
        hints[function.entry] = CuratedFunctionHints(
            entry=function.entry,
            header_comment=header_comment,
            params=params,
        )
    return hints


def curated_hints_to_json(hints: dict[int, CuratedFunctionHints]) -> dict[str, dict[str, Any]]:
    """Entry-hex-keyed view consumed by `source_dump.dump_source_tree` and
    `source_cleanup.cleanup_recovered_source_package` (`curated_hints=`).
    """

    return {
        f"{entry:08x}": {
            "plateComment": hint.header_comment,
            "locals": hint.to_locals_fact(),
        }
        for entry, hint in hints.items()
    }


def merge_curated_locals_into_fact(fact: dict[str, Any], curated: dict[str, Any] | None) -> dict[str, Any]:
    """`fact` with curated parameter names folded into `fact['locals']`.

    Existing entries win on slot collision -- curated names only add
    coverage `clean_source_text` did not already have, they do not override
    an already-populated locals producer.
    """

    if not curated:
        return fact
    curated_locals = curated.get("locals") if isinstance(curated.get("locals"), list) else []
    if not curated_locals:
        return fact
    existing = fact.get("locals") if isinstance(fact.get("locals"), list) else []
    existing_slots = {item.get("slot") for item in existing if isinstance(item, dict)}
    merged = list(existing) + [item for item in curated_locals if item.get("slot") not in existing_slots]
    return {**fact, "locals": merged}
