"""De-Ghidra-ification readability rewrite pass (U11).

This module rewrites raw Ghidra decompiler output into more readable C
*without changing what the code does*. It is a surface/spelling pass only:

    * ``undefined``/``undefinedN`` and Ghidra scalar typedefs (``uint``,
      ``ushort``, ``uchar``, ``ulong``, ``byte``, ``sbyte``) are replaced with
      their ``<stdint.h>`` equivalents.
    * Register/stack-spill artifacts (``in_EAX``/``in_ECX``/``in_stack_*``,
      ``unaff_*``, ``extraout_*``), Ghidra's ``CONCAT``/``SUB`` pseudo-ops,
      Ghidra's bitfield sub-access syntax (``foo._1_3_``), and the ``float10``
      x87-extended type are all *context-dependent*: the same textual pattern
      means different things at different call sites (see the module-level
      ``AMBIGUOUS ARTIFACTS`` notes below and the risks captured in
      ``.mission/notes/`` for this unit). This pass never guesses a rename
      for them. It leaves the identifier/type spelling untouched and attaches
      a short explanatory comment at the first occurrence in the file.

CRITICAL SAFETY CONSTRAINT -- READ BEFORE CALLING THIS FROM A PIPELINE
------------------------------------------------------------------------
This pass is only meaningful to run on source that has *already* been
verified byte-identical (objdiff-zero) against the target binary. It must
never be capable of changing program semantics -- only surface spelling and
typing of identifiers/types, plus comment insertion.

To enforce that structurally:

    * The rewrite walks the source through :func:`_tokenize`, which
      classifies every span of the input as exactly one of: a block comment,
      a line comment, a string literal, a char literal, an identifier, or
      "other" (whitespace, punctuation, numeric literals, operators).
    * Substitution only ever touches whole ``identifier`` tokens, and only
      when that token is an *exact* match for a known Ghidra
      type/typedef name (see ``GHIDRA_TYPE_MAP``). Replacement text is a
      single token standing in for another single token (e.g.
      ``undefined4`` -> ``uint32_t``); no token is ever split, merged, or
      reordered, and no non-identifier text (operators, control flow
      keywords, literals, parens, braces) is ever rewritten.
    * Ambiguous-artifact handling never rewrites the identifier itself --
      it only *appends* a trailing ``// ...`` comment on the line of first
      occurrence. Appending a line comment cannot change the meaning of
      existing code on that line (anything after ``//`` was already dead to
      the compiler), and it never touches lines other than the one it
      annotates.
    * Content inside existing comments and string/char literals is never
      considered for substitution (see the tokenizer groups above), so this
      pass cannot accidentally "fix" a type name mentioned in a comment or
      string.

Explicitly out of scope for this unit (documented, not silently skipped):

    * Renaming generic Ghidra locals (``uVar5``, ``iVar3``, ``local_58``,
      ``auStack_98``, ...). Ghidra's Hungarian-notation letter prefixes
      (``u``/``i``/``f``/``p``/...) are *not* collision-free counters shared
      across prefixes -- ``uVar5`` and ``iVar5`` can coexist as distinct
      locals in the same function. Stripping the prefix (the natural
      "readability" move once the type is spelled out explicitly) would
      require full per-function symbol-table collision detection to stay
      byte-neutral, which this token-level pass does not attempt. Renaming
      these is deferred to a future unit with real scope-aware tooling.
    * Ghidra's synthetic control-flow/data labels (``LAB_...``,
      ``code_r0x...``, ``DAT_...``). A ``goto`` target rename that misses
      even one reference is a compile break, and this pass does not build a
      full identifier cross-reference table, so labels are left completely
      untouched (not even annotated).

Casing conventions (AGENTS.md: camelCase locals/params/globals, CapitalCase
types, snake_case struct fields, COBRA_CASE enum constants) apply only to
identifiers this pass actually renames. Per the scope notes above, this pass
renames zero identifiers -- it only retypes declarations (stdint types are
lowercase by C convention, not subject to the CapitalCase rule, which is
about *named* aggregate/typedef types this pass does not introduce) and
annotates ambiguous artifacts in place. There is therefore nothing for the
casing rules to apply to yet; this is noted explicitly rather than silently
ignored.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "GHIDRA_TYPE_MAP",
    "RewriteStats",
    "rewrite_source",
    "rewrite_file",
    "rewrite_verified_tree",
]


# ---------------------------------------------------------------------------
# Safe, unconditional type/typedef spelling replacements.
# ---------------------------------------------------------------------------
#
# All of these are pure width/signedness spellings with a single unambiguous
# stdint equivalent for this corpus's target (swkotor.exe, x86-32 PE). None
# of them carry call-site-dependent meaning the way in_*/unaff_*/extraout_*
# do, so a blanket token-for-token swap is safe.
GHIDRA_TYPE_MAP: dict[str, str] = {
    # Ghidra's opaque "N raw bytes, no signedness/format known" family.
    # Bare `undefined` (no width suffix) defaults to a single unknown byte,
    # matching `undefined1`'s width; `unsigned char` is the closest honest
    # C spelling of "one byte, no signedness claims beyond unsigned".
    "undefined": "unsigned char",
    "undefined1": "uint8_t",
    "undefined2": "uint16_t",
    "undefined4": "uint32_t",
    "undefined8": "uint64_t",
    # Ghidra scalar typedefs.
    "uint": "uint32_t",
    "ushort": "uint16_t",
    "uchar": "uint8_t",
    # This corpus targets a 32-bit x86 binary, where Ghidra's `ulong` is a
    # 4-byte type -- the same width as `undefined4`/`uint` here, not the
    # platform `unsigned long`.
    "ulong": "uint32_t",
    "byte": "uint8_t",
    "sbyte": "int8_t",
}

# Types that are ambiguous/unsafe to blanket-rewrite: no correct stdint
# equivalent exists, so they are annotated (see module docstring) rather
# than replaced.
_AMBIGUOUS_TYPES: dict[str, str] = {
    "float10": (
        "Ghidra 'float10' is x87 80-bit extended precision; no portable "
        "stdint/standard-C type has the same width, so it is left as-is "
        "rather than silently narrowed/widened."
    ),
}

# Register/stack-spill/SEH artifact families. Each of these is
# context-dependent per call site (real implicit argument vs. leftover
# register noise vs. SEH frame slot) -- see the risks captured during the
# research pass for this unit. Never renamed; only annotated once.
_ARTIFACT_RE = re.compile(r"^(in|unaff|extraout)_[A-Za-z0-9_]+$")

_ARTIFACT_EXPLANATIONS: dict[str, str] = {
    "in": (
        "Ghidra register/stack-argument artifact -- may be a genuine "
        "implicit parameter (e.g. __thiscall 'this') or leftover register "
        "state; meaning is call-site dependent, left unrenamed."
    ),
    "unaff": (
        "Ghidra 'unaffected register' artifact (value assumed live across "
        "a call Ghidra couldn't account for, often the SEH fs:[0] chain "
        "via unaff_FS_OFFSET); left unrenamed."
    ),
    "extraout": (
        "Ghidra 'extra output' artifact -- a prior call's return value "
        "still live in a register that decompiled C doesn't show being "
        "captured; attaching it to the correct call requires the .asm "
        "sidecar, so it is left unrenamed."
    ),
}

# CONCATxx / SUBxx pseudo-ops: sometimes genuine multi-register value
# reconstruction, sometimes pure decompiler/stack-frame bookkeeping noise
# (see module docstring / research notes). Never rewritten; annotated once.
_CONCAT_SUB_RE = re.compile(r"^(CONCAT\d{2}|SUB\d{2})$")
_CONCAT_SUB_EXPLANATION = (
    "Ghidra CONCAT/SUB pseudo-op: may be genuine multi-register value "
    "reconstruction or pure decompiler bookkeeping/SEH noise depending on "
    "call site; left unrewritten rather than guessed."
)

# Ghidra bitfield-style sub-access syntax, e.g. `local_c._0_1_` or
# `param_1._1_3_` (byte-range view onto a wider local/param). Detected as an
# identifier token of the form `_N_M_` immediately preceded by a literal
# '.'; annotated once per file, never rewritten.
_BITFIELD_SUFFIX_RE = re.compile(r"^_\d+_\d+_$")
_BITFIELD_EXPLANATION = (
    "Ghidra sub-field access syntax '.N_M_' (byte-range view of a wider "
    "value); left unrewritten -- see readability_rewrite.py."
)

# Matches the target-name identifier of a simple scalar/pointer typedef
# declaration, e.g. `typedef unsigned char undefined;` or `typedef void
# *HANDLE;` -- the Ghidra type-header preamble present in effectively every
# real recovered file consists entirely of this shape. Deliberately narrow:
# it does not attempt function-pointer or array typedefs (`typedef int
# code();`), since none of GHIDRA_TYPE_MAP's keys collide with a target name
# in that shape in this corpus, and a narrow miss here only means a rarer
# typedef form doesn't get the exclusion, not that a wrong one is excluded.
#
# Why this exists: without it, `typedef unsigned char undefined;` rewrites to
# `typedef unsigned char unsigned char;` -- the substitution can't tell "the
# name being defined" from "a use of the type" by token text alone, since
# both are spelled identically. This is a hard C compile failure, not a
# cosmetic issue, and it was caught only by running the pass against a real
# file carrying this preamble (the pass's own test fixtures were bare
# function bodies without it).
_TYPEDEF_TARGET_RE = re.compile(r"\btypedef\b[^;{}]*?\b([A-Za-z_]\w*)\s*;")


def _typedef_target_spans(source: str) -> set[tuple[int, int]]:
    """Character spans of typedef target-name identifiers to never substitute."""

    return {match.span(1) for match in _TYPEDEF_TARGET_RE.finditer(source)}


_COMMENT_TAG = "U11"


@dataclass
class RewriteStats:
    """Measured counts from a :func:`rewrite_source` call."""

    types_replaced: dict[str, int] = field(default_factory=dict)
    """Ghidra type token -> number of occurrences replaced."""

    artifacts_annotated: dict[str, str] = field(default_factory=dict)
    """Ambiguous identifier/pseudo-op token -> explanation comment attached."""

    comments_added: int = 0
    """Total number of explanatory comment lines appended."""


_TOKEN_RE = re.compile(
    r"(?P<block_comment>/\*.*?\*/)"
    r"|(?P<line_comment>//[^\n]*)"
    r"|(?P<string>\"(?:\\.|[^\"\\])*\")"
    r"|(?P<char>'(?:\\.|[^'\\])*')"
    r"|(?P<ident>[A-Za-z_][A-Za-z0-9_]*)",
    re.DOTALL,
)


def _line_number(source: str, offset: int) -> int:
    """0-indexed line number of ``offset`` within ``source``."""

    return source.count("\n", 0, offset)


def rewrite_source(source: str) -> tuple[str, RewriteStats]:
    """Apply the de-Ghidra-ification readability pass to ``source``.

    Returns ``(rewritten_source, stats)``. See the module docstring for the
    byte-neutrality guarantee this function relies on structurally.
    """

    stats = RewriteStats()
    typedef_target_spans = _typedef_target_spans(source)
    pieces: list[str] = []
    # line index (0-based) -> list of comments to append at end of that line
    pending_comments: dict[int, list[str]] = {}
    seen_artifact_tokens: set[str] = set()
    seen_concat_sub_tokens: set[str] = set()
    seen_ambiguous_types: set[str] = set()
    seen_bitfield = False

    last_end = 0
    for match in _TOKEN_RE.finditer(source):
        # Verbatim text between tokens (whitespace, punctuation, numeric
        # literals, operators) is never touched.
        pieces.append(source[last_end : match.start()])
        last_end = match.end()

        group = match.lastgroup
        text = match.group()

        if group != "ident":
            # Comments and string/char literal contents pass through
            # unchanged and are never scanned for identifiers.
            pieces.append(text)
            continue

        if text in GHIDRA_TYPE_MAP and match.span() not in typedef_target_spans:
            replacement = GHIDRA_TYPE_MAP[text]
            pieces.append(replacement)
            stats.types_replaced[text] = stats.types_replaced.get(text, 0) + 1
            continue

        if text in _AMBIGUOUS_TYPES:
            pieces.append(text)
            if text not in seen_ambiguous_types:
                seen_ambiguous_types.add(text)
                line_no = _line_number(source, match.start())
                comment = f"{_COMMENT_TAG}: {_AMBIGUOUS_TYPES[text]}"
                pending_comments.setdefault(line_no, []).append(comment)
                stats.artifacts_annotated[text] = comment
            continue

        artifact_match = _ARTIFACT_RE.match(text)
        if artifact_match:
            pieces.append(text)
            if text not in seen_artifact_tokens:
                seen_artifact_tokens.add(text)
                family = artifact_match.group(1)
                line_no = _line_number(source, match.start())
                comment = (
                    f"{_COMMENT_TAG}: {text} -- {_ARTIFACT_EXPLANATIONS[family]}"
                )
                pending_comments.setdefault(line_no, []).append(comment)
                stats.artifacts_annotated[text] = comment
            continue

        if _CONCAT_SUB_RE.match(text):
            # Confirm this is a call (`CONCAT44(` / `SUB41(`), not some
            # unrelated identifier that happens to match the shape.
            rest = source[match.end() :]
            if re.match(r"\s*\(", rest):
                pieces.append(text)
                if text not in seen_concat_sub_tokens:
                    seen_concat_sub_tokens.add(text)
                    line_no = _line_number(source, match.start())
                    comment = f"{_COMMENT_TAG}: {text}(...) -- {_CONCAT_SUB_EXPLANATION}"
                    pending_comments.setdefault(line_no, []).append(comment)
                    stats.artifacts_annotated[text] = comment
                continue

        if _BITFIELD_SUFFIX_RE.match(text) and match.start() > 0 and source[match.start() - 1] == ".":
            pieces.append(text)
            if not seen_bitfield:
                seen_bitfield = True
                line_no = _line_number(source, match.start())
                comment = f"{_COMMENT_TAG}: {_BITFIELD_EXPLANATION}"
                pending_comments.setdefault(line_no, []).append(comment)
                stats.artifacts_annotated["<bitfield-access>"] = comment
            continue

        # Anything else (real identifiers: params, locals, function names,
        # keywords) passes through completely unchanged.
        pieces.append(text)

    pieces.append(source[last_end:])
    rewritten = "".join(pieces)

    if pending_comments:
        lines = rewritten.split("\n")
        for line_no, comments in pending_comments.items():
            if 0 <= line_no < len(lines):
                for comment in comments:
                    lines[line_no] = f"{lines[line_no]}  // {comment}"
                    stats.comments_added += 1
        rewritten = "\n".join(lines)

    return rewritten, stats


def rewrite_file(path: str | Path, *, write: bool = False) -> tuple[str, RewriteStats]:
    """Convenience wrapper: read ``path``, rewrite it, optionally write back.

    Only ever call this on source that has already been verified
    byte-identical against the target binary (see module docstring).
    """

    p = Path(path)
    rewritten, stats = rewrite_source(p.read_text(encoding="utf-8"))
    if write:
        p.write_text(rewritten, encoding="utf-8")
    return rewritten, stats


def rewrite_verified_tree(verified_dir: Path, readable_dir: Path) -> dict[str, Any]:
    """Write `verified_dir`'s `.c` files into `readable_dir`, rewritten for readability.

    This is a distinct output tier, never an in-place edit of ``verified/``:
    ``verified/`` is the byte-exact proof tier (objdiff-zero), and
    ``readable/`` is that same content run through :func:`rewrite_source` for
    humans. Conflating the two would let a non-proof pass masquerade as
    proof-tier content, which this project's design explicitly forbids (see
    ``docs/plans/2026-07-25-readable-recovery-quality.md``, R12-R13).

    Byte-neutral by construction (see module docstring), so this is safe to
    always run once ``verified/`` exists -- gated on nothing except having
    something to rewrite. Cleanly no-ops (``status: "skipped"``) when
    `verified_dir` is missing or has no `.c` files, rather than creating an
    empty `readable_dir`.
    """

    if not verified_dir.is_dir():
        return {
            "schema": "agentdecompile.readable-rewrite.v1",
            "status": "skipped",
            "reason": "no-verified-dir",
            "fileCount": 0,
        }
    c_files = sorted(verified_dir.rglob("*.c"))
    if not c_files:
        return {
            "schema": "agentdecompile.readable-rewrite.v1",
            "status": "skipped",
            "reason": "verified-dir-empty",
            "fileCount": 0,
        }

    if readable_dir.exists():
        shutil.rmtree(readable_dir)
    readable_dir.mkdir(parents=True, exist_ok=True)

    types_replaced = 0
    artifacts_annotated = 0
    for path in c_files:
        rel = path.relative_to(verified_dir)
        dest = readable_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        rewritten, stats = rewrite_source(path.read_text(encoding="utf-8"))
        dest.write_text(rewritten, encoding="utf-8")
        types_replaced += sum(stats.types_replaced.values())
        artifacts_annotated += len(stats.artifacts_annotated)

    return {
        "schema": "agentdecompile.readable-rewrite.v1",
        "status": "complete",
        "readableDir": str(readable_dir),
        "fileCount": len(c_files),
        "typesReplaced": types_replaced,
        "artifactsAnnotated": artifacts_annotated,
        "claimBoundary": (
            "readable/ is a byte-neutral spelling/typing pass over verified/; "
            "it carries no additional proof beyond verified/'s own objdiff-zero guarantee"
        ),
    }
